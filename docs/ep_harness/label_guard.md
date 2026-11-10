# Label guard

Status: **implemented** (`ep_harness/label_guard.py`, wired into `main.py`, `ep_harness.cli preflight`);
tests: `tests/test_label_guard.py`. Always on: it is an invariant, not a toggle.

## Problem

Windows-APT telemetry is produced with Atomic Red Team. Its command lines and file paths carry the ATT&CK
technique under test, e.g. `...\atomics\T1566.001\bin\PhishingAttachment.xlsm` or `write-host 'T1543.003 Test'`.
These IDs are the ground-truth labels. Measured before masking (sanitized telemetry, `preflight`):

| Scenario | Events | Distinct technique IDs | Of them in the ground truth | Fields |
|---|---|---|---|---|
| S07 | 342 | 12 (64 occurrences) | 7 | commandLine, parentCommandLine, targetFilename, imagePath |
| S16 | 341 | 7 (67 occurrences) | 4 | commandLine, parentCommandLine |
| S23 | 57 | 5 (14 occurrences) | 5 of 5 | commandLine, parentCommandLine |

The evaluator extracts techniques from the final report with a regex over the whole text, so a report that
merely copied such a path would be credited with the technique.

## What the runtime does

1. `mask_labels` replaces every technique ID in the sanitized telemetry with a stable pseudonym before the
   Coordinator, the evidence extractor or any agent sees it: `T1566.001 → XTID01`. The same ID always gets the
   same pseudonym (case-insensitive), a parent technique and its sub-technique get different ones, so paths
   stay distinct and consistent across events. Compact timestamps (`20241109T111958Z`) and hex strings are not
   touched.
2. `assert_no_labels` checks the masked telemetry and the evidence store; any technique ID left raises
   `LabelLeakError` and the run does not start.
3. The pseudonym → label mapping stays in the runtime bundle and is written to `runs/<id>/label_mask.json`
   only by the post-seal evaluation.

`MASK_SIMULATION_MARKERS=1` also masks simulation-framework markers (`atomic-red-team`, `atomics`,
`PathToAtomicsFolder`, `redcanary`, `Invoke-AtomicTest`) as `XSIMnn`. Off by default: they are not labels,
but they do reveal that the telemetry is an emulation. Whether to mask them is an open decision.

## What evaluation does

The ground-truth artifacts contain the original paths (S16 lists `T1036.003` paths ten times), so IOC scoring
needs the real paths back, but technique scoring must not get them:

- `unmask_artifacts` restores a pseudonym only inside a path-like token (a backslash, slash or file name around
  it). A pseudonym standing alone (`XTID05`, `(XTID05)`, `XTID05.`) is never restored.
- `main._scoring_entities` takes **techniques from the masked text** and every other entity type from the
  restored text, for the telemetry, the report and the curated IOCs.

A report therefore scores a technique only if it names the technique itself.

## Preflight (no model)

```bash
python -m ep_harness.cli preflight --scenario S23 --masoc-repo .
```

Prints events, technique IDs before masking, how many were masked, simulation markers left, and the leak check;
exit code 1 on a leak. Result on 2026-11-10: S07, S16 and S23 all `ok`, no label left in the sanitized telemetry
or the evidence store.

## Known limits

- Pattern-based: it masks `Txxxx[.xxx]` IDs. Technique *names* in free text (e.g. a script called
  `Invoke-MalDoc.ps1`) and APT group names are not masked; no group name was found in S07/S16/S23.
- The mapping is per run; pseudonym numbers are not comparable across scenarios.
- Tools that read files outside the telemetry (e.g. a RAG over the ATT&CK knowledge base) are unaffected by design.
