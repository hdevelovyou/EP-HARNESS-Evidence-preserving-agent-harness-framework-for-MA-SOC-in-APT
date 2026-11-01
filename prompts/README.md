# Prompting Layer

This folder centralizes prompt construction for the five main SOC agents without
changing the current hierarchical pipeline in `main.py`.

## Structure

```text
prompts/
  agent_prompts.py
  techniques/
    role_based_zero_shot/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
    chain_of_thought/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
    example_based_fewshot/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
  debate_techniques/
    role_based_zero_shot/
      coordinator.md
      hunter.md
      verifier.md
      analyst.md
      reporter.md
      feedback.md
      judge.md
      soft_test.md
    chain_of_thought/
      ...
    example_based_fewshot/
      ...
```

Every prompt file contains:

```text
## System Prompt
...

## Human Prompt
...
```

`agent_prompts.py` selects the active technique, loads the matching agent prompt
file, extracts the system/human sections, and passes them into the existing
agent code.

## Supported Techniques

- `role_based_zero_shot`
- `chain_of_thought`
- `example_based_fewshot`

## Selection

Use a global technique:

```powershell
$env:PROMPT_TECHNIQUE="chain_of_thought"
python main.py
```

Run the example-based few-shot variant:

```powershell
$env:PROMPT_TECHNIQUE="example_based_fewshot"
python main.py
```

Or override one agent:

```powershell
$env:HUNTER_PROMPT_TECHNIQUE="example_based_fewshot"
python main.py
```

Agent-specific variables:

- `COORDINATOR_PROMPT_TECHNIQUE`
- `HUNTER_PROMPT_TECHNIQUE`
- `VERIFIER_PROMPT_TECHNIQUE`
- `ANALYST_PROMPT_TECHNIQUE`
- `REPORTER_PROMPT_TECHNIQUE`

Agent-specific variables override `PROMPT_TECHNIQUE`. Unknown values fall back
to `role_based_zero_shot`.

Useful aliases accepted by `agent_prompts.py`:

- Chain-of-thought: `chain_of_thought`, `chain-of-thought`, `cot`
- Example-based few-shot: `example_based_fewshot`, `example-based-fewshot`, `fewshot`, `few_shot`

Current prompt variants share the same runtime architecture:

- Coordinator returns strict JSON and targets 8-10 tasks for normal multi-phase intrusions, max 12.
- Hunter preserves high-recall task evidence; T7 separates malicious/suspicious IOC candidates from benign/contextual observables.
- Analyst treats entity context as baseline observability/audit context, uses the TTP Relations Graph as controlled candidate guidance, and emits a TTP Hypothesis Promotion Table.
- Reporter treats the curated suspicious/malicious IOC set as the source of truth for the final IOC table.

The current `main.py` collaboration flow remains hierarchical. Debate-based
collaboration is implemented in `debate_main.py` and uses the separate
`prompts/debate_techniques/` prompt family.

## Debate-Based Selection

Run the debate-based workflow with role-based zero-shot debate prompts:

```powershell
$env:PROMPT_ARCHITECTURE="debate_based"
$env:PROMPT_TECHNIQUE="role_based_zero_shot"
python debate_main.py
```

Run with example-based few-shot debate prompts:

```powershell
$env:PROMPT_ARCHITECTURE="debate_based"
$env:PROMPT_TECHNIQUE="example_based_fewshot"
python debate_main.py
```

Run with chain-of-thought debate prompts:

```powershell
$env:PROMPT_ARCHITECTURE="debate_based"
$env:PROMPT_TECHNIQUE="chain_of_thought"
python debate_main.py
```

Run the lightweight debate feedback smoke test:

```powershell
$env:PROMPT_ARCHITECTURE="debate_based"
$env:DEBATE_SOFT_TEST="1"
python debate_main.py
```

Useful debate runtime variables:

- `DEBATE_TIMEOUT_SECONDS`: default `300`; after this, unresolved disagreement is escalated to Judge.
- `DEBATE_FEEDBACK_MODEL`: default `gpt-4.1-mini`.
- `DEBATE_JUDGE_MODEL`: default `gpt-4.1-mini`.
- `DEBATE_MODEL_TIMEOUT_SECONDS`: default `300`.

The debate workflow reorders agent communication and feedback only. It reuses
the same EvidenceExtractor, IOC Curator, TTP Relations Graph, MITRE mapper, and
evaluation logic as the hierarchical workflow.
