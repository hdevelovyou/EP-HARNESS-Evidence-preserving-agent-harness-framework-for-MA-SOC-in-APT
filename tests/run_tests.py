"""Minimal test runner for environments without pytest.

Usage: python tests/run_tests.py [module ...]   (pytest also works if installed)
  e.g. python tests/run_tests.py test_capsule_schema test_core
"""

import contextlib
import inspect
import sys
import tempfile
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if "pytest" not in sys.modules:
    shim = types.ModuleType("pytest")

    def fixture(*args, **kwargs):
        if args and callable(args[0]):
            return args[0]
        return lambda fn: fn

    @contextlib.contextmanager
    def raises(exc):
        try:
            yield
        except exc:
            return
        raise AssertionError(f"expected {exc.__name__}")

    shim.fixture, shim.raises = fixture, raises
    sys.modules["pytest"] = shim

import test_capsule_schema  # noqa: E402
import test_inline_gate  # noqa: E402
import test_cited_claims  # noqa: E402
import test_semantic  # noqa: E402
import test_harness_assist  # noqa: E402
import test_policy  # noqa: E402
import test_label_guard  # noqa: E402
import test_claim_dataset  # noqa: E402
import test_baseline  # noqa: E402
import test_rate_limit  # noqa: E402
import test_core  # noqa: E402

fixtures = {
    "evidence_store": test_core.evidence_store(),
    "registry": test_core.registry(),
}

MODULES = (test_capsule_schema, test_core, test_inline_gate, test_cited_claims, test_semantic,
           test_harness_assist, test_policy, test_label_guard,
           test_claim_dataset, test_baseline, test_rate_limit)
# Optional arguments pick modules, e.g. `python tests/run_tests.py test_capsule_schema`.
selected = set(sys.argv[1:])
unknown = selected - {m.__name__ for m in MODULES}
if unknown:
    sys.exit(f"unknown test module(s): {sorted(unknown)}; choose from {[m.__name__ for m in MODULES]}")

failed = 0
tests = [
    (f"{module.__name__}::{n}", f)
    for module in MODULES
    if not selected or module.__name__ in selected
    for n, f in vars(module).items()
    if n.startswith("test_") and callable(f)
]
for name, fn in tests:
    kwargs = {}
    with tempfile.TemporaryDirectory() as tmp:
        for param in inspect.signature(fn).parameters:
            kwargs[param] = Path(tmp) if param == "tmp_path" else fixtures[param]
        try:
            fn(**kwargs)
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
print(f"\n{len(tests) - failed}/{len(tests)} passed")
sys.exit(1 if failed else 0)
