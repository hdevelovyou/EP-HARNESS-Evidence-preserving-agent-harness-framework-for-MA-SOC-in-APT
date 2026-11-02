"""Minimal test runner for environments without pytest.

Usage: python tests/run_tests.py   (pytest also works if installed)
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
import test_core  # noqa: E402

fixtures = {
    "evidence_store": test_core.evidence_store(),
    "registry": test_core.registry(),
}

failed = 0
tests = [
    (f"{module.__name__}::{n}", f)
    for module in (test_capsule_schema, test_core, test_inline_gate)
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
