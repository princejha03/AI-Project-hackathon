"""Minimal pytest-compatible runner (stdlib only) for environments without pytest.
Discovers test_* functions in tests/ and supplies a tmp_path per test."""
import importlib.util
import inspect
import sys
import tempfile
import traceback
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
failed = 0
for f in sorted((root / "tests").glob("test_*.py")):
    spec = importlib.util.spec_from_file_location(f.stem, f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, fn in inspect.getmembers(mod, inspect.isfunction):
        if not name.startswith("test_"):
            continue
        kwargs = {}
        if "tmp_path" in inspect.signature(fn).parameters:
            kwargs["tmp_path"] = Path(tempfile.mkdtemp())
        try:
            fn(**kwargs)
            print(f"PASS  {f.stem}::{name}")
        except Exception:
            failed += 1
            print(f"FAIL  {f.stem}::{name}")
            traceback.print_exc()
sys.exit(1 if failed else 0)
