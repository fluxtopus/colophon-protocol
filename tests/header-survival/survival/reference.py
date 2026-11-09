"""The reference sketch, reference/colophon_v0.py, loaded as a module.

The sketch is not a package and is not changed by this harness. Everything here signs and verifies
through it, so a capture is judged by exactly the code the specification's vectors run against."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]
SKETCH = ROOT / "reference" / "colophon_v0.py"


def load() -> ModuleType:
    if "colophon_v0" in sys.modules:
        return sys.modules["colophon_v0"]
    spec = importlib.util.spec_from_file_location("colophon_v0", SKETCH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SKETCH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["colophon_v0"] = module
    spec.loader.exec_module(module)
    return module


ref = load()
