"""Load the WAF Flask app unambiguously during root-level pytest runs."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

WAF_ROOT = Path(__file__).resolve().parents[1]
WAF_APP = WAF_ROOT / "app.py"


def _module_is_from_waf(module: object) -> bool:
    file_name = getattr(module, "__file__", None)
    if not file_name:
        return False
    try:
        return WAF_ROOT in Path(file_name).resolve().parents or Path(file_name).resolve() == WAF_APP
    except OSError:
        return False


def load_waf_app():
    sys.path = [path for path in sys.path if Path(path or ".").resolve() != WAF_ROOT.resolve()]
    sys.path.insert(0, str(WAF_ROOT))
    for name in ("app", "config", "proxy", "database", "engine", "management", "waf_logging"):
        cached = sys.modules.get(name)
        if cached is not None and not _module_is_from_waf(cached):
            del sys.modules[name]
    cached_app = sys.modules.get("app")
    if cached_app is not None and _module_is_from_waf(cached_app):
        return cached_app
    spec = importlib.util.spec_from_file_location("app", WAF_APP)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load WAF app from {WAF_APP}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["app"] = module
    spec.loader.exec_module(module)
    return module


waf_app = load_waf_app()
create_app = waf_app.create_app
