import json
from pathlib import Path
import pytest
from engine.inspector import RequestContext
from engine.normalizer import Normalizer
from engine.rule_engine import RuleEngine

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def settings():
    return json.loads((ROOT / "config/attack_detection.json").read_text())

@pytest.fixture
def detector_engine(settings):
    return RuleEngine(ROOT / "rules", Normalizer(), 2, settings)

def make_context(value="", field="q", path="/search", ip="127.0.0.1", form=None, files=None):
    return RequestContext(ip, "POST" if form is not None or files else "GET", "http://lab" + path,
                          path, {field: [value]} if value else {}, {}, {}, "Mozilla/5.0", "",
                          b"", files or [], 0, form or {})
