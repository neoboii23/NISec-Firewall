import pytest
from conftest import make_context
from engine.decision import decide

@pytest.mark.parametrize("value", ["<script>alert(1)</script>", "<IMG SRC=x ONERROR=alert(1)>", "javascript:alert(1)", "&lt;script&gt;test&lt;/script&gt;", "%253Cscript%253E", "<svg/onload=alert(1)>"])
def test_attack(detector_engine, value):
    result = detector_engine.inspect(make_context(form={"body":[value]}, path="/comment"))
    assert decide(result) == 403
    assert any(m.category == "XSS" for m in result.matches)

@pytest.mark.parametrize("value", ["I am learning HTML <div> elements", "JavaScript tutorial", "script writing", "SVG graphics", "a < b > c"])
def test_legitimate(detector_engine, value):
    assert decide(detector_engine.inspect(make_context(value))) is None
