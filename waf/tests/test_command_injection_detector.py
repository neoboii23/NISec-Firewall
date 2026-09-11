import pytest
from conftest import make_context
from engine.decision import decide

@pytest.mark.parametrize("value", ["127.0.0.1;whoami", "x | cat /etc/passwd", "x && dir", "$(id)", "x%3Bwhoami", "cmd.exe /c dir", "echo test > output.txt"])
def test_attack(detector_engine, value):
    result = detector_engine.inspect(make_context(value, field="host"))
    assert decide(result) == 403
    assert any(m.category == "COMMAND_INJECTION" for m in result.matches)

@pytest.mark.parametrize("value", ["Research & Development", "red | blue | green", "semicolon; punctuation", "AT&T", "&&", "||", ";"])
def test_punctuation(detector_engine, value):
    assert decide(detector_engine.inspect(make_context(value))) is None
