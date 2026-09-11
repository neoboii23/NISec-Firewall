import pytest
from conftest import make_context
from engine.decision import decide

@pytest.mark.parametrize("value", ["../secret.txt", "..\\secret.txt", "%2e%2e%2fsecret.txt", "%252e%252e%252fsecret.txt", "nested/..\\../secret", "C:\\Windows\\win.ini", "/outside.txt"])
def test_attack(detector_engine, value):
    result = detector_engine.inspect(make_context(value, field="file", path="/download"))
    assert decide(result) == 403
    assert any(m.category == "DIRECTORY_TRAVERSAL" for m in result.matches)

@pytest.mark.parametrize("value", ["readme.txt", "manuals/readme.txt", "laptop.jpg"])
def test_filename(detector_engine, value):
    assert decide(detector_engine.inspect(make_context(value, field="file", path="/download"))) is None

def test_static_path(detector_engine):
    assert decide(detector_engine.inspect(make_context(path="/images/products/laptop.jpg"))) is None
