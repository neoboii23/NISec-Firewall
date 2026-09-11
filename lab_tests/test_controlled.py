import pytest
from .controlled_requests import validate_url,smoke
from .services import services

def test_targets_are_loopback_only():
    assert validate_url('http://127.0.0.1:8080')=='http://127.0.0.1:8080'
    for url in ('http://example.com:8080','http://192.168.1.2:8080','http://user:pass@127.0.0.1:8080','https://127.0.0.1:8080','http://127.0.0.1:8080/path'):
        with pytest.raises(ValueError):validate_url(url)

def test_portable_smoke_real_services():
    with services() as lab:
        rows=smoke(lab['waf'])
        assert len(rows)==6 and all(r['passed'] for r in rows)
