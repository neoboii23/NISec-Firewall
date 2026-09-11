import pytest
from urllib.parse import quote
from conftest import make_context
from engine.decision import decide

@pytest.mark.parametrize("payload", ["' OR 1=1--", "' OR 'a'='a", "1 OR 1=1", "x UNION SELECT name FROM item", "x'; DROP TABLE item--", "sleep(3)", "WAITFOR DELAY '0:0:1'", "' oR\n 1 = 1 --", "&#39; OR 1=1--", quote(quote("' OR 1=1--"))])
def test_attack(detector_engine, payload):
    result = detector_engine.inspect(make_context(payload))
    assert decide(result) == 403
    assert any(m.category == "SQL_INJECTION" for m in result.matches)
    assert all(m.rule_id.startswith("WAF-") for m in result.matches)

@pytest.mark.parametrize("value", ["union jack", "select monitor", "or condition", "bread and butter", "O'Reilly", "notes -- final"])
def test_legitimate(detector_engine, value):
    assert decide(detector_engine.inspect(make_context(value))) is None

def test_evidence_and_no_credential_values(detector_engine):
    ctx = make_context(form={"password":["' OR 1=1--"], "identity":["student"]}, path="/login")
    result = detector_engine.inspect(ctx)
    assert decide(result) == 403
    assert all(m.evidence["raw_value"] == "[REDACTED]" for m in result.matches)
