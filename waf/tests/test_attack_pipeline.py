import io
import json
import sqlite3
from unittest.mock import Mock
import pytest
import app as proxy_app
from flask import Response
from conftest import make_context, ROOT
from engine.decision import decide
from engine.inspector import inspect_request
from engine.normalizer import Normalizer
from engine.rule_engine import RuleEngine

@pytest.fixture
def gateway(tmp_path):
    return proxy_app.create_app({"TESTING":True, "DATABASE_PATH":tmp_path/"events.db",
        "LOG_DIR":tmp_path/"logs", "RATE_LIMIT_ENABLED":False})

def test_multiple_matches(detector_engine):
    result = detector_engine.inspect(make_context("' OR 1=1-- ;whoami"))
    assert decide(result) == 403
    assert result.severity == "CRITICAL"
    assert len({m.category for m in result.matches}) >= 2

def test_legacy_database_migration(tmp_path):
    from database.models import SecurityEventStore
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY, incident_id TEXT, timestamp TEXT, source_ip TEXT, method TEXT, path TEXT, query TEXT, user_agent TEXT, attack_category TEXT, severity TEXT, threat_score INTEGER, matched_rules TEXT, decision TEXT, response_status INTEGER)")
        db.execute("INSERT INTO security_events (id, attack_category, decision) VALUES (1, 'PATH_TRAVERSAL', 'BLOCK')")
    store = SecurityEventStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT id, attack_category, category_code FROM security_events").fetchone() == (1, "DIRECTORY_TRAVERSAL", "WAF-004")
    assert store.attack_counts()["DIRECTORY_TRAVERSAL"] == 1

def test_disable_detector(settings):
    settings["sql_injection"]["enabled"] = False
    engine = RuleEngine(ROOT/"rules", Normalizer(), 2, settings)
    assert decide(engine.inspect(make_context("' OR 1=1--"))) is None

def test_disabled_rule_and_log_action(tmp_path, settings):
    rule = {"id":"WAF-001-TEST","category":"SQL_INJECTION","severity":"HIGH","score":9,
            "name":"Test rule","targets":["query"],"patterns":["test"],"enabled":False}
    path=tmp_path/"test.json"
    path.write_text(json.dumps({"rules":[rule]}))
    engine=RuleEngine(tmp_path,Normalizer(),2,settings)
    assert not engine.inspect(make_context("test")).matches
    rule.update(enabled=True,action="LOG")
    path.write_text(json.dumps({"rules":[rule]}))
    result=RuleEngine(tmp_path,Normalizer(),2,settings).inspect(make_context("test"))
    assert result.score == 9 and decide(result) is None

def test_block_never_forwards_and_redacts(gateway, monkeypatch):
    forward = Mock(return_value=Response("ok"))
    monkeypatch.setattr(proxy_app, "forward", forward)
    response = gateway.test_client().post("/login?password=not-for-logs",
        data={"identity":"student","password":"' OR 1=1--"}, headers={"Cookie":"session=secret-token"})
    assert response.status_code == 403
    forward.assert_not_called()
    with sqlite3.connect(gateway.config["DATABASE_PATH"]) as conn:
        row = conn.execute("SELECT category_code, evidence, query FROM security_events ORDER BY id DESC LIMIT 1").fetchone()
    assert row[0] == "WAF-001"
    assert "' OR 1=1--" not in str(row) and "not-for-logs" not in str(row)
    log = (gateway.config["LOG_DIR"]/"security.log").read_text()
    assert "secret-token" not in log and "not-for-logs" not in log
    assert "[REDACTED]" in log

def test_multipart_preservation_and_duplicate_fields(gateway, monkeypatch):
    received = []
    def forward(base, path):
        from flask import request
        received.append(request.get_data())
        return Response("ok")
    monkeypatch.setattr(proxy_app, "forward", forward)
    client = gateway.test_client()
    response = client.post("/upload", data={"body":"Nice bag","file":(io.BytesIO(b"safe note"),"note.txt","text/plain")})
    assert response.status_code == 200 and b"safe note" in received[0]
    response = client.get("/search?q=normal&q=%3Cscript%3E")
    assert response.status_code == 403 and len(received) == 1

def test_json_cookies_and_headers(gateway, monkeypatch):
    monkeypatch.setattr(proxy_app, "forward", Mock(return_value=Response("ok")))
    client=gateway.test_client()
    assert client.post("/comment", json={"note":{"text":"<script>test</script>"}}).status_code == 403
    client.set_cookie("note", "<script>test</script>")
    assert client.get("/").status_code == 403
    client.delete_cookie("note")
    assert client.get("/",headers={"X-Test":"<script>test</script>"}).status_code == 403

def test_limits_and_malformed(gateway, monkeypatch):
    forward=Mock(return_value=Response("ok"))
    monkeypatch.setattr(proxy_app, "forward", forward)
    assert gateway.test_client().post("/upload",data=b"x"*(gateway.config["MAX_BODY_SIZE"]+1)).status_code == 413
    assert gateway.test_client().post("/comment",data="{bad",content_type="application/json").status_code == 400
    forward.assert_not_called()

def test_static_routes_and_login_response_hook(gateway, monkeypatch):
    forward=Mock(return_value=Response("css",content_type="text/css"))
    monkeypatch.setattr(proxy_app, "forward", forward)
    assert gateway.test_client().get("/static/css/style.css").status_code == 200
    forward.side_effect=lambda *args: Response("login failed",status=200,headers={"X-Lab-Auth-Result":"failure"})
    client=gateway.test_client()
    for n in range(5):
        response=client.post("/login",data={"identity":"student","password":"wrong"})
        assert response.status_code == 200
        assert "X-Lab-Auth-Result" not in response.headers
    assert client.post("/login",data={"identity":"student","password":"wrong"}).status_code == 429
    assert forward.call_count == 6  # CSS + five real failed authentications.
