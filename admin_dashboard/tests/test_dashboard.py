import json
import pytest

def test_authentication_required(admin_app):
    client=admin_app.test_client()
    for path in ("/","/events","/attacks","/rules","/ip-management","/alerts","/system"):
        assert client.get(path).status_code==302
    for path in ("/api/dashboard/summary","/api/events/recent","/api/alerts","/api/rules","/api/ip/blocked","/api/system/status","/api/events/export"):
        assert client.get(path).status_code==401

def test_login_logout_and_csrf(admin_app,login):
    client,csrf=login
    page=client.get("/")
    assert page.status_code==200
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert "no-store" in page.headers["Cache-Control"]
    assert b'id="backend-state"' in page.data
    assert client.post("/logout").status_code==403
    assert client.post("/logout",data={"csrf":csrf}).status_code==302
    assert client.get("/api/rules").status_code==401
    assert admin_app.config["SESSION_COOKIE_NAME"]=="waf_admin_session"
    with admin_app.extensions["management"].connect() as db:
        password=db.execute("SELECT password_hash FROM dashboard_admins").fetchone()[0]
        assert "Dashboard-test-password!" not in password

def test_invalid_login(admin_app):
    client=admin_app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        token=sess["csrf"]
    response=client.post("/login",data={"username":"missing","password":"wrong","csrf":token})
    assert b"Unable to sign in" in response.data
    assert client.get("/api/rules").status_code==401

def test_summary_filters_and_pagination(login,seeded):
    client,_=login
    summary=client.get("/api/dashboard/summary").json
    assert summary["total_requests"]==61
    assert summary["allowed_requests"]==30
    assert summary["blocked_requests"]==31
    assert summary["total_attacks"]==31
    assert summary["active_alerts"]==31
    page1=client.get("/api/events/recent").json
    page2=client.get("/api/events/recent?page=2").json
    assert len(page1["items"])==25 and page1["pages"]==3
    assert page1["items"][0]["id"]!=page2["items"][0]["id"]
    assert client.get("/api/events/recent?source_ip=192.0.2.10&action=BLOCK&method=GET").json["total"]==31
    assert client.get("/api/events/recent?category=SQL_INJECTION&severity=HIGH&path=search").json["total"]==31
    assert client.get("/api/events/recent?incident_id=WAF-TEST-060").json["total"]==1
    assert client.get("/api/events/recent?start=not-a-date").status_code==400
    assert client.get("/api/events/recent?page=abc").status_code==400
    assert client.get("/api/attacks/stats").json["categories"][0]["count"]==31
    assert len(client.get("/api/charts/attacks").json)==60

def test_events_detail_exports_are_safe(login,seeded):
    client,_=login
    for path in ("/events/WAF-TEST-060","/api/events/recent","/api/events/export?format=json","/api/events/export?format=csv"):
        response=client.get(path)
        assert response.status_code==200
        assert b"DO-NOT-DISPLAY" not in response.data and b"secret-token" not in response.data
    assert len(client.get("/api/events/export?format=json&action=ALLOW").json)==30
    csv=client.get("/api/events/export?format=csv&action=BLOCK")
    assert csv.headers["Content-Disposition"].endswith("security-events.csv")
    assert len(csv.data.decode().splitlines())==32

def test_rule_detector_state_persistence(login,admin_app):
    client,csrf=login
    identifier=client.get("/api/rules").json["rules"][0]["id"]
    assert client.put("/api/rules/"+identifier,json={"enabled":False}).status_code==403
    headers={"X-CSRF-Token":csrf}
    assert client.put("/api/rules/"+identifier,json={"enabled":False},headers=headers).status_code==200
    assert client.put("/api/detectors/xss",json={"enabled":False},headers=headers).status_code==200
    assert client.put("/api/detectors/missing",json={"enabled":False},headers=headers).status_code==400
    assert client.put("/api/rules/"+identifier,json={"enabled":"false"},headers=headers).status_code==400
    states=admin_app.extensions["management"].states()
    assert states[0][identifier] is False and states[1]["xss"] is False

def test_ip_policies_alerts(login,seeded,admin_app):
    client,csrf=login
    headers={"X-CSRF-Token":csrf}
    for kind in ("blacklist","whitelist","temporary"):
        response=client.post("/api/ip",json={"operation":"add","kind":kind,"ip":"192.0.2.5","duration":60,"reason":"Lab test"},headers=headers)
        assert response.status_code==200
    assert len(client.get("/api/ip/blocked?ip=192.0.2.5").json)==3
    assert client.get("/api/dashboard/summary").json["temporary_blocks"]==1
    assert client.post("/api/ip",json={"operation":"remove","kind":"temporary","ip":"192.0.2.5"},headers=headers).status_code==200
    assert client.get("/api/dashboard/summary").json["temporary_blocks"]==0
    assert admin_app.extensions["management"].commands(0)
    assert client.post("/api/ip",json={"operation":"add","kind":"blacklist","ip":"invalid"},headers=headers).status_code==400
    alert=client.get("/api/alerts").json["items"][0]
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge",headers=headers).status_code==200
    assert client.get("/api/dashboard/summary").json["active_alerts"]==30

def test_system_offline_is_honest(login):
    client,_=login
    response=client.get("/api/system/status")
    assert response.status_code==200 and response.json["status"]=="offline"
    assert response.json["backend"]=="unknown" and response.json["database"]=="healthy"
    assert "management_token" not in response.data.decode()

def test_management_input_validation(login):
    client,csrf=login
    headers={"X-CSRF-Token":csrf}
    for endpoint in ("/api/rules/WAF-002-XSS-001", "/api/detectors/xss", "/api/ip"):
        method=client.post if endpoint=="/api/ip" else client.put
        for payload in ([], "invalid", 42):
            assert method(endpoint,json=payload,headers=headers).status_code==400
        assert method(endpoint,data="null",content_type="application/json",headers=headers).status_code==400
    for field,value in (("reason",None),("kind",[]),("ip",123),("duration",{})):
        payload={"operation":"add","kind":"temporary","ip":"192.0.2.5",field:value}
        assert client.post("/api/ip",json=payload,headers=headers).status_code==400

def test_output_escaping_and_csv_formula_guard(login,seeded):
    client,_=login
    with seeded.connect() as db:
        db.execute("UPDATE security_events SET path=? WHERE incident_id='WAF-TEST-060'",("<script>unsafe()</script>",))
    page=client.get("/events/WAF-TEST-060")
    assert b"<script>unsafe()" not in page.data and b"&lt;script&gt;unsafe()" in page.data
    with seeded.connect() as db:
        db.execute("UPDATE security_events SET path=? WHERE incident_id='WAF-TEST-060'",("=SUM(1,1)",))
    assert b"'=SUM(1,1)" in client.get("/api/events/export?format=csv").data
