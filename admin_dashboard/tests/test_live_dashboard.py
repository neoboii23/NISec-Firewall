"""Three actual services with real WAF events and persistent management changes."""
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import requests
from lab_tests.services import stop_process

def free_port(preferred):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1",preferred))
            return preferred
        except OSError:
            return 0

def test_live_dashboard_controls_and_six_categories(tmp_path):
    root=Path(__file__).resolve().parents[2]
    script=root/"waf/tests/live_service.py"
    processes,logs=[],[]
    def start(role,port,url="-"):
        log=(tmp_path/(role+".log")).open("w",encoding="utf-8")
        logs.append(log)
        proc=subprocess.Popen([sys.executable,str(script),role,str(tmp_path),str(port),url],
                              cwd=root,stdout=log,stderr=log)
        processes.append(proc)
        deadline=time.monotonic()+20
        ready=tmp_path/(role+"_ready.json")
        while time.monotonic()<deadline:
            if ready.exists():
                return "http://127.0.0.1:"+str(json.loads(ready.read_text())["port"])
            if proc.poll() is not None:
                raise AssertionError((tmp_path/(role+".log")).read_text())
            time.sleep(.05)
        raise AssertionError("Service startup timeout")
    try:
        backend=start("backend",free_port(5000))
        waf=start("waf",free_port(8080),backend)
        dashboard=start("dashboard",free_port(9000),waf)
        admin=requests.Session();admin.trust_env=False
        user=requests.Session();user.trust_env=False
        assert admin.get(dashboard+"/api/dashboard/summary",timeout=10).status_code==401
        page=admin.get(dashboard+"/login",timeout=10)
        token=re.search(r'name="csrf" value="([^"]+)"',page.text)[1]
        page=admin.post(dashboard+"/login",data={"username":"admin","password":"Dashboard-integration-password!","csrf":token},timeout=10)
        assert page.status_code==200 and "Security overview" in page.text
        csrf=re.search(r'name="csrf-token" content="([^"]+)"',page.text)[1]
        headers={"X-CSRF-Token":csrf}
        viewer=requests.Session();viewer.trust_env=False
        login_page=viewer.get(dashboard+'/login',timeout=10)
        viewer_token=re.search(r'name="csrf" value="([^"]+)"',login_page.text)[1]
        viewer_page=viewer.post(dashboard+'/login',data={'username':'viewer','password':'Viewer-integration-password!','csrf':viewer_token},timeout=10)
        assert viewer_page.status_code==200
        viewer_token=re.search(r'name="csrf-token" content="([^"]+)"',viewer_page.text)[1]
        assert viewer.put(dashboard+'/api/rate-limits',json={'rate_enabled':False},headers={'X-CSRF-Token':viewer_token},timeout=10).status_code==403
        def get(path):
            response=admin.get(dashboard+path,timeout=10);assert response.status_code==200,response.text[:200];return response.json()
        def change(path,data=None,method="POST"):
            response=admin.request(method,dashboard+path,json=data,headers=headers,timeout=10)
            assert response.status_code==200,response.text[:200]
        initial=get("/api/dashboard/summary")
        assert admin.get(dashboard+'/live-traffic',timeout=10).status_code==200
        assert user.get(waf+"/",timeout=10).status_code==200
        assert get("/api/dashboard/summary")["allowed_requests"]==initial["allowed_requests"]+1
        assert requests.get(waf+"/internal/status",timeout=10).status_code==401
        # Each detector category produces real events and alerts, visible immediately.
        assert user.get(waf+"/search",params={"q":"' OR 1=1--"},timeout=10).status_code==403
        assert user.post(waf+"/comment",data={"body":"<script>test</script>"},timeout=10).status_code==403
        assert user.get(waf+"/search",params={"q":"127.0.0.1;whoami"},timeout=10).status_code==403
        assert user.get(waf+"/download",params={"file":"../database.db"},timeout=10).status_code==403
        assert user.post(waf+"/upload",files={"file":("harmless.php",b"synthetic note","text/plain")},timeout=10).status_code==403
        for i in range(5):
            assert user.post(waf+"/login",data={"identity":"student","password":"wrong"},timeout=10).status_code==200
        assert user.post(waf+"/login",data={"identity":"student","password":"wrong"},timeout=10).status_code==429
        stats=get("/api/attacks/stats")
        assert all(c['count']>=1 for c in get('/api/attacks/stats?period=1h')['categories'])
        assert get('/api/attack-map')['sources'][0]['location']=='Internal / Lab Network'
        assert all(c["count"]>=1 for c in stats["categories"])
        assert get("/api/dashboard/summary")["active_alerts"]>=6
        assert any(p["kind"]=="temporary" for p in get("/api/ip/blocked"))
        # Unblock synchronizes persisted IP policy and actual in-memory login counters.
        change("/api/ip",{"operation":"remove","ip":"127.0.0.1","kind":"temporary"})
        assert user.post(waf+"/login",data={"identity":"student","password":"student123"},timeout=10).status_code==200
        change("/api/ip",{"operation":"add","ip":"127.0.0.1","kind":"blacklist","reason":"Integration test"})
        assert user.get(waf+"/",timeout=10).status_code==403
        change("/api/ip",{"operation":"add","ip":"127.0.0.1","kind":"whitelist","trust_mode":"BLACKLIST_BYPASS"})
        assert user.get(waf+"/",timeout=10).status_code==200
        assert user.get(waf+"/search",params={"q":"' OR 1=1--"},timeout=10).status_code==403
        change("/api/ip",{"operation":"remove","ip":"127.0.0.1","kind":"whitelist"})
        change("/api/ip",{"operation":"remove","ip":"127.0.0.1","kind":"blacklist"})
        assert user.get(waf+"/",timeout=10).status_code==200
        change("/api/ip",{"operation":"add","ip":"127.0.0.1","kind":"whitelist","reason":"Known source, still inspect"})
        assert user.get(waf+"/search",params={"q":"' OR 1=1--"},timeout=10).status_code==403
        change("/api/ip",{"operation":"remove","ip":"127.0.0.1","kind":"whitelist"})
        # Toggle one rule whose test value matches only that signature.
        rule="/api/rules/WAF-002-XSS-002"
        assert user.get(waf+"/search",params={"q":"javascript:test"},timeout=10).status_code==403
        change(rule,{"enabled":False},"PUT")
        assert user.get(waf+"/search",params={"q":"javascript:test"},timeout=10).status_code==200
        change(rule,{"enabled":True},"PUT")
        assert user.get(waf+"/search",params={"q":"javascript:test"},timeout=10).status_code==403
        change("/api/detectors/xss",{"enabled":False},"PUT")
        assert user.get(waf+"/search",params={"q":"<script>test</script>"},timeout=10).status_code==200
        change("/api/detectors/xss",{"enabled":True},"PUT")
        assert user.get(waf+"/search",params={"q":"<script>test</script>"},timeout=10).status_code==403
        alert=get("/api/alerts")["items"][0]
        before=get("/api/dashboard/summary")["active_alerts"]
        change(f"/api/alerts/{alert['id']}/acknowledge")
        assert get("/api/dashboard/summary")["active_alerts"]==before-1
        event=get("/api/events/recent?category=SQL_INJECTION")["items"][0]
        assert get('/api/events/recent?rule=WAF-001-SQLI-001')['total']>=1
        assert admin.get(dashboard+'/logs/'+event['incident_id'],timeout=10).status_code==200
        assert admin.get(dashboard+"/events/"+event["incident_id"],timeout=10).status_code==200
        for kind in ("csv","json"):
            response=admin.get(dashboard+"/api/events/export?format="+kind+"&action=BLOCK",timeout=10)
            assert response.status_code==200 and "attachment" in response.headers["Content-Disposition"]
            assert "Dashboard-integration-password!" not in response.text and "student123" not in response.text
        assert sum(x["attacks"] for x in get("/api/charts/attacks"))>=6
        status=get("/api/system/status")
        assert status["status"]=="online" and status["backend"]=="online"
        assert "management_token" not in json.dumps(status)
        chart=admin.get(dashboard+"/static/vendor/chart.umd.js",timeout=10)
        assert chart.status_code==200 and "Chart.js" in chart.text
        change('/api/rate-limits',{'auto_enabled':True,'auto_threshold':2,'auto_categories':['XSS']},'PUT')
        change(rule+'/configuration',{'action':'LOG'},'PUT')
        assert user.get(waf+'/search',params={'q':'javascript:test'},timeout=10).status_code==200
        change(rule+'/configuration',{'action':'BLOCK'},'PUT')
        assert get('/api/audit')['items'][0]['new_value']
        # Existing XSS events in the window contribute to the newly enabled policy.
        assert user.get(waf+'/search',params={'q':'<script>test</script>'},timeout=10).status_code==403
        assert user.get(waf+'/',timeout=10).status_code==429
        assert any(p['source']=='automatic' for p in get('/api/ip/blocked'))
        change('/api/ip',{'operation':'remove','ip':'127.0.0.1','kind':'temporary'})
        change('/api/rate-limits',{'auto_enabled':False,'rate_enabled':True,'rate_requests':1},'PUT')
        assert user.get(waf+'/',timeout=10).status_code==200
        assert user.get(waf+'/',timeout=10).status_code==429
        print("\nTHREE-SERVICE VALIDATION "+json.dumps({"backend":backend,"waf":waf,"dashboard":dashboard,
          "six_categories":"passed","management_enforcement":"passed","real_event_counts":"passed"}))
    finally:
        for proc in reversed(processes):
            stop_process(proc)
        for log in logs:log.close()
