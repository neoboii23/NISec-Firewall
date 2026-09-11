"""Real TCP proxy -> Phase 2 integration, including backend non-arrival assertions."""
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
import requests
import os

def available_port(preferred):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            return 0  # Do not interrupt existing user services.

def wait_ready(process, work, role):
    ready = work/(role+"_ready.json")
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        if ready.exists():
            return json.loads(ready.read_text())["port"]
        if process.poll() is not None:
            raise AssertionError((work/(role+".stderr")).read_text())
        time.sleep(.05)
    raise AssertionError("Local test service did not become ready")

def test_live_six_categories_and_forwarding(tmp_path):
    script = Path(__file__).with_name("live_service.py")
    processes = []
    outputs = []
    def start(role, port, backend="-"):
        output=(tmp_path/(role+".stderr")).open("w",encoding="utf-8")
        outputs.append(output)
        process=subprocess.Popen([sys.executable,str(script),role,str(tmp_path),str(port),backend],
                                 stdout=output,stderr=output,cwd=script.parents[1])
        processes.append(process)
        return wait_ready(process,tmp_path,role)
    try:
        backend_port=start("backend",available_port(5000))
        waf_port=start("waf",available_port(8080),f"http://127.0.0.1:{backend_port}")
        url=f"http://127.0.0.1:{waf_port}"
        client=requests.Session()
        client.trust_env=False
        def arrivals():
            path=tmp_path/"arrivals.jsonl"
            return len(path.read_text().splitlines()) if path.exists() else 0
        def blocked(method,path,expected=403,**kwargs):
            before=arrivals()
            response=client.request(method,url+path,timeout=10,**kwargs)
            assert response.status_code==expected, response.text[:200]
            assert arrivals()==before, "Blocked request reached vulnerable backend"
            return response
        assert client.get(url+"/",timeout=10).status_code==200
        css=client.get(url+"/static/css/style.css",timeout=10)
        assert css.status_code==200 and "text/css" in css.headers["Content-Type"]
        # Cookies, form bytes and redirects must survive the reverse proxy.
        login=client.post(url+"/login",data={"identity":"student","password":"student123"},timeout=10)
        assert login.status_code==200 and "Hi, student" in login.text
        assert "student@origine.lab" in client.get(url+"/profile",timeout=10).text
        assert "The Weekender" in client.get(url+"/search?q=travel",timeout=10).text
        comment=client.post(url+"/comment",data={"item_id":"1","body":"Nice bag; lovely design."},timeout=10)
        assert comment.status_code==200 and "Nice bag; lovely design." in comment.text
        upload=client.post(url+"/upload",files={"file":("note.txt",b"safe lab reference","text/plain")},timeout=10)
        assert upload.status_code==200 and "note.txt" in upload.text
        assert (tmp_path/"uploads/note.txt").read_bytes()==b"safe lab reference"
        assert client.get(url+"/download?file=readme.txt",timeout=10).status_code==200
        blocked("GET","/search",params={"q":"' OR 1=1--"})
        blocked("POST","/comment",data={"item_id":"1","body":"<script>test</script>"})
        blocked("GET","/search",params={"q":"127.0.0.1;whoami"})
        blocked("GET","/download",params={"file":"..%2fbackend.db"})
        blocked("POST","/upload",files={"file":("note.php",b"harmless synthetic text","text/plain")})
        blocked("POST","/upload",expected=413,files={"file":("big.txt",b"x"*1048577,"text/plain")})
        # Confirm failures are counted only after real backend authentication.
        client.get(url+"/logout",timeout=10)
        for i in range(5):
            before=arrivals()
            failure=client.post(url+"/login",data={"identity":"student","password":"failed-login-secret"},timeout=10)
            assert failure.status_code==200 and "Invalid username/email or password." in failure.text
            assert arrivals()==before+1
        blocked("POST","/login",expected=429,data={"identity":"student","password":"student123"})
        with sqlite3.connect(tmp_path/"waf.db") as db:
            categories={row[0] for row in db.execute("SELECT DISTINCT category_code FROM security_events WHERE category_code != ''")}
            assert categories=={f"WAF-00{i}" for i in range(1,7)}
            all_rows=str(db.execute("SELECT * FROM security_events").fetchall())
            assert "failed-login-secret" not in all_rows and "student123" not in all_rows
            assert db.execute("SELECT COUNT(*) FROM security_events WHERE decision='BLOCK'").fetchone()[0]>=6
        report={"backend_port":backend_port,"waf_port":waf_port,"categories":sorted(categories),
                "blocked_requests_reached_backend":0,"normal_workflow":"passed"}
        print("\nLIVE INTEGRATION " + json.dumps(report))
    finally:
        for process in reversed(processes):
            if os.name=='nt' and process.poll() is None:
                subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW,timeout=10)
            else:process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for output in outputs:
            output.close()
