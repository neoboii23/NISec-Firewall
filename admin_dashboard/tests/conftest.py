import sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))

@pytest.fixture
def admin_app(tmp_path):
    from admin_dashboard.app import create_app
    return create_app({"TESTING":True,"DATABASE_PATH":tmp_path/"waf.db","ADMIN_PASSWORD":"Dashboard-test-password!",
                       "WAF_URL":"http://127.0.0.1:1"})

@pytest.fixture
def login(admin_app):
    client=admin_app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf=sess["csrf"]
    response=client.post("/login",data={"username":"admin","password":"Dashboard-test-password!","csrf":csrf})
    assert response.status_code==302
    with client.session_transaction() as sess:
        csrf=sess["csrf"]
    return client,csrf

@pytest.fixture
def seeded(admin_app):
    import json
    from datetime import datetime,timezone
    from waf.management.store import ManagementStore
    store=admin_app.extensions["management"]
    with store.connect() as db:
        db.execute("""CREATE TABLE security_events (
            id INTEGER PRIMARY KEY,incident_id TEXT,timestamp TEXT,source_ip TEXT,method TEXT,path TEXT,query TEXT,user_agent TEXT,
            attack_category TEXT,severity TEXT,threat_score INTEGER,matched_rules TEXT,decision TEXT,response_status INTEGER,
            category_code TEXT,category_name TEXT,categories TEXT,evidence TEXT,metadata TEXT)""")
        for i in range(61):
            attack=i%2==0
            event={"incident_id":f"WAF-TEST-{i:03}","timestamp":datetime.now(timezone.utc).isoformat(),"source_ip":"192.0.2.10" if attack else "192.0.2.11",
                   "method":"GET","path":"/search" if attack else "/","query":"password=DO-NOT-DISPLAY","user_agent":"secret-token",
                   "attack_category":"SQL_INJECTION" if attack else "NONE","severity":"HIGH" if attack else "INFO",
                   "threat_score":8 if attack else 0,"matched_rules":["WAF-001-SQLI-001"] if attack else [],
                   "decision":"BLOCK" if attack else "ALLOW","response_status":403 if attack else 200,
                   "category_code":"WAF-001" if attack else "","category_name":"SQL Injection" if attack else "NONE",
                   "categories":[{"category":"SQL_INJECTION"}] if attack else [],
                   "evidence":[{"field":"query.password","raw_value":"DO-NOT-DISPLAY","normalized_value":"secret-token","reason":"Syntax match"}],"metadata":{}}
            values={k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in event.items()}
            cursor=db.execute("INSERT INTO security_events("+",".join(values)+") VALUES ("+",".join("?" for _ in values)+")",tuple(values.values()))
            ManagementStore.capture_event(db,cursor.lastrowid,event)
    return store
