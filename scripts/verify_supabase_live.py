"""Post-migration live acceptance; prompts for the existing dashboard password."""
import getpass
import json
from pathlib import Path
import re
import requests
import psycopg
from activate_supabase import credentials, verify_roles

ROOT=Path(__file__).resolve().parents[1]


def main():
    report=json.loads((ROOT/'.local/migration-report.json').read_text())
    verify_roles(False)
    client=requests.Session()
    client.trust_env=False
    def get(path,base='http://127.0.0.1:8080'):
        response=client.get(base+path,timeout=10)
        assert response.status_code==200,(path,response.status_code)
        return response
    get('/')
    get('/search?q=tote')
    get('/static/css/style.css')
    response=client.post('http://127.0.0.1:8080/login',data={'identity':'student','password':'student123'},allow_redirects=False,timeout=10)
    assert response.status_code==302,'Shop login failed; check existing student password.'
    for path in ('/profile','/comment','/upload'): get(path)
    assert client.get('http://127.0.0.1:8080/download?file=readme.txt',timeout=10).status_code==200
    admin=requests.Session()
    admin.trust_env=False
    page=admin.get('http://127.0.0.1:9000/login',timeout=10)
    token=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
    password=getpass.getpass('Existing Sentinel admin password: ')
    signed=admin.post('http://127.0.0.1:9000/login',data={'username':'admin','password':password,'csrf':token},allow_redirects=False,timeout=10)
    assert signed.status_code==302,'Dashboard authentication failed'
    for path in ('/dashboard','/logs','/analytics','/attack-map','/rules','/ip-management','/rate-limits','/settings','/evaluation'):
        assert admin.get('http://127.0.0.1:9000'+path,timeout=10).status_code==200,path
    status=admin.get('http://127.0.0.1:9000/api/system/status',timeout=10).json()
    assert status['status']=='online' and status['backend']=='online' and status['database']=='healthy',status
    attack=client.get('http://127.0.0.1:8080/search',params={'q':"' OR 1=1--"},timeout=10)
    assert attack.status_code==403,'Expected current SQL injection rules to block the controlled sample'
    with psycopg.connect(credentials('security')) as pg:
        last=pg.execute("SELECT attack_category,decision FROM security_events WHERE path='/search' ORDER BY id DESC LIMIT 1").fetchone()
        assert last==('SQL_INJECTION','BLOCK'),last
        count=pg.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
    assert count>report['tables']['security.security_events']['rows']
    studio=client.get('http://127.0.0.1:54323',timeout=10)
    assert studio.status_code==200
    proof={'run':report['run'],'success':True,'checks':['shop login/pages/assets','Sentinel authentication/pages','all service health','SQL injection blocked and stored in PostgreSQL','cross-schema access denied','Studio reachable'],'security_events_after':count}
    (ROOT/'.local/live-verification.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof,indent=2))


if __name__=='__main__': main()
