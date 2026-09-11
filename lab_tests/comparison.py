"""Measured before/after outcomes, isolated from the working storefront and WAF DB."""
import argparse
from contextlib import closing
import csv
from datetime import datetime,timezone
import json
from pathlib import Path
import platform
import sqlite3
import requests
from .cases import CASES,BRUTE
from .controlled_requests import send
from .services import services

def arrivals(work):
    path=work/'arrivals.jsonl'
    return len(path.read_text(encoding='utf-8').splitlines()) if path.exists() else 0

def query(work,sql,values=()):
    with closing(sqlite3.connect(work/'waf.db')) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute(sql,values).fetchall()]

def cursor(work):return query(work,'SELECT COALESCE(MAX(id),0) id FROM security_events')[0]['id']

def evidence(work,after,category):
    rows=query(work,'''SELECT id,incident_id,category_code,categories,matched_rules,decision,response_status
        FROM security_events WHERE id>? ORDER BY id''',(after,))
    return dict(detected=any(category in [c['category'] for c in json.loads(r['categories'] or '[]')] for r in rows),
                events=[{k:v for k,v in r.items() if k!='categories'} for r in rows],
                alerts=query(work,'SELECT COUNT(*) n FROM security_alerts WHERE event_id>?',(after,))[0]['n'])

def run_mode(protected):
    rows=[]
    with services() as lab,requests.Session() as client:
        client.trust_env=False
        base=lab['waf'] if protected else lab['backend']
        work=lab['work']
        canary=b'Synthetic evaluation traversal canary; no private data.'
        (work/'evaluation-canary.txt').write_bytes(canary)
        login=client.post(base+'/login',data={'identity':'student','password':'student123'},timeout=10,allow_redirects=False)
        if login.status_code!=302:raise RuntimeError('Evaluation setup login failed')
        baseline=client.get(base+'/search',params={'q':'unmatched-lab-baseline-4829'},timeout=10,allow_redirects=False)
        for case in CASES:
            before=cursor(work)
            count=arrivals(work)
            response=send(client,base,case)
            reached=arrivals(work)-count
            row=dict(code=case['code'],category=case['category'],status=response.status_code,
                     backend_arrivals=reached,detected=False,blocked=False,vulnerability_demonstrated=False)
            if protected:
                row.update(evidence(work,before,case['category']))
                row['blocked']=response.status_code in (403,413,429) and any(e['decision'] in ('BLOCK','RATE_LIMIT') for e in row['events'])
                row['observation']='Prevented before backend' if row['blocked'] and reached==0 else 'Inspect recorded response and events'
            elif case['code']=='WAF-001':
                normal=baseline.text.count('class="product-card"')
                injected=response.text.count('class="product-card"')
                row.update(vulnerability_demonstrated=injected>normal,observation=f'Unmatched baseline returned {normal} catalog rows; boolean injection returned {injected}')
            elif case['code']=='WAF-002':
                rendered=client.get(base+'/comment',timeout=10).text
                unsafe=case['kwargs']['data']['body'] in rendered
                row.update(vulnerability_demonstrated=unsafe,observation='Stored script markup rendered unescaped; browser execution not tested' if unsafe else 'No unescaped script markup observed')
            elif case['code']=='WAF-003':
                row.update(vulnerability_demonstrated=None,observation='Pattern accepted as search text; backend has no command-execution sink')
            elif case['code']=='WAF-004':
                row.update(vulnerability_demonstrated=response.content==canary,observation='Synthetic canary outside download directory returned' if response.content==canary else 'Canary not returned')
            elif case['code']=='WAF-006':
                stored=work/'uploads/synthetic.php'
                accepted=stored.exists() and stored.read_bytes()==case['kwargs']['files']['file'][1]
                row.update(vulnerability_demonstrated=accepted,observation='Disallowed extension stored; harmless content, never executed' if accepted else 'File not stored')
            rows.append(row)
        client.get(base+'/logout',timeout=10,allow_redirects=False)
        before=cursor(work)
        statuses=[]
        last_arrivals=0
        for _ in range(6):
            count=arrivals(work)
            statuses.append(send(client,base,BRUTE).status_code)
            last_arrivals=arrivals(work)-count
        row=dict(code='WAF-005',category='BRUTE_FORCE',status=statuses[-1],statuses=statuses,backend_arrivals=last_arrivals,
                 detected=False,blocked=False,vulnerability_demonstrated=all(s==200 for s in statuses) if not protected else False,
                 observation='Six failed logins accepted without throttling' if not protected else 'Failure threshold and sixth login response observed')
        if protected:
            row.update(evidence(work,before,'BRUTE_FORCE'))
            row['blocked']=statuses[-1]==429 and last_arrivals==0
        rows.append(row)
    return sorted(rows,key=lambda r:r['code'])

def comparison():
    direct,protected=run_mode(False),run_mode(True)
    return dict(created_at=datetime.now(timezone.utc).isoformat(),platform=platform.platform(),
                methodology='Identical synthetic cases in separate fresh temporary labs; backend vulnerable mode enabled. No public targets.',
                unit='One scenario per attack category; brute force is one six-request sequence.',
                direct=direct,protected=protected,
                comparison=[dict(code=a['code'],category=a['category'],without_waf=a['observation'],direct_status=a['status'],
                    vulnerability_demonstrated=a['vulnerability_demonstrated'],with_waf=b['observation'],protected_status=b['status'],
                    detected=b['detected'],blocked=b['blocked'],blocked_backend_arrivals=b['backend_arrivals']) for a,b in zip(direct,protected)])

def save(report,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    path=directory/'comparison.json';path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    with (directory/'comparison.csv').open('w',newline='',encoding='utf-8') as output:
        writer=csv.DictWriter(output,fieldnames=list(report['comparison'][0]));writer.writeheader();writer.writerows(report['comparison'])
    return path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='evaluation_results')
    args=parser.parse_args()
    report=comparison()
    print(save(report,args.output))
    print(json.dumps(report['comparison'],indent=2))

if __name__=='__main__':main()
