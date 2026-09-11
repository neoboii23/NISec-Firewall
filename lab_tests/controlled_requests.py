"""Portable Windows/Kali smoke test; target is restricted to local loopback."""
import argparse
import ipaddress
import json
from urllib.parse import urlsplit
import requests
from .cases import CASES,BRUTE

def validate_url(url):
    parsed=urlsplit(url)
    if parsed.scheme!='http' or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('Use a plain HTTP loopback origin without credentials or paths')
    # Numeric loopback only avoids DNS rebinding and accidental LAN/public tests.
    try:allowed=ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:allowed=False
    if not allowed:raise ValueError('Only numeric loopback targets are permitted; use an approved local tunnel for Kali')
    if not parsed.port:raise ValueError('Specify the laboratory port explicitly')
    return url.rstrip('/')

def send(session,base,case):
    return session.request(case['method'],base+case['path'],timeout=10,allow_redirects=False,**case['kwargs'])

def smoke(base):
    base=validate_url(base)
    rows=[]
    with requests.Session() as client:
        client.trust_env=False
        for case in CASES:
            response=send(client,base,case)
            rows.append(dict(code=case['code'],status=response.status_code,expected=case['expected'],passed=response.status_code==case['expected']))
        statuses=[send(client,base,BRUTE).status_code for _ in range(6)]
        rows.append(dict(code=BRUTE['code'],statuses=statuses,status=statuses[-1],expected=429,passed=statuses[:5]==[200]*5 and statuses[-1]==429))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='http://127.0.0.1:8080')
    parser.add_argument('--confirm-local-lab',action='store_true',required=True)
    args=parser.parse_args()
    rows=smoke(args.url)
    print(json.dumps({'target':args.url,'results':rows,'note':'HTTP smoke checks, not proof of exploitation or detector accuracy.'},indent=2))
    return 0 if all(r['passed'] for r in rows) else 1

if __name__=='__main__':raise SystemExit(main())
