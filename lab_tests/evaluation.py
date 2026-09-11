"""Small reproducible local benchmark; numbers are observations, not coverage claims."""
import argparse
from datetime import datetime,timezone
import json
import math
import os
from pathlib import Path
import statistics
import time
import uuid
import requests
from .comparison import comparison,cursor,evidence,save
from .services import services

def normal_traffic():
    cases=[
        ('registration','POST','/register',{'data':{'username':'evaluation-user','email':'evaluation@lab.invalid','password':'synthetic-test-password','confirm_password':'synthetic-test-password'}}),
        ('login','POST','/login',{'data':{'identity':'evaluation-user','password':'synthetic-test-password'}}),
        ('search','GET','/search',{'params':{'q':'union travel'}}),
        ('profile update','POST','/profile/edit',{'data':{'email':'evaluation@lab.invalid','full_name':'Lab Reviewer','bio':'Bags for everyday travel.'}}),
        ('comment','POST','/comment',{'data':{'item_id':'1','body':"It's a lovely bag; thank you!"}}),
        ('upload','POST','/upload',{'files':{'file':('normal.txt',b'Harmless normal laboratory note.','text/plain')}}),
        ('download','GET','/download',{'params':{'file':'readme.txt'}}),
    ]
    rows=[]
    with services() as lab,requests.Session() as client:
        client.trust_env=False
        for name,method,path,kwargs in cases:
            before=cursor(lab['work'])
            response=client.request(method,lab['waf']+path,timeout=10,allow_redirects=False,**kwargs)
            proof=evidence(lab['work'],before,'NONE')
            detected=any(json.loads(e['matched_rules'] or '[]') for e in proof['events'])
            blocked=any(e['decision'] in ('BLOCK','RATE_LIMIT') for e in proof['events'])
            rows.append(dict(name=name,status=response.status_code,detected=detected,blocked=blocked,
                functional_success=response.status_code in (200,302),event_ids=[e['incident_id'] for e in proof['events']]))
    return rows

def ratio(numerator,denominator):return numerator/denominator if denominator else None

def effectiveness(attacks,normal):
    tp=sum(bool(r['detected']) for r in attacks);fn=len(attacks)-tp
    fp=sum(bool(r['detected']) for r in normal);tn=len(normal)-fp
    return dict(true_positives=tp,false_negatives=fn,false_positives=fp,true_negatives=tn,
        detection_rate=ratio(tp,len(attacks)),blocking_rate=ratio(sum(r['blocked'] for r in attacks),len(attacks)),
        false_positive_rate=ratio(fp,len(normal)),false_block_rate=ratio(sum(r['blocked'] for r in normal),len(normal)),
        precision=ratio(tp,tp+fp),recall=ratio(tp,tp+fn),
        per_attack=[dict(code=r['code'],category=r['category'],tested=1,detected=int(r['detected']),blocked=int(r['blocked'])) for r in attacks])

def benchmark(samples):
    if not 5<=samples<=1000:raise ValueError('Benchmark samples must be between 5 and 1000 per path')
    import psutil
    def cpu(processes):return sum(p.cpu_times().user+p.cpu_times().system for p in processes)
    def memory(processes):return sum(p.memory_info().rss for p in processes)
    with services() as lab,requests.Session() as client:
        client.trust_env=False
        for target in ('backend','waf'):
            for _ in range(5):client.get(lab[target]+'/search?q=tote',timeout=10)
        results={}
        for name,target,roles in [('direct','backend',('backend',)),('protected','waf',('backend','waf'))]:
            processes=[psutil.Process(lab['pids'][role]) for role in roles]
            cpu_start=cpu(processes);peak=memory(processes);latencies=[];statuses=[]
            start=time.perf_counter()
            for _ in range(samples):
                before=time.perf_counter()
                response=client.get(lab[target]+'/search?q=tote',timeout=10,allow_redirects=False)
                latencies.append((time.perf_counter()-before)*1000)
                statuses.append(response.status_code);peak=max(peak,memory(processes))
            elapsed=time.perf_counter()-start
            results[name]=dict(samples=samples,mean_latency_ms=statistics.mean(latencies),
                median_latency_ms=statistics.median(latencies),p95_latency_ms=sorted(latencies)[math.ceil(samples*.95)-1],
                requests_per_second=samples/elapsed,cpu_percent_one_core=(cpu(processes)-cpu_start)/elapsed*100,
                peak_sampled_rss_mib=peak/1024**2,successful_responses=sum(s==200 for s in statuses),
                latency_samples_ms=latencies,elapsed_seconds=elapsed)
        direct=results['direct']['mean_latency_ms'];protected=results['protected']['mean_latency_ms']
        results['overhead_ms']=protected-direct
        results['overhead_percent']=(protected-direct)/direct*100 if direct else None
        results['methodology']='Sequential single-client batches; direct then protected after 5 warmups each. CPU is server process-time delta as a percent of one core; protected includes WAF + backend. RSS is sampled, not OS peak. Generic rate limit disabled in disposable test configuration.'
        results['caveat']='Loopback development-server microbenchmark, not capacity/load testing. Client-observed latency difference includes proxy, network and logging costs, not pure detector time. Batch order and host noise can bias results.'
    return results

def evaluate(samples=50):
    report=comparison()
    normal=normal_traffic()
    report.update(run_id=uuid.uuid4().hex,created_at=datetime.now(timezone.utc).isoformat(),dataset='synthetic-v1',
        normal_traffic=normal,effectiveness=effectiveness(report['protected'],normal),performance=benchmark(samples),
        limitations=['One scenario per attack category and seven legitimate scenarios; not statistically representative.',
                     'XSS confirms unescaped stored markup, not browser execution. Command execution is not implemented in the backend.',
                     'No Kali VM execution or public GeoIP dataset was available.'])
    return report

def write_report(report,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    save(report,directory)
    encoded=json.dumps(report,indent=2,allow_nan=False)
    history=directory/('evaluation-'+report['run_id']+'.json');history.write_text(encoded,encoding='utf-8')
    temporary=directory/('pending-'+report['run_id']+'.json');temporary.write_text(encoded,encoding='utf-8')
    os.replace(temporary,directory/'evaluation.json')
    return directory/'evaluation.json'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples',type=int,default=50)
    parser.add_argument('--output',default='evaluation_results')
    args=parser.parse_args()
    report=evaluate(args.samples)
    print(write_report(report,args.output))
    print(json.dumps({'effectiveness':report['effectiveness'],'performance':{k:v for k,v in report['performance'].items() if k not in ('direct','protected')},
                     'direct':{k:v for k,v in report['performance']['direct'].items() if k!='latency_samples_ms'},
                     'protected':{k:v for k,v in report['performance']['protected'].items() if k!='latency_samples_ms'}},indent=2))

if __name__=='__main__':main()
