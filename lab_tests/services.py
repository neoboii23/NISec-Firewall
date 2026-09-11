"""Start only disposable, loopback lab subprocesses; preserve existing services."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]

def stop_process(process):
    # Windows venv launchers can own a child interpreter; stop this known tree.
    if os.name=='nt' and process.poll() is None:
        subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW,timeout=10)
    elif process.poll() is None:process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()

@contextmanager
def services():
    processes,logs=[],[]
    with tempfile.TemporaryDirectory(prefix='waf-evaluation-') as directory:
        work=Path(directory)
        def start(role,backend='-'):
            log=(work/(role+'.log')).open('w',encoding='utf-8');logs.append(log)
            process=subprocess.Popen([sys.executable,str(ROOT/'waf/tests/live_service.py'),role,str(work),'0',backend],
                cwd=ROOT,stdout=log,stderr=log);processes.append(process)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                ready=work/(role+'_ready.json')
                if ready.exists():return 'http://127.0.0.1:'+str(json.loads(ready.read_text())['port'])
                if process.poll() is not None:raise RuntimeError('Disposable '+role+' failed to start; inspect its local log')
                time.sleep(.05)
            raise RuntimeError('Disposable '+role+' startup timed out')
        try:
            backend=start('backend');waf=start('waf',backend)
            pids={role:json.loads((work/(role+'_ready.json')).read_text())['pid'] for role in ('backend','waf')}
            yield dict(work=work,backend=backend,waf=waf,processes=processes,pids=pids)
        finally:
            for process in reversed(processes):
                stop_process(process)
            for log in logs:log.close()
