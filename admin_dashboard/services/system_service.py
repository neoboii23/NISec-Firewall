import time
import threading
from urllib.parse import urlsplit
import requests

class SystemService:
    def __init__(self,store,url,dashboard_port):
        parsed=urlsplit(url)
        if parsed.scheme not in ("http","https") or parsed.hostname not in ("127.0.0.1","localhost","::1"):
            raise ValueError("Management URL must point to the local WAF")
        self.store,self.url,self.port=store,url.rstrip("/"),dashboard_port
        self.cache=None
        self.cached_at=0
        self.lock=threading.Lock()

    def status(self):
        with self.lock:
            if self.cache and time.monotonic()-self.cached_at<3:
                return self.cache
            info={"status":"offline","backend":"unknown","enabled_rules":None,"rate_limits":[],
                  "brute_force":[],"prevention_enabled":None,"rate_limiting_enabled":None,"detection_enabled":None}
            try:
                with requests.Session() as client:
                    client.trust_env=False
                    response=client.get(self.url+"/internal/status",headers={"Authorization":"Bearer "+self.store.secret("management_token")},timeout=2)
                    if response.status_code==200:
                        info.update(response.json())
                    else:
                        info["status"]="management unavailable"
            except (requests.RequestException, ValueError):
                pass
            with self.store.connect() as db:
                healthy=db.execute("SELECT 1").fetchone()[0]==1
            info.update(dashboard="online",database="healthy" if healthy else "error",
                        waf_url=self.url,dashboard_port=self.port)
            self.cache,self.cached_at=info,time.monotonic()
            return info
