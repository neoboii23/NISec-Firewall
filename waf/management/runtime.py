"""Validated, non-secret live policy values shared by dashboard and WAF."""
import json

CATEGORIES = ('SQL_INJECTION','XSS','COMMAND_INJECTION','DIRECTORY_TRAVERSAL','BRUTE_FORCE','MALICIOUS_FILE_UPLOAD')
DEFAULTS = dict(rate_enabled=True,rate_requests=100,rate_window=60,brute_failures=5,brute_window=300,
                brute_block=600,auto_enabled=False,auto_threshold=5,auto_window=300,auto_block=600,
                auto_min_score=7,auto_categories=list(CATEGORIES),block_score=7)
BOUNDS = dict(rate_requests=(1,100000),rate_window=(1,3600),brute_failures=(2,1000),brute_window=(1,86400),
              brute_block=(1,604800),auto_threshold=(2,1000),auto_window=(1,86400),auto_block=(1,604800),
              auto_min_score=(7,1000),block_score=(1,1000))

class RuntimePolicy:
    def __init__(self,store,defaults=None):
        self.store=store
        self.defaults=DEFAULTS | (defaults or {})

    def read(self):
        with self.store.connect() as db:
            row=db.execute("SELECT value FROM management_settings WHERE key='runtime_policy'").fetchone()
        return self.defaults | (json.loads(row[0]) if row else {})

    def update(self,changes,actor):
        if not isinstance(changes,dict) or not changes or set(changes)-set(DEFAULTS):
            raise ValueError('Unknown or empty runtime policy')
        for key,value in changes.items():
            if key in ('rate_enabled','auto_enabled'):
                if type(value) is not bool:raise ValueError(key+' must be boolean')
            elif key=='auto_categories':
                if not isinstance(value,list) or not value or any(v not in CATEGORIES for v in value):
                    raise ValueError('Choose valid automatic-block categories')
            elif type(value) is not int or not BOUNDS[key][0]<=value<=BOUNDS[key][1]:
                raise ValueError(key+' is outside its permitted integer range')
        with self.store.connect() as db:
            db.execute('LOCK TABLE management_settings IN EXCLUSIVE MODE' if self.store.postgres else 'BEGIN IMMEDIATE')
            row=db.execute("SELECT value FROM management_settings WHERE key='runtime_policy'").fetchone()
            old=json.loads(row[0]) if row else {}
            new=old | changes
            db.execute("INSERT INTO management_settings VALUES ('runtime_policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(new),))
            self.store.audit(db,actor,'runtime_policy','thresholds',self.defaults | old,self.defaults | new)
        return self.read()
