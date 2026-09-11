"""All management writes go through this service, in the existing WAF SQLite DB."""
from contextlib import contextmanager
import ipaddress
import json
from pathlib import Path
import secrets
import sqlite3
import time

DETECTORS = ("sql_injection","xss","command_injection","directory_traversal","brute_force","file_upload")
TRUST_MODES = ("NORMAL", "RATE_LIMIT_BYPASS", "BLACKLIST_BYPASS", "FULL_BYPASS")

class ManagementStore:
    def __init__(self, path):
        self.postgres = str(path).startswith(('postgresql://', 'postgresql+psycopg://'))
        if self.postgres:
            self.url = str(path).replace('postgresql://', 'postgresql+psycopg://', 1)
            self.path = None
            with self.connect() as db:
                if db.execute('SELECT version FROM schema_version').fetchone()[0] != 1:
                    raise ValueError('Unsupported security database schema')
            return
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS management_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rule_states (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, changed_at REAL NOT NULL, changed_by TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS detector_states (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, changed_at REAL NOT NULL, changed_by TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ip_policies (
              ip TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL, created_at REAL NOT NULL,
              expires_at REAL, added_by TEXT NOT NULL, incident_id TEXT, scope TEXT NOT NULL DEFAULT 'all',
              PRIMARY KEY(ip,kind));
            CREATE INDEX IF NOT EXISTS ix_ip_policy_expiry ON ip_policies(expires_at);
            CREATE TABLE IF NOT EXISTS management_commands (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS security_alerts (
              id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE NOT NULL, incident_id TEXT NOT NULL,
              timestamp TEXT NOT NULL, source_ip TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
              message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, acknowledged_at REAL, acknowledged_by TEXT);
            CREATE INDEX IF NOT EXISTS ix_alert_active ON security_alerts(acknowledged,id);
            CREATE TABLE IF NOT EXISTS event_categories (
              event_id INTEGER NOT NULL, category TEXT NOT NULL, PRIMARY KEY(event_id,category));
            CREATE INDEX IF NOT EXISTS ix_event_categories ON event_categories(category,event_id);
            CREATE TABLE IF NOT EXISTS management_audit (
              id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dashboard_admins (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_login_limits (ip TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_start REAL NOT NULL, until REAL NOT NULL);
            """)
            columns = {r[1] for r in db.execute("PRAGMA table_info(ip_policies)")}
            for name, definition in (("source", "TEXT NOT NULL DEFAULT 'manual'"),
                                     ("attack_category", "TEXT"), ("trust_mode", "TEXT NOT NULL DEFAULT 'NORMAL'")):
                if name not in columns:
                    db.execute(f"ALTER TABLE ip_policies ADD COLUMN {name} {definition}")
            audit_columns={r[1] for r in db.execute('PRAGMA table_info(management_audit)')}
            if 'role' not in {r[1] for r in db.execute('PRAGMA table_info(dashboard_admins)')}:
                db.execute("ALTER TABLE dashboard_admins ADD COLUMN role TEXT NOT NULL DEFAULT 'ADMIN'")
            for name in ('old_value','new_value'):
                if name not in audit_columns:db.execute(f'ALTER TABLE management_audit ADD COLUMN {name} TEXT')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS firewall_rules (id TEXT PRIMARY KEY, config TEXT NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS rate_limit_records (id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE,
                    source_ip TEXT NOT NULL, timestamp TEXT NOT NULL, retry_after INTEGER NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES security_events(id));
                CREATE INDEX IF NOT EXISTS ix_rate_record_ip_time ON rate_limit_records(source_ip,timestamp);
                CREATE VIEW IF NOT EXISTS blocked_ips AS SELECT * FROM ip_policies WHERE kind IN ('blacklist','temporary');
                CREATE VIEW IF NOT EXISTS trusted_ips AS SELECT * FROM ip_policies WHERE kind='whitelist';
            ''')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='security_events'").fetchone():
                db.execute('''CREATE VIEW IF NOT EXISTS request_logs AS SELECT id,incident_id,timestamp,source_ip,
                    method,path,decision,response_status FROM security_events''')
                db.execute('CREATE INDEX IF NOT EXISTS ix_event_ip_time ON security_events(source_ip,timestamp)')
                db.execute('CREATE INDEX IF NOT EXISTS ix_event_incident ON security_events(incident_id)')
            for key in ("management_token","dashboard_secret"):
                db.execute("INSERT OR IGNORE INTO management_settings VALUES (?,?)", (key,secrets.token_hex(32)))
            self.backfill(db)

    @contextmanager
    def connect(self):
        if self.postgres:
            from .postgres import connect
            with connect(self.url) as db:
                yield db
            return
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def secret(self, key):
        with self.connect() as db:
            return db.execute("SELECT value FROM management_settings WHERE key=?", (key,)).fetchone()[0]

    @staticmethod
    def capture_event(db, event_id, event):
        if event['decision']=='RATE_LIMIT':
            db.execute('''INSERT INTO rate_limit_records(event_id,source_ip,timestamp,retry_after)
                VALUES (?,?,?,?) ON CONFLICT DO NOTHING''',(event_id,event['source_ip'],event['timestamp'],event.get('metadata',{}).get('retry_after',60)))
        for category in event.get("categories", []):
            db.execute("INSERT INTO event_categories VALUES (?,?) ON CONFLICT DO NOTHING", (event_id,category["category"]))
        if (event["severity"] in ("HIGH","CRITICAL") or event.get('metadata',{}).get('alert_requested')) and event.get("matched_rules"):
            db.execute("""INSERT INTO security_alerts
              (event_id,incident_id,timestamp,source_ip,category,severity,message) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
              (event_id,event["incident_id"],event["timestamp"],event["source_ip"],event["attack_category"],
               event["severity"],"Security detection: " + event.get("category_name",event["attack_category"])))

    @staticmethod
    def backfill(db):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='security_events'").fetchone():
            return
        # Indexed watermark makes subsequent process starts incremental, not a full scan.
        marker=db.execute("SELECT value FROM management_settings WHERE key='projection_watermark'").fetchone()
        since=int(marker[0]) if marker else 0
        maximum=db.execute("SELECT COALESCE(MAX(id),0) FROM security_events").fetchone()[0]
        db.execute("""INSERT OR IGNORE INTO event_categories SELECT e.id,json_extract(j.value,'$.category')
          FROM security_events e,json_each(CASE WHEN json_valid(e.categories) THEN e.categories ELSE '[]' END) j
          WHERE e.id>? AND e.id<=? AND json_extract(j.value,'$.category') IS NOT NULL""", (since,maximum))
        db.execute("""INSERT OR IGNORE INTO security_alerts
          (event_id,incident_id,timestamp,source_ip,category,severity,message)
          SELECT id,incident_id,timestamp,source_ip,attack_category,severity,'Security detection: '||COALESCE(category_name,attack_category)
          FROM security_events WHERE id>? AND id<=? AND severity IN ('HIGH','CRITICAL')
          AND matched_rules IS NOT NULL AND matched_rules!='[]' AND incident_id IS NOT NULL""", (since,maximum))
        db.execute("INSERT OR REPLACE INTO management_settings VALUES ('projection_watermark',?)",(str(maximum),))

    def states(self):
        with self.connect() as db:
            return ({r["id"]:bool(r["enabled"]) for r in db.execute("SELECT * FROM rule_states")},
                    {r["id"]:bool(r["enabled"]) for r in db.execute("SELECT * FROM detector_states")})

    @staticmethod
    def audit(db, actor, action, target, old=None, new=None):
        db.execute("INSERT INTO management_audit(timestamp,actor,action,target,old_value,new_value) VALUES (?,?,?,?,?,?)",
                   (time.time(),actor,action,target,json.dumps(old),json.dumps(new)))

    def set_enabled(self, kind, identifier, enabled, actor, previous=None):
        if type(enabled) is not bool or kind not in ("rule","detector"):
            raise ValueError("Invalid state change")
        if kind=="detector" and identifier not in DETECTORS:
            raise ValueError("Unknown detector")
        with self.connect() as db:
            db.execute(f"INSERT INTO {kind}_states VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,changed_at=excluded.changed_at,changed_by=excluded.changed_by",
                       (identifier,int(enabled),time.time(),actor))
            self.audit(db,actor,kind+("_enable" if enabled else "_disable"),identifier,previous,enabled)

    def rule_configurations(self):
        with self.connect() as db:
            return {r['id']:json.loads(r['config']) for r in db.execute('SELECT * FROM firewall_rules')}

    def configure_rule(self,identifier,values,actor,previous):
        with self.connect() as db:
            db.execute('INSERT INTO firewall_rules VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config,updated_at=excluded.updated_at',(identifier,json.dumps(values),time.time()))
            self.audit(db,actor,'rule_configure',identifier,previous,values)

    def set_ip(self, ip, kind, reason, actor, duration=None, incident_id=None, scope="all",
               trust_mode="NORMAL", source="manual", attack_category=None):
        ip=str(ipaddress.ip_address(ip))
        if kind not in ("blacklist","whitelist","temporary") or scope not in ("all","login"):
            raise ValueError("Invalid IP policy")
        if len(reason)>250:
            raise ValueError("Reason must be at most 250 characters")
        if trust_mode not in TRUST_MODES or source not in ("manual", "automatic"):
            raise ValueError("Invalid trust mode or policy source")
        expires=None
        if kind=="temporary" or (kind=="blacklist" and duration not in (None, "", 0, "0")):
            duration=int(duration)
            if not 1<=duration<=604800:
                raise ValueError("Duration must be between 1 second and 7 days")
            expires=time.time()+duration
        with self.connect() as db:
            old=db.execute('SELECT * FROM ip_policies WHERE ip=? AND kind=?',(ip,kind)).fetchone()
            db.execute("""INSERT INTO ip_policies
              (ip,kind,reason,created_at,expires_at,added_by,incident_id,scope,source,attack_category,trust_mode)
              VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip,kind) DO UPDATE SET
              reason=excluded.reason,created_at=excluded.created_at,expires_at=excluded.expires_at,
              added_by=excluded.added_by,incident_id=excluded.incident_id,scope=excluded.scope,
              source=excluded.source,attack_category=excluded.attack_category,trust_mode=excluded.trust_mode""",
              (ip,kind,reason,time.time(),expires,actor,incident_id,scope,source,attack_category,trust_mode))
            new=dict(db.execute('SELECT * FROM ip_policies WHERE ip=? AND kind=?',(ip,kind)).fetchone())
            self.audit(db,actor,"ip_"+kind,ip,dict(old) if old else None,new)

    def remove_ip(self, ip, kind, actor):
        ip=str(ipaddress.ip_address(ip))
        if kind not in ("temporary","blacklist","whitelist"):
            raise ValueError("Unknown policy type")
        with self.connect() as db:
            old=db.execute('SELECT * FROM ip_policies WHERE ip=? AND kind=?',(ip,kind)).fetchone()
            db.execute("DELETE FROM ip_policies WHERE ip=? AND kind=?",(ip,kind))
            if kind=="temporary":
                db.execute("INSERT INTO management_commands(ip,created_at) VALUES (?,?)",(ip,time.time()))
            self.audit(db,actor,"remove_"+kind,ip,dict(old) if old else None,None)

    def policies(self):
        now=time.time()
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM ip_policies WHERE expires_at IS NULL OR expires_at>? ORDER BY created_at DESC",(now,))]

    def policy(self, ip):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM ip_policies WHERE ip=? AND (expires_at IS NULL OR expires_at>?)",(ip,time.time()))]

    def commands(self, after):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT id,ip FROM management_commands WHERE id>? ORDER BY id",(after,))]

    def acknowledge(self, alert_id, actor):
        with self.connect() as db:
            row=db.execute("UPDATE security_alerts SET acknowledged=1,acknowledged_at=?,acknowledged_by=? WHERE id=?",
                           (time.time(),actor,alert_id))
            if not row.rowcount:
                raise ValueError("Alert not found")
            self.audit(db,actor,"acknowledge_alert",str(alert_id))
