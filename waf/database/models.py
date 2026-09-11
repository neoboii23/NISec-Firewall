"""Additive migration keeps Phase 3 history and adds dashboard/evidence fields."""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from engine.decision import CATEGORIES
from engine.privacy import safe_query
from management.store import ManagementStore

def event_payload(context, result, status):
    if not result.timestamp:
        result.timestamp = datetime.now(timezone.utc).isoformat()
    if not result.incident_id:
        result.incident_id = "WAF-" + uuid.uuid4().hex.upper()
    return {
        "timestamp": result.timestamp, "incident_id": result.incident_id,
        "source_ip": context.client_ip, "method": context.method, "path": context.path,
        "query": safe_query(context.query), "user_agent": "[omitted]",
        "attack_category": result.category, "category_code": result.category_code,
        "category_name": result.category_name,
        "categories": [{"category": c, "category_code": CATEGORIES.get(c, ("", c))[0],
                        "category_name": CATEGORIES.get(c, ("", c))[1]}
                       for c in dict.fromkeys(m.category for m in result.matches)],
        "severity": result.severity, "threat_score": result.score,
        "matched_rules": result.rule_ids, "decision": result.decision, "response_status": status,
        "evidence": [dict(m.evidence, rule_id=m.rule_id) for m in result.matches],
        "metadata": result.metadata,
    }

class SecurityEventStore:
    def __init__(self, database_path):
        self.postgres = str(database_path).startswith(('postgresql://', 'postgresql+psycopg://'))
        if self.postgres:
            self.management = ManagementStore(database_path)
            self.database_path = None
            return
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY, incident_id TEXT, timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
                query TEXT, user_agent TEXT, attack_category TEXT, severity TEXT,
                threat_score INTEGER NOT NULL, matched_rules TEXT, decision TEXT NOT NULL,
                response_status INTEGER NOT NULL)""")
            columns = {r[1] for r in connection.execute("PRAGMA table_info(security_events)")}
            for name in ("category_code", "category_name", "categories", "evidence", "metadata"):
                if name not in columns:
                    connection.execute(f"ALTER TABLE security_events ADD COLUMN {name} TEXT")
            for name in ("timestamp", "source_ip", "attack_category", "decision", "severity", "category_code"):
                connection.execute(f"CREATE INDEX IF NOT EXISTS ix_event_{name} ON security_events({name})")
            # Preserve existing Phase 3 events while aligning their dashboard labels.
            for old, new in (("PATH_TRAVERSAL", "DIRECTORY_TRAVERSAL"), ("MALICIOUS_UPLOAD", "MALICIOUS_FILE_UPLOAD")):
                connection.execute("UPDATE security_events SET attack_category=? WHERE attack_category=?", (new, old))
            for category, (code, name) in CATEGORIES.items():
                connection.execute("UPDATE security_events SET category_code=?, category_name=?, categories=? WHERE attack_category=? AND category_code IS NULL",
                    (code, name, json.dumps([{"category": category, "category_code": code, "category_name": name}]), category))
        self.management = ManagementStore(self.database_path)

    @contextmanager
    def _connect(self):
        if self.postgres:
            with self.management.connect() as connection:
                yield connection
            return
        connection = sqlite3.connect(self.database_path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def record(self, context, result, response_status):
        event = event_payload(context, result, response_status)
        row = {k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v for k, v in event.items()}
        with self._connect() as connection:
            suffix = ' RETURNING id' if self.postgres else ''
            cursor = connection.execute(f"INSERT INTO security_events ({','.join(row)}) VALUES ({','.join('?' for _ in row)})" + suffix, tuple(row.values()))
            identifier = cursor.fetchone()[0] if self.postgres else cursor.lastrowid
            self.management.capture_event(connection, identifier, event)

    def counts(self):
        with self._connect() as connection:
            rows = connection.execute("SELECT decision, COUNT(*) FROM security_events GROUP BY decision").fetchall()
        values = dict(rows)
        return {"total": sum(values.values()), "allowed": values.get("ALLOW", 0),
                "blocked": values.get("BLOCK", 0), "rate_limited": values.get("RATE_LIMIT", 0)}

    def attack_counts(self):
        # Includes every matched category, not just the highest-scoring category.
        counts = {category: 0 for category in CATEGORIES}
        with self._connect() as connection:
            for (encoded,) in connection.execute("SELECT categories FROM security_events WHERE categories IS NOT NULL"):
                for item in json.loads(encoded):
                    category = item["category"]
                    if category in counts:
                        counts[category] += 1
        return counts
