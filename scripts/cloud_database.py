"""Apply and verify the cloud PostgreSQL schema without printing credentials."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from waf.management.settings import normalize_database_url

CLOUD_ENV = ROOT / ".local" / "cloud.env"
MIGRATION = ROOT / "supabase" / "migrations" / "20260911000100_nisec.sql"

REQUIRED_TABLES = {
    "shop": {"user", "item", "comment", "upload"},
    "security": {
        "security_events",
        "management_settings",
        "ip_policies",
        "security_alerts",
        "event_categories",
        "management_audit",
        "dashboard_admins",
        "firewall_rules",
    },
}


def load_cloud_env() -> None:
    if not CLOUD_ENV.exists():
        return
    for raw_line in CLOUD_ENV.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip("\"'"))


def database_url() -> str:
    load_cloud_env()
    value = os.environ.get("CLOUD_DATABASE_URL") or os.environ.get("SHOP_DATABASE_URL")
    if not value:
        raise SystemExit("Set SHOP_DATABASE_URL or run scripts/configure_cloud_env.ps1 first.")
    return normalize_database_url(value)


def connect():
    return psycopg.connect(database_url(), connect_timeout=15)


def apply_schema() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    print("Cloud schema is ready: shop + security.")


def check_schema() -> None:
    missing = []
    with connect() as conn:
        with conn.cursor() as cur:
            for schema, tables in REQUIRED_TABLES.items():
                cur.execute(
                    """
                    select table_name
                    from information_schema.tables
                    where table_schema = %s
                    """,
                    (schema,),
                )
                existing = {row[0] for row in cur.fetchall()}
                for table in sorted(tables - existing):
                    missing.append(f"{schema}.{table}")
    if missing:
        raise SystemExit("Missing cloud tables: " + ", ".join(missing))
    print("Cloud database check passed: required shop and security tables exist.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Apply the non-destructive schema migration.")
    parser.add_argument("--check", action="store_true", help="Verify required schemas and tables.")
    args = parser.parse_args()
    if not args.apply and not args.check:
        parser.error("choose --apply, --check, or both")
    if args.apply:
        apply_schema()
    if args.check:
        check_schema()


if __name__ == "__main__":
    main()
