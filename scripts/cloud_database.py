"""Apply and verify the cloud PostgreSQL schema without printing credentials."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import psycopg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from waf.management.settings import normalize_psycopg_url

CLOUD_ENV = ROOT / ".local" / "cloud.env"
MIGRATION = ROOT / "supabase" / "migrations" / "20260911000100_nisec.sql"

REQUIRED_TABLES = {
    "shop": {"user", "item", "comment", "upload"},
    "security": {
        "schema_version",
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
    value = normalize_psycopg_url(value)
    try:
        psycopg.conninfo.conninfo_to_dict(value)
    except psycopg.ProgrammingError:
        # libpq parse errors can include the complete URL and its password.
        raise SystemExit(
            'Invalid cloud database URL. Check the URL format and '
            'percent-encode reserved password characters.'
        ) from None
    return value


def connect():
    url = database_url()
    try:
        return psycopg.connect(url, connect_timeout=15, prepare_threshold=None)
    except psycopg.OperationalError as exc:
        host = urlsplit(url).hostname or "unknown"
        raw_message = str(exc).lower()
        reason = ""
        if "password authentication failed" in raw_message:
            reason = (
                "\nReason: password authentication failed. Recheck the database password "
                "you inserted into the connection string."
            )
        elif "tenant or user not found" in raw_message or "invalid username" in raw_message:
            reason = (
                "\nReason: pooler username/project reference was not accepted. For Supabase "
                "pooler URLs, the user usually looks like postgres.<project-ref>."
            )
        elif "timeout" in raw_message or "timed out" in raw_message:
            reason = "\nReason: the connection timed out before PostgreSQL accepted it."
        elif "ssl" in raw_message:
            reason = "\nReason: SSL negotiation failed. Use the full Supabase URI copied from the dashboard."
        hint = ""
        if host.startswith("db.") and host.endswith(".supabase.co"):
            hint = (
                "\nThis looks like Supabase's direct database host. If it fails on your network, "
                "copy the Supavisor pooler connection string from Supabase Dashboard -> Connect "
                "and rerun scripts/configure_cloud_env.ps1."
            )
        raise SystemExit(f"Could not connect to cloud database host {host}.{reason}{hint}") from exc


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
