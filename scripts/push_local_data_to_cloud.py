"""Copy current local Supabase data into a prepared Supabase Cloud database."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import psycopg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.cloud_database import apply_schema, database_url
from waf.management.settings import normalize_psycopg_url

LOCAL_ADMIN_CONFIG = ROOT / ".local" / "migration-database.json"

TABLES = [
    ("shop", "user"),
    ("shop", "item"),
    ("shop", "comment"),
    ("shop", "upload"),
    ("security", "management_settings"),
    ("security", "rule_states"),
    ("security", "detector_states"),
    ("security", "ip_policies"),
    ("security", "management_commands"),
    ("security", "security_events"),
    ("security", "security_alerts"),
    ("security", "event_categories"),
    ("security", "management_audit"),
    ("security", "dashboard_admins"),
    ("security", "admin_login_limits"),
    ("security", "firewall_rules"),
    ("security", "rate_limit_records"),
    ("security", "geo_cache"),
]

IDENTITY_TABLES = {
    ("shop", "user"),
    ("shop", "item"),
    ("shop", "comment"),
    ("shop", "upload"),
    ("security", "management_commands"),
    ("security", "security_events"),
    ("security", "security_alerts"),
    ("security", "management_audit"),
    ("security", "rate_limit_records"),
}


def quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def qualified(schema: str, table: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(table)}"


def table_literal(schema: str, table: str) -> str:
    table_name = f'{schema}."{table}"' if table == "user" else f"{schema}.{table}"
    return table_name.replace("'", "''")


def source_url() -> str:
    if not LOCAL_ADMIN_CONFIG.exists():
        raise SystemExit("Local source database config is missing: .local/migration-database.json")
    value = normalize_psycopg_url(json.loads(LOCAL_ADMIN_CONFIG.read_text(encoding="utf-8"))["url"])
    parsed = urlsplit(value)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Source database must be the local Supabase database.")
    return value


def target_url() -> str:
    value = database_url()
    parsed = urlsplit(value)
    if parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Target database must be Supabase Cloud, not the local database.")
    return value


def columns(conn, schema: str, table: str) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select column_name
            from information_schema.columns
            where table_schema = %s and table_name = %s
            order by ordinal_position
            """,
            (schema, table),
        )
        names = [row[0] for row in cur.fetchall()]
    if not names:
        raise SystemExit(f"Missing source table: {schema}.{table}")
    return names


def count_rows(conn, schema: str, table: str) -> int:
    with conn.cursor() as cur:
        cur.execute(f"select count(*) from {qualified(schema, table)}")
        return int(cur.fetchone()[0])


def ensure_empty_target(conn) -> None:
    non_empty = []
    for schema, table in TABLES:
        count = count_rows(conn, schema, table)
        if count:
            non_empty.append(f"{schema}.{table}={count}")
    if non_empty:
        raise SystemExit(
            "Cloud target is not empty. Refusing to overwrite existing data: "
            + ", ".join(non_empty)
        )


def reset_sequence(conn, schema: str, table: str) -> None:
    if (schema, table) not in IDENTITY_TABLES:
        return
    with conn.cursor() as cur:
        cur.execute(
            f"""
            select setval(
                pg_get_serial_sequence('{table_literal(schema, table)}', 'id'),
                coalesce((select max(id) from {qualified(schema, table)}), 1),
                (select max(id) is not null from {qualified(schema, table)})
            )
            """
        )


def copy_table(source, target, schema: str, table: str) -> int:
    names = columns(source, schema, table)
    column_sql = ", ".join(quote_ident(name) for name in names)
    placeholders = ", ".join(["%s"] * len(names))
    with source.cursor() as source_cur:
        source_cur.execute(f"select {column_sql} from {qualified(schema, table)} order by 1")
        rows = source_cur.fetchall()
    if rows:
        with target.cursor() as target_cur:
            target_cur.executemany(
                f"insert into {qualified(schema, table)} ({column_sql}) overriding system value values ({placeholders})",
                rows,
            )
    reset_sequence(target, schema, table)
    return len(rows)


def push_data() -> None:
    # Validate both destinations before making any schema changes.
    source_dsn = source_url()
    target_dsn = target_url()
    apply_schema()
    copied = {}
    with psycopg.connect(source_dsn, connect_timeout=15) as source:
        with psycopg.connect(target_dsn, connect_timeout=15) as target:
            ensure_empty_target(target)
            for schema, table in TABLES:
                copied[f"{schema}.{table}"] = copy_table(source, target, schema, table)
            target.commit()
    for name, count in copied.items():
        print(f"{name}: {count}")
    print("Local Supabase data copied to Supabase Cloud.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes", action="store_true", help="Confirm copying into an empty cloud target.")
    args = parser.parse_args()
    if not args.yes:
        parser.error("add --yes after confirming the cloud target is correct")
    push_data()


if __name__ == "__main__":
    main()
