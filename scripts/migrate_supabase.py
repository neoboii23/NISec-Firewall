"""Offline, backup-first SQLite -> local PostgreSQL migration.

No automatic deletion or connection switch: activation is a separate verified step.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
from urllib.parse import urlsplit
import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {'shop': ROOT/'database.db', 'security': ROOT/'waf/database/waf.db', 'legacy': ROOT/'lab.db'}
SECURITY_TABLES = ['security_events','management_settings','rule_states','detector_states','ip_policies',
    'management_commands','security_alerts','event_categories','management_audit','dashboard_admins',
    'admin_login_limits','firewall_rules','rate_limit_records','geo_cache']
SHOP_TABLES = ['user','item','comment','upload']


def sqlite_open(path):
    return sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)


def table_names(db):
    return [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]


def identifier(value):
    return '"'+value.replace('"','""')+'"'


def inventory():
    result = {}
    for name,path in SOURCES.items():
        if path.is_file():
            with closing(sqlite_open(path)) as db:
                result[name] = {t: db.execute('SELECT COUNT(*) FROM '+identifier(t)).fetchone()[0] for t in table_names(db)}
    return result


def offline():
    for port in (5000,8080,9000):
        with socket.socket() as sock:
            sock.settimeout(.3)
            if sock.connect_ex(('127.0.0.1',port)) == 0:
                raise RuntimeError(f'Stop all three application services first; port {port} is listening.')


def normalize(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return {'hex': value.hex()}
    return value


def digest(rows):
    # SQLite REAL-affinity values and PostgreSQL doubles can represent integral
    # numbers with different Python types; canonicalize exact integral floats.
    def canonical(value):
        value=normalize(value)
        return int(value) if isinstance(value,float) and value.is_integer() else value
    values = [json.dumps([canonical(v) for v in row],separators=(',',':'),ensure_ascii=False) for row in rows]
    return hashlib.sha256('\n'.join(sorted(values)).encode()).hexdigest()


def shop_value(column,value):
    if value is None: return None
    if column == 'is_admin': return bool(value)
    if column in ('created_at','uploaded_at'):
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    return value


def import_table(pg, source, schema, table):
    columns = [r[1] for r in source.execute('PRAGMA table_info('+identifier(table)+')')]
    rows = source.execute('SELECT '+','.join(map(identifier,columns))+' FROM '+identifier(table)).fetchall()
    if schema == 'shop': rows = [tuple(shop_value(k,v) for k,v in zip(columns,row)) for row in rows]
    target = sql.Identifier(schema,table)
    if pg.execute(sql.SQL('SELECT COUNT(*) FROM {}').format(target)).fetchone()[0]:
        raise RuntimeError(f'Target {schema}.{table} is not empty; refusing to merge or overwrite.')
    names = sql.SQL(',').join(map(sql.Identifier,columns))
    if rows:
        with pg.cursor() as cur:
            cur.executemany(sql.SQL('INSERT INTO {} ({}) VALUES ({})').format(target,names,sql.SQL(',').join(sql.Placeholder() for _ in columns)),rows)
    # Binary results retain the full stored double precision regardless of the
    # database's extra_float_digits display setting.
    imported = pg.execute(sql.SQL('SELECT {} FROM {}').format(names,target),binary=True).fetchall()
    if digest(rows) != digest(imported):
        differences=[]
        if len(rows)==len(imported)==1:
            differences=[(name,type(a).__name__,type(b).__name__) for name,a,b in zip(columns,rows[0],imported[0]) if normalize(a)!=normalize(b)]
        raise RuntimeError(f'Content verification failed for {schema}.{table}; differing column/types: {differences}')
    if 'id' in columns:
        sequence = pg.execute('SELECT pg_get_serial_sequence(%s,%s)',(schema+'.'+identifier(table),'id')).fetchone()[0]
        if sequence:
            maximum = pg.execute(sql.SQL('SELECT COALESCE(MAX(id),0) FROM {}').format(target)).fetchone()[0]
            pg.execute('SELECT setval(%s,%s,%s)',(sequence,max(maximum,1),bool(maximum)))
    return {'rows':len(rows),'sha256':digest(rows)}


def create_role(pg, role, schema):
    # Refuse to reuse any potentially privileged pre-existing role.
    if pg.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone():
        raise RuntimeError(f'Role {role} already exists; review previous migration before retrying.')
    password = secrets.token_urlsafe(36)
    pg.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS').format(sql.Identifier(role),sql.Literal(password)))
    pg.execute(sql.SQL('ALTER ROLE {} SET search_path TO {},pg_catalog').format(sql.Identifier(role),sql.Identifier(schema)))
    pg.execute(sql.SQL('ALTER ROLE {} SET statement_timeout TO {}').format(sql.Identifier(role),sql.Literal('5s')))
    pg.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(role)))
    pg.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(role)))
    pg.execute(sql.SQL('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(role)))
    pg.execute(sql.SQL('REVOKE CREATE ON SCHEMA public FROM {}').format(sql.Identifier(role)))
    return password


def migrate():
    offline()
    dsn = os.environ.get('NISEC_MIGRATION_URL') or json.loads((ROOT/'.local/migration-database.json').read_text())['url']
    parsed=urlsplit(dsn)
    if parsed.hostname != '127.0.0.1' or parsed.port != 54322 or parsed.path != '/postgres':
        raise RuntimeError('Migration destination must be this local Supabase database on 127.0.0.1:54322/postgres.')
    run = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    backup_dir = ROOT/'backups'/('supabase-'+run)
    backup_dir.mkdir(parents=True)
    report = {'run':run,'backup_directory':str(backup_dir),'tables':{},'status':'verified import; activation pending'}
    snapshots = {}
    for name,path in SOURCES.items():
        if not path.exists(): continue
        snapshot = backup_dir/(name+'.db')
        with closing(sqlite_open(path)) as source, closing(sqlite3.connect(snapshot)) as target:
            if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Source integrity check failed: '+name)
            source.backup(target)
        snapshots[name] = snapshot
    if not {'shop','security'} <= snapshots.keys(): raise RuntimeError('Both application source databases are required.')
    with psycopg.connect(dsn) as pg:
        # A clean local stack may have applied the schema automatically on first start.
        if not pg.execute("SELECT to_regclass('security.schema_version')").fetchone()[0]:
            pg.execute((ROOT/'supabase/migrations/20260911000100_nisec.sql').read_text())
        for schema,tables in [('shop',SHOP_TABLES),('security',SECURITY_TABLES)]:
            with closing(sqlite_open(snapshots[schema])) as source:
                present=table_names(source)
                if set(present)-set(tables): raise RuntimeError('Unexpected source tables; review before migration: '+schema)
                for table in tables:
                    if table in present:
                        report['tables'][schema+'.'+table]=import_table(pg,source,schema,table)
        # Preserve obsolete application's data in a read-only-to-apps archive schema.
        if 'legacy' in snapshots:
            pg.execute('CREATE SCHEMA legacy_archive')
            with closing(sqlite_open(snapshots['legacy'])) as source:
                for table in table_names(source):
                    columns=source.execute('PRAGMA table_info('+identifier(table)+')').fetchall()
                    definitions=[]
                    for _,name,type_name,*_ in columns:
                        typ='bigint' if 'INT' in type_name.upper() else 'double precision' if any(t in type_name.upper() for t in ('REAL','FLOAT','DOUBLE')) else 'bytea' if 'BLOB' in type_name.upper() else 'text'
                        definitions.append(sql.SQL('{} {}').format(sql.Identifier(name),sql.SQL(typ)))
                    pg.execute(sql.SQL('CREATE TABLE {} ({})').format(sql.Identifier('legacy_archive',table),sql.SQL(',').join(definitions)))
                    report['tables']['legacy_archive.'+table]=import_table(pg,source,'legacy_archive',table)
            pg.execute('REVOKE ALL ON SCHEMA legacy_archive FROM PUBLIC,anon,authenticated')
        credentials={}
        for service,schema in [('shop','shop'),('security','security')]:
            role='nisec_'+service
            password=create_role(pg,role,schema)
            credentials[service]={'url':f'postgresql+psycopg://{role}:{password}@127.0.0.1:54322/postgres'}
        # Shared secrets are imported unchanged so dashboard accounts/sessions survive.
        for key in ('management_token','dashboard_secret'):
            if not pg.execute('SELECT 1 FROM security.management_settings WHERE key=%s',(key,)).fetchone():
                raise RuntimeError('Source security settings are incomplete.')
    pending=ROOT/'.local'/'pending'
    pending.mkdir(parents=True,exist_ok=True)
    for service,value in credentials.items():
        (pending/(service+'-database.json')).write_text(json.dumps(value),encoding='utf-8')
    (backup_dir/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (pending/'migration-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',action='store_true')
    parser.add_argument('--migrate',action='store_true')
    args=parser.parse_args()
    if args.inventory: print(json.dumps(inventory(),indent=2))
    elif args.migrate: migrate()
    else: parser.error('Choose --inventory or --migrate')
