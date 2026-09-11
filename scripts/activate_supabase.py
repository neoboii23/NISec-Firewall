"""Verify migrated records and isolated roles, then activate local PostgreSQL.

Retirement archives exact SQLite files; it never recursively deletes anything.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import shutil
import psycopg
from psycopg import sql
from migrate_supabase import ROOT, SOURCES, SHOP_TABLES, SECURITY_TABLES, offline, sqlite_open, identifier, digest, shop_value


def credentials(service, pending=False):
    folder=ROOT/'.local'
    if pending: folder=folder/'pending'
    return json.loads((folder/(service+'-database.json')).read_text())['url'].replace('postgresql+psycopg://','postgresql://',1)


def verify_roles(pending):
    with psycopg.connect(credentials('shop',pending)) as pg:
        assert pg.execute('SELECT COUNT(*) FROM shop.item').fetchone()[0] >= 6
        try: pg.execute('SELECT password_hash FROM security.dashboard_admins')
        except psycopg.errors.InsufficientPrivilege: pg.rollback()
        else: raise RuntimeError('Shop account can read security data!')
    with psycopg.connect(credentials('security',pending)) as pg:
        assert pg.execute('SELECT version FROM schema_version').fetchone()[0] == 1
        try: pg.execute('SELECT password FROM shop."user"')
        except psycopg.errors.InsufficientPrivilege: pg.rollback()
        else: raise RuntimeError('Security account can read shop data!')


def verify_originals(report):
    """Compare original snapshots with source files and migrated rows by their PKs.

Activation happens offline before PostgreSQL application writes. Retirement uses
the already saved verification and checks source files against backups again.
"""
    for schema,path in SOURCES.items():
        if not path.exists(): continue
        backup=Path(report['backup_directory'])/(schema+'.db')
        with closing(sqlite_open(path)) as current, closing(sqlite_open(backup)) as saved:
            tables=[r[0] for r in current.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for table in tables:
                query='SELECT * FROM '+identifier(table)
                if digest(current.execute(query).fetchall()) != digest(saved.execute(query).fetchall()):
                    raise RuntimeError('SQLite source changed after import: '+str(path))


def activate():
    offline()
    pending=ROOT/'.local/pending'
    report=json.loads((pending/'migration-report.json').read_text())
    verify_originals(report)
    verify_roles(True)
    admin=json.loads((ROOT/'.local/migration-database.json').read_text())['url']
    with psycopg.connect(admin) as pg:
        for target,entry in report['tables'].items():
            schema,table=target.split('.',1)
            source_schema='legacy' if schema=='legacy_archive' else schema
            with closing(sqlite_open(Path(report['backup_directory'])/(source_schema+'.db'))) as source:
                columns=[r[1] for r in source.execute('PRAGMA table_info('+identifier(table)+')')]
            names=sql.SQL(',').join(map(sql.Identifier,columns))
            rows=pg.execute(sql.SQL('SELECT {} FROM {}').format(names,sql.Identifier(schema,table)),binary=True).fetchall()
            if len(rows)!=entry['rows'] or digest(rows)!=entry['sha256']:
                raise RuntimeError('Migrated content changed before activation: '+target)
    for service in ('shop','security'):
        destination=ROOT/'.local'/(service+'-database.json')
        if destination.exists(): raise RuntimeError('Already activated; refusing to overwrite connection settings.')
    for service in ('shop','security'):
        shutil.copy2(pending/(service+'-database.json'),ROOT/'.local'/(service+'-database.json'))
    report['status']='activated; live service verification required before SQLite retirement'
    (ROOT/'.local/migration-report.json').write_text(json.dumps(report,indent=2))
    print('Activated local PostgreSQL for shop and security services. All copied rows and role isolation verified. SQLite originals retained.')


def retire():
    offline()
    report=json.loads((ROOT/'.local/migration-report.json').read_text())
    proof=json.loads((ROOT/'.local/live-verification.json').read_text())
    if proof.get('run')!=report['run'] or proof.get('success') is not True:
        raise RuntimeError('Successful post-migration live verification is required.')
    verify_roles(False)
    verify_originals(report)
    archive=Path(report['backup_directory']).resolve()/'retired-originals'
    if archive.parent.parent != (ROOT/'backups').resolve():
        raise RuntimeError('Backup path is outside the project backup directory.')
    archive.mkdir(exist_ok=True)
    moved=[]
    for name,path in SOURCES.items():
        for suffix in ('','-wal','-shm'):
            source=Path(str(path)+suffix).resolve()
            if not source.is_relative_to(ROOT.resolve()): raise RuntimeError('Invalid source path')
            destination=archive/(name+'.db'+suffix)
            if destination.exists(): raise RuntimeError('Archive file already exists; refusing overwrite.')
            if source.exists():
                source.rename(destination)
                moved.append(str(source))
    report['status']='verified and activated; SQLite originals archived'
    report['retired_files']=moved
    (ROOT/'.local/migration-report.json').write_text(json.dumps(report,indent=2))
    (archive.parent/'report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({'removed_from_active_paths':moved,'recoverable_archive':str(archive)},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate',action='store_true')
    parser.add_argument('--retire-sqlite',action='store_true')
    args=parser.parse_args()
    if args.activate: activate()
    elif args.retire_sqlite: retire()
    else: parser.error('Choose --activate or --retire-sqlite')
