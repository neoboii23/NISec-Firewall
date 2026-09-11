"""Real PostgreSQL regression tests, isolated in disposable schemas.

Skipped on machines without the local Supabase administrator configuration.
"""
import json
import re
import uuid
from pathlib import Path
import pytest
import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


@pytest.fixture
def pg_dashboard():
    root=Path(__file__).resolve().parents[2]
    settings=root/'.local/migration-database.json'
    if not settings.exists(): pytest.skip('Local Supabase not configured')
    dsn=json.loads(settings.read_text())['url']
    security='test_security_'+uuid.uuid4().hex
    shop='test_shop_'+uuid.uuid4().hex
    migration=(root/'supabase/migrations/20260911000100_nisec.sql').read_text()
    migration=re.sub(r'\bsecurity\b',security,migration)
    migration=re.sub(r'\bshop\b',shop,migration)
    try:
        with psycopg.connect(dsn) as pg: pg.execute(migration)
        url=make_url(dsn).set(drivername='postgresql+psycopg').update_query_dict({'options':'-csearch_path='+security}).render_as_string(hide_password=False)
        from admin_dashboard.app import create_app
        from waf.management.store import ManagementStore
        with psycopg.connect(dsn) as pg:
            for key in ('dashboard_secret','management_token'):
                pg.execute(sql.SQL('INSERT INTO {}.management_settings VALUES (%s,%s)').format(sql.Identifier(security)),(key,uuid.uuid4().hex))
        app=create_app({'TESTING':True,'DATABASE_URL':url,'ADMIN_PASSWORD':'Postgres-test-password!','WAF_URL':'http://127.0.0.1:1'})
        store=app.extensions['management']
        from datetime import datetime,timezone
        event=dict(incident_id='WAF-PG-TEST',timestamp=datetime.now(timezone.utc).isoformat(),source_ip='192.0.2.10',method='GET',path='/search',
            attack_category='SQL_INJECTION',category_code='WAF-001',category_name='SQL Injection',severity='HIGH',threat_score=8,
            decision='BLOCK',response_status=403,matched_rules=['WAF-001-SQLI-001'],categories=[{'category':'SQL_INJECTION'}],evidence=[],metadata={})
        values={k:json.dumps(v) if isinstance(v,(list,dict)) else v for k,v in event.items()}
        with store.connect() as db:
            identifier=db.execute('INSERT INTO security_events('+','.join(values)+') VALUES ('+','.join('?' for _ in values)+') RETURNING id',tuple(values.values())).fetchone()[0]
            ManagementStore.capture_event(db,identifier,event)
        client=app.test_client()
        client.get('/login')
        with client.session_transaction() as session: csrf=session['csrf']
        assert client.post('/login',data={'username':'admin','password':'Postgres-test-password!','csrf':csrf}).status_code==302
        with client.session_transaction() as session: csrf=session['csrf']
        yield app,client,csrf
    finally:
        # Names originate solely from fresh UUIDs above, never caller-provided SQL.
        with psycopg.connect(dsn) as pg:
            for schema in (security,shop):
                pg.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))


def test_postgres_dashboard_queries_and_management(pg_dashboard):
    app,client,csrf=pg_dashboard
    assert client.get('/api/dashboard/summary').json['blocked_requests']==1
    assert client.get('/api/events/recent?rule=WAF-001-SQLI-001').json['total']==1
    assert client.get('/api/events/recent?path=search').json['total']==1
    assert client.get('/api/attacks/stats?period=1h').json['categories'][0]['count']==1
    assert sum(r['blocked'] for r in client.get('/api/charts/attacks').json)==1
    assert client.get('/api/attack-map').json['sources'][0]['attempts']==1
    assert client.get('/logs/WAF-PG-TEST').status_code==200
    assert len(client.get('/api/events/export?format=json').json)==1
    assert client.get('/api/events/export?format=csv').status_code==200
    headers={'X-CSRF-Token':csrf}
    assert client.put('/api/rate-limits',json={'rate_requests':123},headers=headers).status_code==200
    assert client.post('/api/ip',json={'operation':'add','kind':'blacklist','ip':'192.0.2.10','reason':'test'},headers=headers).status_code==200
    assert client.post('/api/ip',json={'operation':'remove','kind':'blacklist','ip':'192.0.2.10'},headers=headers).status_code==200
    assert client.put('/api/rules/WAF-001-SQLI-001/configuration',json={'score':9,'action':'ALERT'},headers=headers).status_code==200
    assert client.put('/api/rules/WAF-001-SQLI-001',json={'enabled':False},headers=headers).status_code==200
    assert client.post('/api/alerts/1/acknowledge',headers=headers).status_code==200
    assert client.get('/api/audit').json['items']
    for path in ('/dashboard','/logs','/rules','/rate-limits','/ip-management','/settings','/system'):
        assert client.get(path).status_code==200


def test_postgres_parameter_binding_and_rollback(pg_dashboard):
    app,client,csrf=pg_dashboard
    store=app.extensions['management']
    with store.connect() as db:
        row=db.execute("SELECT '?' AS literal, ? AS value",("O'Reilly % _ ?",)).fetchone()
        assert row[0]=='?' and dict(row)['value']=="O'Reilly % _ ?"
    with pytest.raises(RuntimeError):
        with store.connect() as db:
            db.execute("INSERT INTO management_settings VALUES ('rollback-test','x')")
            raise RuntimeError('roll back')
    with store.connect() as db:
        assert db.execute("SELECT 1 FROM management_settings WHERE key='rollback-test'").fetchone() is None
