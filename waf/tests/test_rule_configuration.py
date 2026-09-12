from unittest.mock import patch
from waf_app_loader import create_app

def test_rule_actions_literals_and_audit(tmp_path):
    app=create_app({'DATABASE_PATH':tmp_path/'db','LOG_DIR':tmp_path/'logs','RATE_LIMIT_ENABLED':False})
    store=app.extensions['security_events'].management
    client=app.test_client()
    rule='WAF-002-XSS-002'
    with patch('app.forward',return_value=app.response_class('ok')):
        store.configure_rule(rule,{'score':8,'action':'LOG','severity':'LOW'},'admin',{})
        assert client.get('/search?q=javascript:test').status_code==200
        store.configure_rule(rule,{'score':8,'action':'ALERT','severity':'LOW'},'admin',{})
        assert client.get('/search?q=javascript:test').status_code==200
        with store.connect() as db:assert db.execute('SELECT COUNT(*) FROM security_alerts').fetchone()[0]>=1
        store.configure_rule(rule,{'score':8,'action':'TEMPORARY_BLOCK','severity':'HIGH','literal_patterns':['synthetic-marker']},'admin',{})
        assert client.get('/search?q=synthetic-marker').status_code==403
        assert client.get('/').status_code==429
        with store.connect() as db:assert db.execute("SELECT new_value FROM management_audit WHERE action='rule_configure' ORDER BY id DESC").fetchone()[0]
