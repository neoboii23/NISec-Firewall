from unittest.mock import patch
from waf_app_loader import create_app
from management.runtime import RuntimePolicy

def test_live_rate_threshold_and_bypass(tmp_path):
    app=create_app({'DATABASE_PATH':tmp_path/'db','LOG_DIR':tmp_path/'logs','RATE_LIMIT_ENABLED':True})
    store=app.extensions['security_events'].management
    config=RuntimePolicy(store)
    config.update({'rate_requests':2,'rate_window':10},'admin')
    client=app.test_client()
    with patch('app.forward',return_value=app.response_class('ok')):
        assert client.get('/').status_code==200
        assert client.get('/').status_code==200
        response=client.get('/')
        assert response.status_code==429 and 1<=int(response.headers['Retry-After'])<=10
        store.set_ip('127.0.0.1','whitelist','test','admin',trust_mode='RATE_LIMIT_BYPASS')
        assert client.get('/').status_code==200
        assert client.get('/search',query_string={'q':"' OR 1=1--"}).status_code==403

def test_repeated_attack_block(tmp_path):
    app=create_app({'DATABASE_PATH':tmp_path/'db','LOG_DIR':tmp_path/'logs','RATE_LIMIT_ENABLED':False})
    store=app.extensions['security_events'].management
    RuntimePolicy(store).update({'auto_enabled':True,'auto_threshold':2},'admin')
    client=app.test_client()
    assert client.get('/search',query_string={'q':"' OR 1=1--"}).status_code==403
    assert not store.policy('127.0.0.1')
    assert client.get('/search',query_string={'q':"' OR 1=1--"}).status_code==403
    assert store.policy('127.0.0.1')[0]['attack_category']=='SQL_INJECTION'
    assert client.get('/').status_code==429
