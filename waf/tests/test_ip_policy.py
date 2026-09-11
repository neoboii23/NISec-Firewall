from unittest.mock import patch
import pytest
from app import create_app

@pytest.fixture
def policy_app(tmp_path):
    return create_app({'DATABASE_PATH':tmp_path/'waf.db','LOG_DIR':tmp_path/'logs','RATE_LIMIT_ENABLED':False})

def test_trust_modes_and_no_backend_arrivals(policy_app):
    store=policy_app.extensions['security_events'].management
    client=policy_app.test_client()
    with patch('app.forward',return_value=policy_app.response_class('backend')) as forward:
        store.set_ip('127.0.0.1','blacklist','test','admin')
        assert client.get('/').status_code==403
        forward.assert_not_called()
        store.set_ip('127.0.0.1','whitelist','normal','admin')
        assert client.get('/').status_code==403
        store.set_ip('127.0.0.1','whitelist','trusted','admin',trust_mode='BLACKLIST_BYPASS')
        assert client.get('/').status_code==200
        forward.reset_mock()
        assert client.get('/search',query_string={'q':"' OR 1=1--"}).status_code==403
        forward.assert_not_called()
        store.set_ip('127.0.0.1','whitelist','explicit','admin',trust_mode='FULL_BYPASS')
        assert client.get('/search',query_string={'q':"' OR 1=1--"}).status_code==200
        forward.reset_mock()
        assert client.post('/upload',data=b'x'*(2*1024*1024+1)).status_code==413
        forward.assert_not_called()

def test_policy_expiry_and_ipv6(policy_app):
    store=policy_app.extensions['security_events'].management
    store.set_ip('2001:db8::1','blacklist','test','admin',duration=30)
    assert store.policy('2001:db8::1')[0]['source']=='manual'
    with store.connect() as db:db.execute('UPDATE ip_policies SET expires_at=1')
    assert store.policy('2001:db8::1')==[]
    with pytest.raises(ValueError):store.set_ip('not-an-ip','blacklist','test','admin')
    with pytest.raises(ValueError):store.set_ip('127.0.0.1','whitelist','test','admin',trust_mode='unknown')
