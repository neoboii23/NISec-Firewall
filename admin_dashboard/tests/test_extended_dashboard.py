def test_live_traffic_is_protected_and_bounded(admin_app,login,seeded):
    assert admin_app.test_client().get('/live-traffic').status_code==302
    client,_=login
    page=client.get('/live-traffic?method=GET&action=BLOCK')
    assert page.status_code==200 and b'data-page="live"' in page.data
    data=client.get('/api/events/recent?method=GET&action=BLOCK').json
    assert data['total']==31 and len(data['items'])==25

def test_analytics_ranges(login,seeded):
    client,_=login
    assert client.get('/analytics').status_code==200
    for period in ('1h','24h','7d','30d'):
        assert client.get('/api/attacks/stats?period='+period).json['categories'][0]['count']==31
        assert len(client.get('/api/charts/attacks?period='+period).json)==60
    query='period=custom&start=2000-01-01&end=2000-01-02'
    assert client.get('/api/attacks/stats?'+query).json['categories'][0]['count']==0
    assert client.get('/api/charts/attacks?period=custom&start=bad').status_code==400
    assert client.get('/api/attacks/stats?period=unknown').status_code==400

def test_private_map_never_fabricates_locations(login,seeded):
    client,_=login
    assert client.get('/attack-map').status_code==200
    rows=client.get('/api/attack-map').json['sources']
    assert rows[0]['location']=='Internal / Lab Network'
    assert rows[0]['latitude'] is None and rows[0]['longitude'] is None
    from admin_dashboard.services.geo_service import GeoService
    geo=GeoService(seeded,None)
    assert geo.locate('8.8.8.8')['location']=='GeoIP unavailable'
    assert geo.locate('127.0.0.1')['country'] is None

def test_rule_configuration_validation_and_audit(login):
    import json
    client,csrf=login
    url='/api/rules/WAF-002-XSS-002/configuration'
    headers={'X-CSRF-Token':csrf}
    assert client.put(url,json={'score':9}).status_code==403
    assert client.put(url,json={'patterns':['(a+)+']},headers=headers).status_code==400
    assert client.put(url,json={'score':101},headers=headers).status_code==400
    assert client.put(url,json={'score':9,'action':'ALERT','literal_patterns':['lab-marker']},headers=headers).status_code==200
    audit=client.get('/api/audit').json['items'][0]
    assert json.loads(audit['old_value'])['score']==8
    assert json.loads(audit['new_value'])['score']==9 and audit['actor']=='admin'

def test_security_logs_rule_filter_and_detail(login,seeded):
    client,_=login
    assert client.get('/logs?rule=WAF-001-SQLI-001').status_code==200
    assert client.get('/api/events/recent?rule=WAF-001-SQLI-001').json['total']==31
    assert client.get('/api/events/recent?rule=missing').json['total']==0
    assert len(client.get('/api/events/export?format=json&rule=WAF-001-SQLI-001').json)==31
    assert b'Current IP policy' in client.get('/logs/WAF-TEST-060').data

def test_viewer_read_only_and_fixed_session(admin_app):
    admin_app.extensions['auth'].provision('reviewer','Viewer-test-password!','VIEWER')
    client=admin_app.test_client()
    client.get('/login')
    with client.session_transaction() as sess:token=sess['csrf']
    assert client.post('/login',data={'username':'reviewer','password':'Viewer-test-password!','csrf':token}).status_code==302
    with client.session_transaction() as sess:token=sess['csrf']
    assert client.get('/analytics').status_code==200
    assert client.get('/settings').status_code==200
    assert 'Set-Cookie' not in client.get('/api/dashboard/summary').headers
    for method,path,data in [('PUT','/api/rules/WAF-002-XSS-002',{'enabled':False}),('PUT','/api/rate-limits',{'rate_enabled':False}),
                             ('POST','/api/ip',{'operation':'add','kind':'blacklist','ip':'127.0.0.1'}),('POST','/api/alerts/1/acknowledge',{})]:
        assert client.open(path,method=method,json=data,headers={'X-CSRF-Token':token}).status_code==403
    assert client.post('/logout',data={'csrf':token}).status_code==302

def test_expired_session_is_rejected(admin_app):
    import time
    from unittest.mock import patch
    client=admin_app.test_client()
    with patch('time.time',return_value=time.time()-1900):
        client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        client.post('/login',data={'username':'admin','password':'Dashboard-test-password!','csrf':token})
    assert client.get('/api/dashboard/summary').status_code==401

def test_evaluation_is_authenticated_and_honest(admin_app,login,tmp_path):
    from admin_dashboard.services.evaluation_service import EvaluationService
    assert admin_app.test_client().get('/api/evaluation').status_code==401
    assert login[0].get('/evaluation').status_code==200
    assert EvaluationService(tmp_path/'missing.json').read()['available'] is False
