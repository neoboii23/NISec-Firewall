"""Harmless synthetic inputs, never executed as operating-system commands."""
CASES = [
    dict(code='WAF-001',category='SQL_INJECTION',method='GET',path='/search',kwargs={'params':{'q':"' OR 1=1--"}},expected=403),
    dict(code='WAF-002',category='XSS',method='POST',path='/comment',kwargs={'data':{'item_id':'1','body':'<script>/* lab-marker */</script>'}},expected=403),
    dict(code='WAF-003',category='COMMAND_INJECTION',method='GET',path='/search',kwargs={'params':{'q':'127.0.0.1;whoami'}},expected=403),
    dict(code='WAF-004',category='DIRECTORY_TRAVERSAL',method='GET',path='/download',kwargs={'params':{'file':'../evaluation-canary.txt'}},expected=403),
    dict(code='WAF-006',category='MALICIOUS_FILE_UPLOAD',method='POST',path='/upload',kwargs={'files':{'file':('synthetic.php',b'Harmless synthetic laboratory sample.','text/plain')}},expected=403),
]

BRUTE=dict(code='WAF-005',category='BRUTE_FORCE',method='POST',path='/login',kwargs={'data':{'identity':'lab-evaluation-missing','password':'intentionally-wrong'}},expected=429)
