from .comparison import comparison

def test_comparison_uses_observed_outcomes():
    report=comparison()
    assert len(report['comparison'])==6
    for row in report['comparison']:
        assert row['detected'] and row['blocked'] and row['blocked_backend_arrivals']==0
        if row['code']=='WAF-003':assert row['vulnerability_demonstrated'] is None
        else:assert row['vulnerability_demonstrated'] is True
