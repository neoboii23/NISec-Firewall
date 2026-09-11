from .evaluation import effectiveness,benchmark,normal_traffic

def test_effectiveness_handles_misses_and_empty_denominators():
    result=effectiveness([dict(code='test',category='XSS',detected=True,blocked=False),dict(code='test2',category='XSS',detected=False,blocked=False)],
                         [dict(detected=True,blocked=True),dict(detected=False,blocked=False)])
    assert (result['true_positives'],result['false_positives'],result['true_negatives'],result['false_negatives'])==(1,1,1,1)
    assert result['detection_rate']==.5 and result['blocking_rate']==0
    assert effectiveness([],[])['precision'] is None

def test_normal_workflow_and_real_benchmark():
    rows=normal_traffic()
    assert len(rows)==7 and all(r['functional_success'] and not r['blocked'] for r in rows)
    result=benchmark(5)
    for key in ('direct','protected'):
        assert result[key]['successful_responses']==5
        assert result[key]['mean_latency_ms']>0 and result[key]['peak_sampled_rss_mib']>0
