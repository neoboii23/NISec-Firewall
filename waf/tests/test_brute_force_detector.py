from conftest import make_context
from detectors.brute_force_detector import BruteForceDetector
from engine.scoring import build_result
from engine.decision import decide

def test_failure_threshold_and_expiry(detector_engine):
    now = [100.]
    detector = BruteForceDetector(detector_engine, clock=lambda: now[0])
    ctx = make_context(path="/login", form={"identity":["student"], "password":["private"]})
    for n in range(5):
        assert detector.detect(ctx) == []
        matches, meta = detector.observe(ctx, 200, {"X-Lab-Auth-Result":"failure"})
        assert meta["failed_attempt_count"] == n + 1
        assert bool(matches) == (n == 4)
    assert decide(build_result(detector.detect(ctx), False, 0)) == 429
    now[0] += 601
    assert detector.detect(ctx) == []
    assert not detector.state

def test_success_unknown_expiration_and_isolation(detector_engine):
    now = [100.]
    detector = BruteForceDetector(detector_engine, clock=lambda: now[0])
    ctx = make_context(path="/login", form={"identity":["student"]})
    for n in range(4):
        detector.observe(ctx, 200, {"X-Lab-Auth-Result":"failure"})
    detector.observe(ctx, 302, {"X-Lab-Auth-Result":"success"})
    assert not detector.state
    detector.observe(ctx, 200, {})
    detector.observe(ctx, 502, {"X-Lab-Auth-Result":"failure"})
    assert not detector.state
    detector.observe(ctx, 200, {"X-Lab-Auth-Result":"failure"})
    now[0] += 301
    detector.detect(ctx)
    assert not detector.state
    for n in range(5):
        detector.observe(ctx, 200, {"X-Lab-Auth-Result":"failure"})
    other = make_context(path="/login", ip="192.0.2.2", form={"identity":["other"]})
    assert not detector.detect(other)
    # IP-wide and account-wide limits intentionally aggregate across the other dimension.
    assert detector.detect(make_context(path="/login", ip="192.0.2.2", form={"identity":["student"]}))
    assert detector.detect(make_context(path="/login", form={"identity":["other"]}))

def test_bounded_state(detector_engine):
    detector = BruteForceDetector(detector_engine)
    detector.policy["max_entries"] = 3
    detector.observe(make_context(path="/login", form={"identity":["student"]}), 200, {"X-Lab-Auth-Result":"failure"})
    assert detector.detect(make_context(path="/login", ip="192.0.2.2", form={"identity":["other"]}))
    assert len(detector.state) == 3
