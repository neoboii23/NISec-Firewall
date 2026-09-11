from engine.rate_limit import RateLimiter


def test_rate_limiter_blocks_after_threshold():
    limiter = RateLimiter(2, 60)
    assert limiter.allowed("127.0.0.1")
    assert limiter.allowed("127.0.0.1")
    assert not limiter.allowed("127.0.0.1")
