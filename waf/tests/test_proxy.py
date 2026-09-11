import pytest
from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({
        'DATABASE_PATH': tmp_path / 'waf.db',
        'LOG_DIR': tmp_path / 'logs',
        'RATE_LIMIT_ENABLED': False,
    })


def test_malicious_request_is_blocked_before_forwarding(app):
    client = app.test_client()
    response = client.get("/search?q=%27%20OR%201%3D1--")
    assert response.status_code == 403
    assert b"Request blocked" in response.data


def test_health_endpoint_has_waf_service_identity(app):
    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.json["service"] == "WAF"
