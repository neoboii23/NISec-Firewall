from pathlib import Path
from engine.inspector import RequestContext, FileInfo
from engine.normalizer import Normalizer
from engine.rule_engine import RuleEngine

ROOT = Path(__file__).resolve().parents[1]


def context(query=None, body=b"", files=None, user_agent="Mozilla/5.0"):
    return RequestContext("127.0.0.1", "GET", "http://test/", "/", query or {}, {}, {}, user_agent, "", body, files or [], len(body))


def engine():
    return RuleEngine(ROOT / "rules", Normalizer(), 2)


def test_normal_search_remains_allowed():
    result = engine().inspect(context({"q": ["union made tote"]}))
    assert result.score == 0
    assert result.matches == []


def test_sqli_is_detected_after_encoding_normalization():
    result = engine().inspect(context({"q": ["%27%20OR%201%3D1--"]}))
    assert result.score >= 7
    assert "WAF-001-SQLI-001" in result.rule_ids


def test_xss_traversal_command_and_upload_categories():
    assert engine().inspect(context({"q": ["<script>alert(1)</script>"]})).category == "XSS"
    assert engine().inspect(context({"file": ["..%2fetc%2fpasswd"]})).category == "DIRECTORY_TRAVERSAL"
    assert engine().inspect(context({"host": ["127.0.0.1;whoami"]})).category == "COMMAND_INJECTION"
    upload = FileInfo("image.php.jpg", "image/jpeg", 100)
    assert engine().inspect(context(files=[upload])).category == "MALICIOUS_FILE_UPLOAD"
