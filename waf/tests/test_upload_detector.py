import pytest
from conftest import make_context
from engine.inspector import FileInfo
from engine.decision import decide

@pytest.mark.parametrize("name,mime,data", [
("a.jpg","image/jpeg",b"\xff\xd8\xff harmless"),
("a.png","image/png",b"\x89PNG\r\n\x1a\n harmless"),
("a.pdf","application/pdf",b"%PDF-1.4 harmless"),
("a.gif","image/gif",b"GIF89a harmless"),
("a.txt","text/plain",b"Lab note")])
def test_allowed(detector_engine, name, mime, data):
    assert decide(detector_engine.inspect(make_context(files=[FileInfo(name,mime,len(data),data)]))) is None

@pytest.mark.parametrize("name,mime,data,rule", [
("a.php","text/plain",b"harmless","001"),
("a.exe","application/octet-stream",b"harmless","001"),
("image.jpg.php","text/plain",b"harmless","002"),
("image.php.jpg","image/jpeg",b"harmless","002"),
("a.jpg","image/jpeg",b"just text","003"),
("a.png","text/plain",b"\x89PNG\r\n\x1a\n","003"),
("../a.txt","text/plain",b"note","004"),
("C:\\a.txt","text/plain",b"note","004"),
(".hidden.txt","text/plain",b"note","004"),
("a%00.txt","text/plain",b"note","004"),
("a.txt","text/plain",b"<?php /* harmless test marker */ ?>","006"),
("a.png","image/png",b"\x89PNG\r\n\x1a\n<script>test</script>","006"),
("a.txt","text/plain",b"MZ harmless synthetic header","006")])
def test_blocked(detector_engine, name, mime, data, rule):
    result = detector_engine.inspect(make_context(files=[FileInfo(name,mime,len(data),data)]))
    assert decide(result) == 403
    assert "WAF-006-UPLOAD-" + rule in result.rule_ids

def test_size(detector_engine):
    result = detector_engine.inspect(make_context(files=[FileInfo("a.txt","text/plain",2*1024*1024,b"prefix")]))
    assert decide(result) == 413
