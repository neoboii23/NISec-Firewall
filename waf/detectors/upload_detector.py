"""Bounded magic-byte and metadata checks; never executes or saves file contents."""
import re
from pathlib import PurePosixPath
from .base import BaseDetector

class UploadDetector(BaseDetector):
    def __init__(self, engine):
        self.engine = engine
        self.policy = engine.settings["file_upload"]
        self.content_patterns = [re.compile(p, re.I) for p in self.policy["content_patterns"]]

    def detect(self, context, fields):
        matches = []
        for index, upload in enumerate(context.files):
            field = f"files.{index}.filename"
            normalized = self.engine.normalizer.normalize(upload.filename).normalized_value
            def add(number, **details):
                match = self.engine.make_match(f"WAF-006-UPLOAD-00{number}", field, upload.filename, normalized, details)
                if match:
                    matches.append(match)
            if upload.size > self.policy["max_size_bytes"]:
                add(5, file_size=upload.size, limit=self.policy["max_size_bytes"])
                continue
            segments = PurePosixPath(normalized).name.split(".")
            ext = segments[-1] if len(segments) > 1 else ""
            allowed = self.policy["allowed_extensions"]
            dangerous = set(self.policy["dangerous_extensions"])
            if ext not in allowed or any(part in dangerous for part in segments[1:]):
                add(1)
            if len(segments) > 2 and any(part in dangerous for part in segments[1:]):
                add(2)
            if (not normalized or len(upload.filename) > self.policy["max_filename_length"]
                or "/" in normalized or ":" in normalized or normalized.startswith(".")
                or any(ord(c) < 32 for c in upload.filename) or "%00" in upload.filename.lower()):
                add(4)
            content = upload.content[:self.policy["inspection_max_bytes"]]
            expected = allowed.get(ext)
            actual = self.signature(content)
            if expected and (upload.content_type.lower() != expected or actual != expected):
                add(3, declared_mime=upload.content_type[:80], detected_mime=actual)
            decoded = content.decode("utf-8", errors="replace")
            if (content.startswith((b"MZ", b"\x7fELF", b"#!", b"PK\x03\x04"))
                or any(p.search(decoded) for p in self.content_patterns)
                or re.search(r"<\s*(?:html|iframe|object|embed)\b", decoded, re.I)):
                add(6)
        return matches

    @staticmethod
    def signature(content):
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if content.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if content.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if content.startswith(b"%PDF-"):
            return "application/pdf"
        try:
            text = content.decode("utf-8")
            if all(ord(c) >= 32 or c in "\r\n\t" for c in text):
                return "text/plain"
        except UnicodeDecodeError:
            pass
        return "application/octet-stream"
