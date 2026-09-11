"""One redaction policy shared by SQLite and structured file logs."""
import re

SENSITIVE = re.compile(r"password|passwd|pwd|secret|token|cookie|authorization|session|identity|username|email", re.I)

def evidence(field, raw="", normalized="", reason=""):
    result = {"field": field, "reason": reason}
    # Unstructured bodies and headers might contain credentials under arbitrary keys.
    if SENSITIVE.search(field) or field.startswith(("body", "headers", "cookies")):
        result["raw_value"] = result["normalized_value"] = "[REDACTED]"
    else:
        result["raw_value"] = raw[:180]
        result["normalized_value"] = normalized[:180]
    return result

def safe_query(query):
    # Keep parameter names for correlation, never raw query values in access logs.
    return {key[:80]: ["[REDACTED]"] * len(values) for key, values in query.items()}

