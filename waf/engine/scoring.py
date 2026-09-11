from .decision import DetectionResult, Match

SEVERITY_ORDER = {"NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def build_result(matches: list[Match], encoded: bool, encoded_bonus: int) -> DetectionResult:
    # Count a rule once, even when the same evidence appears in several fields.
    unique = list({m.rule_id: m for m in matches}.values())
    score = sum(m.score for m in unique) + (encoded_bonus if unique and encoded else 0)
    severity = max((m.severity for m in unique), key=SEVERITY_ORDER.get, default="INFO")
    if score >= 11 and sum(m.score >= 7 for m in unique) >= 2:
        severity = "CRITICAL"
    strongest = max(unique, key=lambda m: m.score, default=None)
    return DetectionResult(score=score, severity=severity, category=strongest.category if strongest else "NONE", matches=unique)
