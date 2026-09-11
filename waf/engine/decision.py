from dataclasses import dataclass, field
from typing import Literal

Decision = Literal["ALLOW", "BLOCK", "RATE_LIMIT"]
CATEGORIES = {
    "SQL_INJECTION": ("WAF-001", "SQL Injection"),
    "XSS": ("WAF-002", "Cross-Site Scripting"),
    "COMMAND_INJECTION": ("WAF-003", "Command Injection"),
    "DIRECTORY_TRAVERSAL": ("WAF-004", "Directory Traversal"),
    "BRUTE_FORCE": ("WAF-005", "Brute Force"),
    "MALICIOUS_FILE_UPLOAD": ("WAF-006", "Malicious File Upload"),
}

@dataclass
class Match:
    rule_id: str
    category: str
    severity: str
    score: int
    name: str
    component: str
    evidence: dict = field(default_factory=dict)
    action: str = "BLOCK"

@dataclass
class DetectionResult:
    decision: Decision = "ALLOW"
    score: int = 0
    severity: str = "INFO"
    category: str = "NONE"
    matches: list[Match] = field(default_factory=list)
    incident_id: str | None = None
    timestamp: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def rule_ids(self):
        return list(dict.fromkeys(match.rule_id for match in self.matches))

    @property
    def category_code(self):
        return CATEGORIES.get(self.category, ("", self.category))[0]

    @property
    def category_name(self):
        return CATEGORIES.get(self.category, ("", self.category))[1]

def decide(result, block_score=7):
    """The single policy boundary for detector HTTP decisions."""
    active = [m for m in result.matches if m.action not in ("LOG","ALERT")]
    if any(m.action=='RATE_LIMIT' for m in active):
        result.decision='RATE_LIMIT'
        return 429
    if any(m.rule_id == "WAF-006-UPLOAD-005" for m in active):
        result.decision = "BLOCK"
        return 413
    if any(m.category == "BRUTE_FORCE" for m in active):
        result.decision = "RATE_LIMIT"
        return 429
    active_score=sum(m.score for m in active)+max(0,result.score-sum(m.score for m in result.matches))
    if active and active_score >= block_score:
        result.decision = "BLOCK"
        return 403
    result.decision = "ALLOW"
    return None
