"""Shared compiled-rule registry. Detectors reuse this matcher and normalizer."""
import json
import re
from pathlib import Path
from .decision import Match
from .privacy import evidence

class RuleEngine:
    def __init__(self, rules_dir, normalizer, encoded_bonus, settings=None):
        self.normalizer, self.encoded_bonus = normalizer, encoded_bonus
        if settings is None:
            settings = json.loads((Path(rules_dir).parent / "config" / "attack_detection.json").read_text(encoding="utf-8"))
        self.settings = settings
        self.rule_overrides = {}
        self.rule_configs = {}
        self.detector_overrides = {}
        self.rules = self._load(Path(rules_dir))
        self.by_id = {rule["id"]: rule for rule in self.rules}
        for rule in self.rules:
            rule["_compiled"] = [re.compile(p, re.I) for p in rule.get("patterns", [])]
        from .detector import AttackPipeline
        self.pipeline = AttackPipeline(self)

    @staticmethod
    def _load(rules_dir):
        rules = []
        for path in sorted(rules_dir.glob("*.json")):
            rules.extend(json.loads(path.read_text(encoding="utf-8")).get("rules", []))
        return rules

    def rule_enabled(self, rule):
        return self.rule_overrides.get(rule["id"], rule.get("enabled", True))

    def detector_enabled(self, key):
        return self.detector_overrides.get(key, self.settings[key]["enabled"])

    def make_match(self, rule_id, field, raw="", normalized="", details=None):
        rule = self.by_id.get(rule_id)
        if not rule or not self.rule_enabled(rule):
            return None
        rule=rule | self.rule_configs.get(rule_id,{})
        proof = evidence(field, raw, normalized, rule["name"])
        if details:
            proof.update(details)
        return Match(rule_id, rule["category"], rule["severity"], rule["score"], rule["name"], field, proof, rule.get("action", "BLOCK"))

    def match_category(self, category, fields):
        matches = []
        for rule in self.rules:
            if rule["category"] != category or not self.rule_enabled(rule):
                continue
            for field, value in fields:
                if field.split(".")[0] not in rule.get("targets", []):
                    continue
                literals=self.rule_configs.get(rule['id'],{}).get('literal_patterns',[])
                if any(p.search(value.normalized_value) for p in rule["_compiled"]) or any(self.normalizer.normalize(p).normalized_value in value.normalized_value for p in literals):
                    matches.append(self.make_match(rule["id"], field, value.raw_value, value.normalized_value))
                    break
        return matches

    def inspect(self, context):
        return self.pipeline.detect(context)
