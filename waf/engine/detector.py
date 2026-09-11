"""Runs enabled detectors over one normalized field representation."""
from detectors.sqli_detector import SQLInjectionDetector
from detectors.xss_detector import XSSDetector
from detectors.command_injection_detector import CommandInjectionDetector
from detectors.traversal_detector import TraversalDetector
from detectors.upload_detector import UploadDetector
from detectors.brute_force_detector import BruteForceDetector
from .scoring import build_result

class AttackPipeline:
    def __init__(self, engine):
        self.engine = engine
        self.detectors = [(key, cls(engine)) for key, cls in [
            ("sql_injection", SQLInjectionDetector), ("xss", XSSDetector),
            ("command_injection", CommandInjectionDetector), ("directory_traversal", TraversalDetector),
            ("file_upload", UploadDetector)]]
        self.brute_force = BruteForceDetector(engine)

    def detect(self, context):
        fields = [(name, self.engine.normalizer.normalize(raw)) for name, raw in context.text_fields()]
        matches = []
        for key, detector in self.detectors:
            if self.engine.detector_enabled(key):
                matches.extend(detector.detect(context, fields))
        if self.engine.detector_enabled("brute_force"):
            matches.extend(self.brute_force.detect(context))
        matches.extend(self.engine.match_category("SCANNER", fields))
        # Bonus only for encoded evidence that actually matched, not an unrelated field.
        matched_fields = {m.component for m in matches}
        encoded = any(v.passes > 0 and f in matched_fields for f, v in fields)
        return build_result(matches, encoded, self.engine.encoded_bonus)

    def observe_response(self, context, status, headers, result):
        if not self.engine.detector_enabled("brute_force"):
            return result
        matches, metadata = self.brute_force.observe(context, status, headers)
        if matches:
            result = build_result(result.matches + matches, False, self.engine.encoded_bonus)
        result.metadata.update(metadata)
        return result
