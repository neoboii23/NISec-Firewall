import posixpath
import re
from .base import SignatureDetector

class TraversalDetector(SignatureDetector):
    category = "DIRECTORY_TRAVERSAL"

    def detect(self, context, fields):
        matches = super().detect(context, fields)
        # Resolve within a virtual POSIX root, independent of the WAF host OS.
        # The proxy has no access to the backend filesystem.
        keys = self.engine.settings["directory_traversal"].get("file_endpoints", {}).get(context.path, [])
        for field, value in fields:
            if any(field.startswith("query." + key + "[") for key in keys):
                path = value.normalized_value
                root = "/__lab_root__"
                resolved = posixpath.normpath(root + "/" + path)
                if path.startswith("/") or re.match(r"^[a-z]:", path) or not resolved.startswith(root + "/"):
                    match = self.engine.make_match("WAF-004-TRAV-003", field, value.raw_value, path)
                    if match:
                        matches.append(match)
        return matches

