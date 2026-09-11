from .base import SignatureDetector

class SQLInjectionDetector(SignatureDetector):
    category = "SQL_INJECTION"

