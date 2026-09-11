from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """Return Match objects; only the central decision engine chooses HTTP action."""
    @abstractmethod
    def detect(self, context, fields):
        raise NotImplementedError

class SignatureDetector(BaseDetector):
    category = ""
    def __init__(self, engine):
        self.engine = engine

    def detect(self, context, fields):
        return self.engine.match_category(self.category, fields)

