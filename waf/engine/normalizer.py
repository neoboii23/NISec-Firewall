"""Bounded, non-destructive normalization for signature comparison."""
from __future__ import annotations
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class NormalizedValue:
    raw_value: str
    normalized_value: str
    passes: int

    @property
    def changed(self) -> bool:
        return self.raw_value != self.normalized_value


class Normalizer:
    def __init__(self, max_passes: int = 4):
        self.max_passes = max_passes

    def normalize(self, value: str | bytes | None) -> NormalizedValue:
        if value is None:
            value = ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        raw = str(value)
        current = raw
        passes = 0
        for _ in range(self.max_passes):
            decoded = html.unescape(unquote_plus(current))
            if decoded == current:
                break
            current = decoded
            passes += 1
        current = unicodedata.normalize("NFKC", current)
        current = current.replace("\x00", "").replace("\\", "/")
        current = re.sub(r"\s+", " ", current).strip().lower()
        return NormalizedValue(raw, current, passes)
