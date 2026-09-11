"""Response-confirmed login tracking with injected time, expiry and bounded state."""
from collections import deque
import hashlib
import hmac
import secrets
import threading
import time
from .base import BaseDetector

class BruteForceDetector(BaseDetector):
    def __init__(self, engine, clock=time.monotonic):
        self.engine, self.clock = engine, clock
        self.policy = engine.settings["brute_force"]
        self.state = {}
        self.lock = threading.Lock()
        self.salt = secrets.token_bytes(32)

    def is_login(self, context):
        return context.method == "POST" and context.path == self.policy["login_path"]

    def unblock_ip(self, ip):
        with self.lock:
            accounts = {key[-1] for key in self.state if key[0] == "pair" and key[1] == ip}
            for key in list(self.state):
                if (key[0] in ("ip", "pair") and key[1] == ip) or (key[0] == "account" and key[1] in accounts):
                    self.state.pop(key, None)

    def snapshot(self):
        with self.lock:
            now = self.clock()
            self.cleanup(now)
            return [{"source_ip": key[1], "failures": len(value[0]),
                     "remaining_seconds": max(0, int(value[1]-now))}
                    for key,value in self.state.items() if key[0] == "ip"]

    def keys(self, context):
        identity = ""
        for field in self.policy["identity_fields"]:
            if context.form.get(field):
                identity = context.form[field][0].strip().casefold()
                break
        digest = hmac.new(self.salt, identity.encode(), hashlib.sha256).hexdigest()
        return [("ip", context.client_ip)] + ([("account", digest), ("pair", context.client_ip, digest)] if identity else [])

    def cleanup(self, now):
        for key, (failures, blocked_until) in list(self.state.items()):
            while failures and now - failures[0] >= self.policy["window_seconds"]:
                failures.popleft()
            if not failures and blocked_until <= now:
                del self.state[key]

    def match(self, count, remaining, reason="failure threshold"):
        match = self.engine.make_match("WAF-005-BRUTE-001", "login.identity")
        if match:
            match.evidence.update(failed_attempt_count=count, time_window=self.policy["window_seconds"],
                                 block_duration=self.policy["block_seconds"], retry_after=max(1, int(remaining)),
                                 reason=reason)
        return match

    def detect(self, context, fields=()):
        if not self.is_login(context):
            return []
        with self.lock:
            now = self.clock()
            self.cleanup(now)
            keys = self.keys(context)
            for key in keys:
                failures, until = self.state.get(key, ((), 0))
                if until > now:
                    match = self.match(len(failures), until - now)
                    return [match] if match else []
            if len(self.state) + sum(k not in self.state for k in keys) > self.policy["max_entries"]:
                match = self.match(0, 1, "login tracking capacity reached")
                return [match] if match else []
        return []

    def observe(self, context, status, headers):
        if not self.is_login(context):
            return [], {}
        header = self.policy["response_header"].lower()
        outcome = next((v for k, v in headers.items() if k.lower() == header), "")
        failure = outcome == self.policy["failure_value"] and 200 <= status < 500
        success = outcome == self.policy["success_value"] and 200 <= status < 400
        if not failure and not success:
            return [], {"authentication_outcome": "unknown"}
        with self.lock:
            now = self.clock()
            self.cleanup(now)
            keys = self.keys(context)
            meta = {"authentication_outcome": "success" if success else "failure",
                    "account_hash": keys[-1][-1] if len(keys) > 1 else ""}
            if success:
                for key in keys:
                    self.state.pop(key, None)
                return [], meta
            peak, threshold = 0, False
            for key in keys:
                if key not in self.state and len(self.state) >= self.policy["max_entries"]:
                    continue
                failures, until = self.state.setdefault(key, (deque(), 0))
                # Already in-flight requests cannot extend a block forever.
                if until > now:
                    continue
                failures.append(now)
                peak = max(peak, len(failures))
                if len(failures) >= self.policy["max_failures"]:
                    until = now + self.policy["block_seconds"]
                    threshold = True
                self.state[key] = failures, until
            meta["failed_attempt_count"] = peak
            match = self.match(peak, self.policy["block_seconds"]) if threshold else None
            return [match] if match else [], meta
