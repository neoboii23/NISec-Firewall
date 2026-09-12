"""Smoke-test the root Flask shop app in a Vercel-like environment."""
from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLOUD_ENV = ROOT / ".local" / "cloud.env"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_cloud_env() -> None:
    if not CLOUD_ENV.exists():
        raise SystemExit("Missing .local/cloud.env. Run scripts/configure_cloud_env.ps1 first.")
    for raw_line in CLOUD_ENV.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip("\"'"))


def main() -> None:
    load_cloud_env()
    os.environ["VERCEL"] = "1"
    os.environ["VULNERABLE_MODE"] = "false"
    os.environ["LAB_MODE"] = "false"

    from app import app

    checks = [
        ("GET", "/", None),
        ("GET", "/search", {"q": "tote"}),
        ("GET", "/login", None),
        ("GET", "/register", None),
        ("GET", "/comment", None),
        ("GET", "/upload", None),
        ("GET", "/admin", None),
    ]
    client = app.test_client()
    failures = []
    for method, path, query in checks:
        response = client.open(path, method=method, query_string=query)
        print(f"{method} {path}: {response.status_code}")
        if response.status_code >= 500:
            failures.append(f"{method} {path} -> {response.status_code}")
    if failures:
        raise SystemExit("Smoke test failed: " + ", ".join(failures))
    print("Vercel-style shop smoke test passed.")


if __name__ == "__main__":
    main()
