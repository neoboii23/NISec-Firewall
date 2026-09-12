"""Smoke-test the local Sentinel dashboard against the configured security DB."""
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
    from admin_dashboard.app import create_app

    app = create_app({"TESTING": True})
    client = app.test_client()
    response = client.get("/login")
    print(f"GET /login: {response.status_code}")
    if response.status_code >= 500:
        raise SystemExit("Dashboard smoke test failed.")
    print("Dashboard smoke test passed.")


if __name__ == "__main__":
    main()
