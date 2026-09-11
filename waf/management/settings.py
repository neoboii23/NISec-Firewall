"""Persistent local connection settings. No credentials are sent to browsers."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def database_url(service):
    # Each service loads only its own least-privilege connection string.
    variable = 'SHOP_DATABASE_URL' if service == 'shop' else 'SECURITY_DATABASE_URL'
    if variable in os.environ:
        return os.environ[variable] or None
    if os.environ.get('NISEC_SQLITE_TEST_MODE') == '1':
        return None
    path = ROOT / '.local' / (service + '-database.json')
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding='utf-8'))['url']
    if not value.startswith('postgresql+psycopg://'):
        raise ValueError('Invalid local database configuration')
    return value
