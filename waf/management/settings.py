"""Persistent local connection settings. No credentials are sent to browsers."""
import json
import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]


def normalize_database_url(value, schema=None):
    if not value:
        return None
    if value.startswith('postgres://'):
        value = 'postgresql+psycopg://' + value[len('postgres://'):]
    elif value.startswith('postgresql://'):
        value = 'postgresql+psycopg://' + value[len('postgresql://'):]
    if schema and value.startswith('postgresql+psycopg://'):
        parts = urlsplit(value)
        query = parse_qsl(parts.query, keep_blank_values=True)
        if not any(key == 'options' for key, _value in query):
            query.append(('options', f'-csearch_path={schema},public'))
        value = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return value


def database_url(service):
    # Each service loads only its own least-privilege connection string.
    variable = 'SHOP_DATABASE_URL' if service == 'shop' else 'SECURITY_DATABASE_URL'
    if variable in os.environ:
        schema_variable = 'SHOP_DATABASE_SCHEMA' if service == 'shop' else 'SECURITY_DATABASE_SCHEMA'
        return normalize_database_url(os.environ[variable], os.environ.get(schema_variable)) or None
    if os.environ.get('NISEC_SQLITE_TEST_MODE') == '1':
        return None
    path = ROOT / '.local' / (service + '-database.json')
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding='utf-8'))['url']
    if not value.startswith('postgresql+psycopg://'):
        raise ValueError('Invalid local database configuration')
    return value
