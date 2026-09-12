"""PostgreSQL connection adapter for the existing parameterized store API.

Schema creation belongs to migrations, never runtime application accounts.
Only placeholder syntax is adapted; SQL dialect differences live at call sites.
"""
from contextlib import contextmanager
from functools import lru_cache
from urllib.parse import parse_qsl, unquote, urlsplit
from sqlalchemy import create_engine, text


def bind_query(query, values):
    output, index, quote = [], 0, None
    for char in query:
        if char in ("'", '"'):
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
        if char == '?' and quote is None:
            output.append(f':p{index}')
            index += 1
        else:
            output.append(char)
    if index != len(values):
        raise ValueError('SQL parameter count mismatch')
    return text(''.join(output)), {f'p{i}': value for i, value in enumerate(values)}


class Row:
    def __init__(self, row):
        self.row = row
    def keys(self):
        return self.row._mapping.keys()
    def __getitem__(self, key):
        return self.row[key] if isinstance(key, int) else self.row._mapping[key]
    def __iter__(self):
        return iter(self.row)


class Result:
    def __init__(self, result):
        self.result = result
        self.rowcount = result.rowcount
    def fetchone(self):
        row = self.result.fetchone()
        return Row(row) if row is not None else None
    def fetchall(self):
        return [Row(row) for row in self.result.fetchall()]
    def __iter__(self):
        return (Row(row) for row in self.result)


class Connection:
    def __init__(self, connection):
        self.connection = connection
    def execute(self, query, values=()):
        statement, bindings = bind_query(query, values)
        return Result(self.connection.execute(statement, bindings))


@lru_cache(maxsize=8)
def engine(url):
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=3,
                         connect_args={'connect_timeout': 5})


def search_path_from_url(url):
    query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    options = unquote(query.get("options", ""))
    marker = "-csearch_path="
    if marker not in options:
        return None
    value = options.split(marker, 1)[1].split()[0]
    schemas = [schema.strip() for schema in value.split(",") if schema.strip()]
    if not schemas:
        return None
    for schema in schemas:
        if not schema.replace("_", "").isalnum() or schema[0].isdigit():
            raise ValueError("Unsafe PostgreSQL schema name")
    return schemas


def quote_identifier(identifier):
    return '"' + identifier.replace('"', '""') + '"'


@contextmanager
def connect(url):
    with engine(url).begin() as connection:
        schemas = search_path_from_url(url)
        if schemas:
            quoted = ", ".join(quote_identifier(schema) for schema in schemas)
            connection.execute(text(f"SET LOCAL search_path TO {quoted}"))
        yield Connection(connection)
