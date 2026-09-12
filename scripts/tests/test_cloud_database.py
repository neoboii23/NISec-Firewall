"""Offline regression coverage for cloud connection URLs (fake credentials only)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from psycopg.conninfo import conninfo_to_dict
from sqlalchemy.engine import make_url

from scripts import cloud_database, push_local_data_to_cloud as push
from waf.management.settings import normalize_database_url, normalize_psycopg_url


class CloudDatabaseTests(unittest.TestCase):
    def test_supported_schemes_and_reserved_password_characters(self):
        for scheme in ('postgres', 'postgresql', 'postgresql+psycopg'):
            with self.subTest(scheme=scheme):
                value = f'{scheme}://postgres:#demo$pass?word%2F50%@db.example.com:5432/postgres?sslmode=require'
                parsed = conninfo_to_dict(normalize_psycopg_url(value))
                self.assertEqual(parsed['password'], '#demo$pass?word/50%')
                self.assertEqual(parsed['host'], 'db.example.com')
                self.assertEqual(parsed['dbname'], 'postgres')
                self.assertEqual(parsed['sslmode'], 'require')

    def test_encoded_password_is_not_encoded_twice(self):
        value = 'postgresql://postgres:%23test%40pass%2523@db.example.com/postgres'
        normalized = normalize_psycopg_url(value)
        self.assertEqual(normalize_psycopg_url(normalized), normalized)
        self.assertEqual(conninfo_to_dict(normalized)['password'], '#test@pass%23')

    def test_sqlalchemy_schema_settings_preserve_password_and_host(self):
        value = 'postgresql://postgres:#demo$pass@db.example.com:5432/postgres?sslmode=require'
        normalized = normalize_database_url(value, 'security')
        parsed = make_url(normalized)
        self.assertEqual(parsed.drivername, 'postgresql+psycopg')
        self.assertEqual(parsed.password, '#demo$pass')
        self.assertEqual(parsed.host, 'db.example.com')
        self.assertEqual(parsed.query['options'], '-csearch_path=security,public')
        self.assertEqual(parsed.query['sslmode'], 'require')

    def test_existing_options_and_sqlite_are_preserved(self):
        value = 'postgresql://postgres:pass@localhost/postgres?options=-csearch_path%3Dcustom'
        normalized = normalize_database_url(value, 'shop')
        self.assertEqual(parse_qs(urlsplit(normalized).query)['options'], ['-csearch_path=custom'])
        self.assertEqual(normalize_database_url('sqlite:///local.db', 'shop'), 'sqlite:///local.db')
        value = 'postgresql://localhost/postgres?application_name=me@example.com'
        self.assertEqual(normalize_psycopg_url(value), value)

    def test_saved_cloud_environment_works_for_both_connection_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / 'cloud.env'
            env.write_text('SHOP_DATABASE_URL=postgresql+psycopg://postgres:#demo$pass@db.example.com/postgres\n', encoding='utf-8-sig')
            with patch.object(cloud_database, 'CLOUD_ENV', env), patch.dict(os.environ, {}, clear=True):
                dsn = cloud_database.database_url()
                self.assertEqual(push.target_url(), dsn)
                self.assertEqual(conninfo_to_dict(dsn)['password'], '#demo$pass')
                with patch.object(cloud_database.psycopg, 'connect') as connect:
                    cloud_database.connect()
                    connect.assert_called_once_with(dsn, connect_timeout=15)

    def test_cloud_override_and_local_target_guard(self):
        for host in ('localhost', '127.0.0.1', '[::1]'):
            with self.subTest(host=host), patch.object(cloud_database, 'load_cloud_env'), patch.dict(
                os.environ, {'CLOUD_DATABASE_URL': f'postgresql://postgres:#pass@{host}/postgres'}, clear=True
            ):
                with self.assertRaisesRegex(SystemExit, 'Target database must be Supabase Cloud'):
                    push.target_url()

    def test_source_url_converts_driver_and_rejects_remote_host(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'database.json'
            with patch.object(push, 'LOCAL_ADMIN_CONFIG', config):
                config.write_text(json.dumps({'url': 'postgresql+psycopg://postgres:#pass@localhost/postgres'}))
                self.assertEqual(conninfo_to_dict(push.source_url())['host'], 'localhost')
                config.write_text(json.dumps({'url': 'postgresql://postgres:pass@db.example.com/postgres'}))
                with self.assertRaisesRegex(SystemExit, 'Source database must be the local'):
                    push.source_url()

    def test_invalid_url_error_does_not_include_credentials(self):
        with patch.object(cloud_database, 'load_cloud_env'), patch.dict(
            os.environ, {'CLOUD_DATABASE_URL': 'invalid://secret-password'}, clear=True
        ):
            with self.assertRaises(SystemExit) as error:
                cloud_database.database_url()
            self.assertNotIn('secret-password', str(error.exception))

    def test_local_target_is_rejected_before_applying_schema(self):
        with patch.object(push, 'source_url', return_value='postgresql://localhost/postgres'), patch.object(
            push, 'target_url', side_effect=SystemExit('local target')
        ), patch.object(push, 'apply_schema') as apply:
            with self.assertRaises(SystemExit):
                push.push_data()
            apply.assert_not_called()


if __name__ == '__main__':
    unittest.main()
