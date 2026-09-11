"""Create local-only Docker credentials once; never print them."""
import json
from pathlib import Path
import secrets

root=Path(__file__).resolve().parents[1]
folder=root/'.local'
folder.mkdir(exist_ok=True)
path=folder/'supabase.env'
if not path.exists():
    password=secrets.token_urlsafe(36)
    key=secrets.token_hex(32)
    path.write_text(f'POSTGRES_PASSWORD={password}\nPG_META_CRYPTO_KEY={key}\n',encoding='utf-8')
    (folder/'migration-database.json').write_text(json.dumps({'url':f'postgresql://postgres:{password}@127.0.0.1:54322/postgres'}),encoding='utf-8')
print('Local Supabase credentials are ready (not displayed).')
