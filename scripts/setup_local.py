"""Create ignored local secrets without printing them to the terminal."""

import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


root = Path(__file__).resolve().parents[1]
target = root / '.env'
if target.exists():
    raise SystemExit('.env already exists; not overwriting local secrets')

content = '\n'.join([
    '# Local Lab08 secrets. Never commit this file.',
    f'APP_SECRET={secrets.token_urlsafe(48)}',
    f'JWT_SECRET={secrets.token_urlsafe(48)}',
    f'TOTP_ENCRYPTION_KEY={Fernet.generate_key().decode()}',
    'BASE_URL=http://127.0.0.1:8088',
    'DATABASE=instance/techstore.sqlite3',
    'COOKIE_SECURE=false',
    'GOOGLE_CLIENT_ID=',
    'GOOGLE_CLIENT_SECRET=',
    'GITHUB_CLIENT_ID=',
    'GITHUB_CLIENT_SECRET=',
    '',
])
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(content)
print('Created ignored .env with private permissions. OAuth fields remain empty.')
