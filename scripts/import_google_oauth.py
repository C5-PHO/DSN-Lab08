"""Import Google's downloaded web OAuth credentials into the ignored local .env."""

import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('json_file', type=Path)
    args = parser.parse_args()
    config = json.loads(args.json_file.read_text()).get('web', {})
    callback = 'http://127.0.0.1:8088/oauth/google/callback'
    if callback not in config.get('redirect_uris', []):
        raise SystemExit(f'The Google client must authorize {callback}')
    if not config.get('client_id') or not config.get('client_secret'):
        raise SystemExit('The JSON does not contain a complete web OAuth client')
    target = Path(__file__).resolve().parents[1] / '.env'
    if not target.is_file():
        raise SystemExit('Create .env with setup_local.py first')
    updates = {
        'GOOGLE_CLIENT_ID': config['client_id'],
        'GOOGLE_CLIENT_SECRET': config['client_secret'],
    }
    lines = []
    for line in target.read_text().splitlines():
        key = line.split('=', 1)[0]
        if key in updates:
            lines.append(f'{key}={updates.pop(key)}')
        else:
            lines.append(line)
    lines.extend(f'{key}={value}' for key, value in updates.items())
    os.chmod(target, 0o600)
    target.write_text('\n'.join(lines) + '\n')
    print('Google OAuth imported into the ignored .env. Callback verified. No credentials printed.')


if __name__ == '__main__':
    main()
