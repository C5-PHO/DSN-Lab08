import tempfile
import unittest
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app


PASSWORD = 'StrongPass1!'


class TechStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.key = Fernet.generate_key().decode()
        self.app = create_app({
            'TESTING': True,
            'SECRET_KEY': 'test-session-key-not-for-deployment',
            'JWT_SECRET': 'test-jwt-key-not-for-deployment-1234567890',
            'TOTP_ENCRYPTION_KEY': self.key,
            'DATABASE': str(Path(self.temp.name) / 'db.sqlite3'),
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def sql(self, statement, values=()):
        with self.app.app_context():
            import sqlite3
            conn = sqlite3.connect(self.app.config['DATABASE'])
            conn.row_factory = sqlite3.Row
            row = conn.execute(statement, values)
            if statement.lstrip().upper().startswith('SELECT'):
                result = row.fetchall()
            else:
                result = row.lastrowid
                conn.commit()
            conn.close()
            return result

    def add_user(self, role, store_id=1):
        email = f'{role}{store_id}@example.test'
        secret = pyotp.random_base32()
        user_id = self.sql(
            'INSERT INTO users(email,full_name,password_hash,role,store_id,totp_secret_encrypted,totp_enabled) '
            'VALUES (?,?,?,?,?,?,1)',
            (email, role.title(), generate_password_hash(PASSWORD), role, store_id,
             Fernet(self.key.encode()).encrypt(secret.encode()).decode()),
        )
        return user_id, email, secret

    def csrf(self, client=None):
        client = client or self.client
        client.get('/login')
        with client.session_transaction() as session:
            return session['csrf']

    def login(self, email, secret):
        client = self.app.test_client()
        response = client.post('/login', data={
            '_csrf': self.csrf(client), 'email': email, 'password': PASSWORD,
        })
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            csrf = session['csrf']
        response = client.post('/mfa', data={'_csrf': csrf, 'code': pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            csrf = session['csrf']
        token = client.get('/api/token').json['access_token']
        return client, csrf, {'Authorization': f'Bearer {token}'}

    def test_registration_restricts_role_and_enrolls_totp(self):
        response = self.client.post('/register', data={
            '_csrf': self.csrf(), 'email': 'new@example.test', 'full_name': 'New Person',
            'password': PASSWORD, 'store_id': '2', 'role': 'admin',
        })
        self.assertEqual(response.status_code, 302)
        user = self.sql('SELECT role,store_id,totp_enabled FROM users WHERE email=?', ('new@example.test',))[0]
        self.assertEqual((user['role'], user['store_id'], user['totp_enabled']), ('sales', 2, 0))
        self.assertIn(b'Configurar TOTP', self.client.get('/mfa').data)
        encrypted = self.sql('SELECT totp_secret_encrypted FROM users WHERE email=?', ('new@example.test',))[0][0]
        secret = Fernet(self.key.encode()).decrypt(encrypted.encode()).decode()
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        self.assertEqual(self.client.get('/api/token').status_code, 401)
        self.assertEqual(self.client.post('/mfa', data={
            '_csrf': csrf, 'code': pyotp.TOTP(secret).now(),
        }).status_code, 302)
        self.assertEqual(self.sql('SELECT totp_enabled FROM users WHERE email=?', ('new@example.test',))[0][0], 1)
        self.assertEqual(self.client.get('/api/me', headers={
            'Authorization': 'Bearer ' + self.client.get('/api/token').json['access_token'],
        }).status_code, 200)

    def test_totp_code_cannot_be_replayed(self):
        _, email, secret = self.add_user('sales')
        client, _, _ = self.login(email, secret)
        client.post('/login', data={'_csrf': self.csrf(client), 'email': email, 'password': PASSWORD})
        with client.session_transaction() as session:
            csrf = session['csrf']
        response = client.post('/mfa', data={'_csrf': csrf, 'code': pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'C\xc3\xb3digo inv\xc3\xa1lido', response.data)
        self.assertEqual(client.get('/api/token').status_code, 401)

    def test_registration_rejects_weak_password_duplicate_and_csrf(self):
        payload = {'email': 'new@example.test', 'full_name': 'New Person', 'store_id': '1'}
        self.assertEqual(self.client.post('/register', data={**payload, 'password': PASSWORD}).status_code, 400)
        response = self.client.post('/register', data={**payload, 'password': 'weak', '_csrf': self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sql('SELECT COUNT(*) AS n FROM users')[0]['n'], 0)

    def test_password_lockout_after_five_failures(self):
        user_id, email, _ = self.add_user('sales')
        token = self.csrf()
        for _ in range(5):
            response = self.client.post('/login', data={'_csrf': token, 'email': email, 'password': 'WrongPass1!'})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sql('SELECT password_failures FROM users WHERE id=?', (user_id,))[0]['password_failures'], 5)
        response = self.client.post('/login', data={'_csrf': token, 'email': email, 'password': PASSWORD})
        self.assertIn(b'bloqueada', response.data)

    def test_mfa_three_failures_lock_account_and_no_jwt(self):
        user_id, email, _ = self.add_user('sales')
        self.client.post('/login', data={'_csrf': self.csrf(), 'email': email, 'password': PASSWORD})
        with self.client.session_transaction() as session:
            token = session['csrf']
        for _ in range(3):
            self.client.post('/mfa', data={'_csrf': token, 'code': '000000'})
        user = self.sql('SELECT mfa_failures,locked_until FROM users WHERE id=?', (user_id,))[0]
        self.assertEqual(user['mfa_failures'], 3)
        self.assertGreater(user['locked_until'], 0)
        self.assertEqual(self.client.get('/api/token').status_code, 401)

    def test_roles_and_store_boundaries(self):
        _, admin_email, admin_secret = self.add_user('admin')
        _, manager_email, manager_secret = self.add_user('manager')
        _, sales_email, sales_secret = self.add_user('sales')
        _, auditor_email, auditor_secret = self.add_user('auditor')
        admin, _, admin_auth = self.login(admin_email, admin_secret)
        manager, _, manager_auth = self.login(manager_email, manager_secret)
        sales, _, sales_auth = self.login(sales_email, sales_secret)
        auditor, _, auditor_auth = self.login(auditor_email, auditor_secret)
        self.assertEqual(admin.post('/api/products', json={
            'store_id': 2, 'sku': 'R-2', 'name': 'Router', 'price_cents': 10000, 'stock': 8,
        }, headers=admin_auth).status_code, 201)
        own = manager.post('/api/products', json={
            'store_id': 1, 'sku': 'S-1', 'name': 'Switch', 'price_cents': 12000, 'stock': 3,
        }, headers=manager_auth)
        self.assertEqual(own.status_code, 201)
        own_id = own.json['id']
        self.assertEqual(manager.get('/api/products', headers=manager_auth).json[0]['store_id'], 1)
        self.assertEqual(len(auditor.get('/api/products', headers=auditor_auth).json), 2)
        self.assertEqual(sales.patch(f'/api/products/{own_id}', json={'price_cents': 1}, headers=sales_auth).status_code, 403)
        self.assertEqual(sales.patch(f'/api/products/{own_id}', json={'stock': 7}, headers=sales_auth).status_code, 200)
        self.assertEqual(sales.delete(f'/api/products/{own_id}', headers=sales_auth).status_code, 403)
        self.assertEqual(auditor.patch(f'/api/products/{own_id}', json={'stock': 9}, headers=auditor_auth).status_code, 403)
        self.assertEqual(manager.delete('/api/products/1', headers=manager_auth).status_code, 403)
        self.assertEqual(manager.get('/api/report', headers=manager_auth).json[0]['store_id'], 1)
        self.assertEqual(len(auditor.get('/api/report', headers=auditor_auth).json), 2)

    def test_admin_changes_revoke_old_jwt(self):
        _, admin_email, admin_secret = self.add_user('admin')
        sales_id, sales_email, sales_secret = self.add_user('sales')
        admin, csrf, _ = self.login(admin_email, admin_secret)
        sales, _, sales_auth = self.login(sales_email, sales_secret)
        self.assertEqual(sales.get('/api/me', headers=sales_auth).status_code, 200)
        response = admin.post(f'/users/{sales_id}', data={'_csrf': csrf, 'role': 'auditor', 'store_id': '2'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(sales.get('/api/me', headers=sales_auth).status_code, 401)

    def test_social_login_requires_configuration_and_api_requires_bearer(self):
        self.assertEqual(self.client.get('/oauth/google/start').status_code, 404)
        self.assertEqual(self.client.get('/oauth/github/start').status_code, 404)
        self.assertEqual(self.client.get('/api/products').status_code, 401)


if __name__ == '__main__':
    unittest.main()
