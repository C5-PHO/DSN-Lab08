"""TechStore: local inventory lab with RBAC, OAuth account linking and TOTP MFA."""

import base64
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import click
import jwt
import pyotp
import qrcode
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request, session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


ROLES = ('admin', 'manager', 'sales', 'auditor')
ISSUER = 'techstore-lab08'
AUDIENCE = 'techstore-api'
LOCK_SECONDS = 15 * 60


def valid_password(password):
    return (8 <= len(password) <= 128 and bool(re.search(r'[A-Z]', password))
            and bool(re.search(r'[0-9]', password))
            and bool(re.search(r'[^A-Za-z0-9]', password)))


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv('APP_SECRET'),
        JWT_SECRET=os.getenv('JWT_SECRET'),
        TOTP_ENCRYPTION_KEY=os.getenv('TOTP_ENCRYPTION_KEY'),
        DATABASE=os.getenv('DATABASE', 'instance/techstore.sqlite3'),
        BASE_URL=os.getenv('BASE_URL', 'http://127.0.0.1:8088').rstrip('/'),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE', 'false').lower() == 'true',
        MAX_CONTENT_LENGTH=64 * 1024,
        TRUSTED_HOSTS=['127.0.0.1', 'localhost'],
    )
    if test_config:
        app.config.update(test_config)
    missing = [key for key in ('SECRET_KEY', 'JWT_SECRET', 'TOTP_ENCRYPTION_KEY')
               if not app.config.get(key)]
    if missing:
        raise RuntimeError(f'Missing configuration: {", ".join(missing)}. See .env.example.')
    if len(app.config['SECRET_KEY']) < 32 or len(app.config['JWT_SECRET']) < 32:
        raise RuntimeError('APP_SECRET and JWT_SECRET must each be at least 32 characters')
    fernet = Fernet(app.config['TOTP_ENCRYPTION_KEY'].encode())
    db_path = Path(app.config['DATABASE'])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(str(db_path))
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys = ON')
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        conn = g.pop('db', None)
        if conn is not None:
            conn.close()

    with app.app_context():
        db().executescript((Path(__file__).parent / 'schema.sql').read_text())
        columns = {row['name'] for row in db().execute('PRAGMA table_info(oauth_links)')}
        if 'provider_email' not in columns:
            db().execute('ALTER TABLE oauth_links ADD COLUMN provider_email TEXT')
        if 'provider_username' not in columns:
            db().execute('ALTER TABLE oauth_links ADD COLUMN provider_username TEXT')
        db().commit()

    oauth = OAuth(app)
    providers = {}
    if os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET'):
        providers['google'] = oauth.register(
            name='google',
            client_id=os.getenv('GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'},
        )
    if os.getenv('GITHUB_CLIENT_ID') and os.getenv('GITHUB_CLIENT_SECRET'):
        providers['github'] = oauth.register(
            name='github',
            client_id=os.getenv('GITHUB_CLIENT_ID'),
            client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            api_base_url='https://api.github.com/',
            client_kwargs={'scope': 'read:user'},
        )

    def row_dict(row):
        return dict(row) if row else None

    def get_user(user_id):
        return db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    def public_user(user):
        return {key: user[key] for key in ('id', 'email', 'full_name', 'role', 'store_id')}

    def csrf_token():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return session['csrf']

    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def csrf_guard():
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and not request.path.startswith('/api/'):
            supplied = request.form.get('_csrf', '')
            if not secrets.compare_digest(supplied, session.get('csrf', '')) or not supplied:
                abort(400, 'Invalid CSRF token')

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "form-action 'self' https://accounts.google.com; frame-ancestors 'none'"
        )
        response.headers['Cache-Control'] = 'no-store'
        return response

    def issue_jwt(user):
        now = datetime.now(timezone.utc)
        claims = {
            'sub': str(user['id']), 'iss': ISSUER, 'aud': AUDIENCE,
            'iat': now, 'exp': now + timedelta(minutes=30),
            'jti': secrets.token_hex(16), 'ver': user['token_version'],
            'mfa': True,
        }
        return jwt.encode(claims, app.config['JWT_SECRET'], algorithm='HS256')

    def authenticated_user(api=False):
        raw = ''
        if api:
            header = request.headers.get('Authorization', '')
            if header.startswith('Bearer '):
                raw = header[7:]
        else:
            raw = request.cookies.get('techstore_access', '')
        if not raw:
            return None
        try:
            claims = jwt.decode(
                raw, app.config['JWT_SECRET'], algorithms=['HS256'],
                audience=AUDIENCE, issuer=ISSUER,
                options={'require': ['sub', 'iss', 'aud', 'iat', 'exp', 'jti', 'ver', 'mfa']},
            )
            if claims['mfa'] is not True:
                return None
            user = get_user(int(claims['sub']))
            if not user or claims['ver'] != user['token_version'] or user['locked_until'] > int(time.time()):
                return None
            return user
        except (jwt.PyJWTError, ValueError, TypeError):
            return None

    def html_user():
        user = authenticated_user()
        if not user:
            abort(401)
        return user

    def api_user():
        user = authenticated_user(api=True)
        if not user:
            abort(401)
        return user

    def can(user, action, product=None, store_id=None):
        role = user['role']
        if role == 'admin':
            return True
        target_store = product['store_id'] if product else store_id
        if action == 'report':
            return role in ('manager', 'auditor')
        if action == 'read':
            return role == 'auditor' or target_store == user['store_id']
        if role == 'auditor':
            return False
        if target_store != user['store_id']:
            return False
        if role == 'manager':
            return action in ('create', 'edit', 'stock', 'delete')
        return role == 'sales' and action == 'stock'

    def visible_products(user):
        if user['role'] in ('admin', 'auditor'):
            return db().execute('SELECT p.*, s.name AS store_name FROM products p JOIN stores s ON s.id=p.store_id ORDER BY p.id').fetchall()
        return db().execute(
            'SELECT p.*, s.name AS store_name FROM products p JOIN stores s ON s.id=p.store_id '
            'WHERE p.store_id=? ORDER BY p.id', (user['store_id'],)
        ).fetchall()

    def stores():
        return db().execute('SELECT * FROM stores ORDER BY id').fetchall()

    def begin_mfa(user):
        session.clear()
        session['pending_user_id'] = user['id']
        session['pending_started'] = int(time.time())
        csrf_token()
        response = redirect(url_for('mfa'))
        response.delete_cookie('techstore_access')
        return response

    def pending_user():
        user_id = session.get('pending_user_id')
        started = session.get('pending_started', 0)
        if not user_id or int(time.time()) - started > 300:
            session.clear()
            abort(401, 'MFA session expired')
        user = get_user(user_id)
        if not user or user['locked_until'] > int(time.time()):
            session.clear()
            abort(401)
        return user

    def verify_totp(user, code):
        if not re.fullmatch(r'\d{6}', code or ''):
            return None
        secret = fernet.decrypt(user['totp_secret_encrypted'].encode()).decode()
        current = int(time.time() // 30)
        totp = pyotp.TOTP(secret)
        for counter in (current - 1, current, current + 1):
            if counter > user['last_totp_counter'] and totp.verify(code, for_time=counter * 30):
                return counter
        return None

    @app.route('/')
    def index():
        return redirect(url_for('dashboard' if authenticated_user() else 'login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            name = request.form.get('full_name', '').strip()
            password = request.form.get('password', '')
            try:
                store_id = int(request.form.get('store_id', ''))
            except ValueError:
                store_id = -1
            if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or len(name) < 2 or not valid_password(password):
                flash('Revisa el correo, nombre y contraseña (8 caracteres, mayúscula, número y símbolo).', 'error')
            elif not db().execute('SELECT id FROM stores WHERE id=?', (store_id,)).fetchone():
                flash('Tienda inválida.', 'error')
            else:
                try:
                    cursor = db().execute(
                        'INSERT INTO users (email, full_name, password_hash, role, store_id, totp_secret_encrypted) '
                        'VALUES (?, ?, ?, ?, ?, ?)',
                        (email, name, generate_password_hash(password), 'sales', store_id,
                         fernet.encrypt(pyotp.random_base32().encode()).decode()),
                    )
                    db().commit()
                    flash('Cuenta creada como empleado de ventas. Configura tu segundo factor.', 'success')
                    return begin_mfa(get_user(cursor.lastrowid))
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash('No se pudo registrar el correo.', 'error')
        return render_template('register.html', stores=stores())

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            user = db().execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            if user and user['locked_until'] and user['locked_until'] <= int(time.time()):
                db().execute('UPDATE users SET password_failures=0, mfa_failures=0, locked_until=0 WHERE id=?',
                             (user['id'],))
                db().commit()
                user = get_user(user['id'])
            if user and user['locked_until'] > int(time.time()):
                flash('Cuenta bloqueada temporalmente. Intenta más tarde.', 'error')
            elif not user or not check_password_hash(user['password_hash'], password):
                if user:
                    attempts = user['password_failures'] + 1
                    lock = int(time.time()) + LOCK_SECONDS if attempts >= 5 else 0
                    db().execute('UPDATE users SET password_failures=?, locked_until=? WHERE id=?',
                                 (attempts, lock, user['id']))
                    db().commit()
                flash('Credenciales inválidas.', 'error')
            else:
                db().execute('UPDATE users SET password_failures=0 WHERE id=?', (user['id'],))
                db().commit()
                return begin_mfa(user)
        return render_template('login.html', providers=providers)

    @app.route('/mfa', methods=['GET', 'POST'])
    def mfa():
        user = pending_user()
        if request.method == 'POST':
            counter = verify_totp(user, request.form.get('code', '').strip())
            if counter is None:
                failures = user['mfa_failures'] + 1
                lock = int(time.time()) + LOCK_SECONDS if failures >= 3 else 0
                db().execute('UPDATE users SET mfa_failures=?, locked_until=? WHERE id=?',
                             (failures, lock, user['id']))
                db().commit()
                if failures >= 3:
                    session.clear()
                    flash('Tres códigos incorrectos. Cuenta bloqueada temporalmente.', 'error')
                    return redirect(url_for('login'))
                flash(f'Código inválido. Quedan {3 - failures} intentos.', 'error')
            else:
                db().execute(
                    'UPDATE users SET last_totp_counter=?, totp_enabled=1, mfa_failures=0 WHERE id=?',
                    (counter, user['id']),
                )
                db().commit()
                token = issue_jwt(get_user(user['id']))
                session.clear()
                csrf_token()
                response = redirect(url_for('dashboard'))
                response.set_cookie(
                    'techstore_access', token, max_age=1800, httponly=True,
                    secure=app.config['SESSION_COOKIE_SECURE'], samesite='Lax',
                )
                return response
        qr = None
        if not user['totp_enabled']:
            secret = fernet.decrypt(user['totp_secret_encrypted'].encode()).decode()
            uri = pyotp.TOTP(secret).provisioning_uri(user['email'], issuer_name='TechStore Lab08')
            image = qrcode.make(uri)
            buffer = io.BytesIO()
            image.save(buffer, format='PNG')
            qr = base64.b64encode(buffer.getvalue()).decode()
        return render_template('mfa.html', user=user, qr=qr)

    @app.post('/logout')
    def logout():
        user = authenticated_user()
        if user:
            db().execute('UPDATE users SET token_version=token_version+1 WHERE id=?', (user['id'],))
            db().commit()
        session.clear()
        response = redirect(url_for('login'))
        response.delete_cookie('techstore_access')
        return response

    @app.route('/dashboard')
    def dashboard():
        user = html_user()
        products = visible_products(user)
        summary = None
        if can(user, 'report'):
            if user['role'] == 'manager':
                summary = db().execute('SELECT COUNT(*) AS items, COALESCE(SUM(stock),0) AS units FROM products WHERE store_id=?',
                                       (user['store_id'],)).fetchone()
            else:
                summary = db().execute('SELECT COUNT(*) AS items, COALESCE(SUM(stock),0) AS units FROM products').fetchone()
        links = {row['provider']: dict(row) for row in db().execute(
            'SELECT provider, provider_email, provider_username FROM oauth_links WHERE user_id=?', (user['id'],))}
        return render_template('dashboard.html', user=user, products=products, stores=stores(),
                               can=can, summary=summary, providers=providers, links=links)

    @app.post('/products')
    def create_product_form():
        user = html_user()
        try:
            store_id = int(request.form.get('store_id', ''))
            stock = int(request.form.get('stock', ''))
            price_cents = int(request.form.get('price_cents', ''))
        except ValueError:
            abort(400)
        if not can(user, 'create', store_id=store_id):
            abort(403)
        sku, name = request.form.get('sku', '').strip(), request.form.get('name', '').strip()
        if not sku or not name or stock < 0 or price_cents < 0:
            abort(400)
        try:
            db().execute('INSERT INTO products (sku, name, price_cents, stock, store_id) VALUES (?,?,?,?,?)',
                         (sku, name, price_cents, stock, store_id))
            db().commit()
            flash('Producto creado.', 'success')
        except sqlite3.IntegrityError:
            db().rollback()
            flash('SKU duplicado o tienda inválida.', 'error')
        return redirect(url_for('dashboard'))

    @app.post('/products/<int:product_id>/stock')
    def stock_form(product_id):
        user = html_user()
        product = db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            abort(404)
        if not can(user, 'stock', product):
            abort(403)
        try:
            stock = int(request.form.get('stock', ''))
        except ValueError:
            abort(400)
        if stock < 0:
            abort(400)
        db().execute('UPDATE products SET stock=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (stock, product_id))
        db().commit()
        flash('Stock actualizado.', 'success')
        return redirect(url_for('dashboard'))

    @app.post('/products/<int:product_id>/edit')
    def edit_form(product_id):
        user = html_user()
        product = db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            abort(404)
        if not can(user, 'edit', product):
            abort(403)
        name = request.form.get('name', '').strip()
        try:
            price_cents = int(request.form.get('price_cents', ''))
        except ValueError:
            abort(400)
        if not name or price_cents < 0:
            abort(400)
        db().execute('UPDATE products SET name=?, price_cents=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                     (name, price_cents, product_id))
        db().commit()
        flash('Producto actualizado.', 'success')
        return redirect(url_for('dashboard'))

    @app.post('/products/<int:product_id>/delete')
    def delete_form(product_id):
        user = html_user()
        product = db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            abort(404)
        if not can(user, 'delete', product):
            abort(403)
        db().execute('DELETE FROM products WHERE id=?', (product_id,))
        db().commit()
        flash('Producto eliminado.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/users')
    def users_page():
        user = html_user()
        if user['role'] != 'admin':
            abort(403)
        users = db().execute('SELECT id,email,full_name,role,store_id FROM users ORDER BY id').fetchall()
        return render_template('users.html', users=users, stores=stores(), roles=ROLES)

    @app.post('/users/<int:user_id>')
    def update_user(user_id):
        actor = html_user()
        if actor['role'] != 'admin':
            abort(403)
        target = get_user(user_id)
        if not target:
            abort(404)
        role = request.form.get('role', '')
        if role not in ROLES:
            abort(400)
        try:
            store_id = int(request.form.get('store_id', ''))
        except ValueError:
            abort(400)
        if not db().execute('SELECT id FROM stores WHERE id=?', (store_id,)).fetchone():
            abort(400)
        if target['id'] == actor['id'] and role != 'admin':
            abort(400, 'Do not remove your own admin role')
        db().execute('UPDATE users SET role=?, store_id=?, token_version=token_version+1 WHERE id=?',
                     (role, store_id, user_id))
        db().commit()
        flash('Usuario actualizado. Sus tokens previos se revocaron.', 'success')
        return redirect(url_for('users_page'))

    @app.get('/api/me')
    def api_me():
        return jsonify(public_user(api_user()))

    @app.get('/api/products')
    def api_products():
        user = api_user()
        return jsonify([row_dict(row) for row in visible_products(user)])

    @app.post('/api/products')
    def api_create_product():
        user = api_user()
        data = request.get_json(silent=True) or {}
        try:
            store_id = int(data['store_id'])
            price_cents = int(data['price_cents'])
            stock = int(data['stock'])
            sku, name = str(data['sku']).strip(), str(data['name']).strip()
        except (KeyError, TypeError, ValueError):
            abort(400)
        if not can(user, 'create', store_id=store_id):
            abort(403)
        if not sku or not name or price_cents < 0 or stock < 0:
            abort(400)
        try:
            cursor = db().execute('INSERT INTO products (store_id,sku,name,price_cents,stock) VALUES (?,?,?,?,?)',
                                  (store_id, sku, name, price_cents, stock))
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409)
        return jsonify(row_dict(db().execute('SELECT * FROM products WHERE id=?', (cursor.lastrowid,)).fetchone())), 201

    @app.patch('/api/products/<int:product_id>')
    def api_update_product(product_id):
        user = api_user()
        product = db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            abort(404)
        data = request.get_json(silent=True) or {}
        if not data or set(data) - {'name', 'price_cents', 'stock'}:
            abort(400)
        action = 'edit' if {'name', 'price_cents'} & set(data) else 'stock'
        if not can(user, action, product):
            abort(403)
        try:
            name = str(data.get('name', product['name'])).strip()
            price_cents = int(data.get('price_cents', product['price_cents']))
            stock = int(data.get('stock', product['stock']))
        except (TypeError, ValueError):
            abort(400)
        if not name or price_cents < 0 or stock < 0:
            abort(400)
        db().execute('UPDATE products SET name=?,price_cents=?,stock=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',
                     (name, price_cents, stock, product_id))
        db().commit()
        return jsonify(row_dict(db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()))

    @app.delete('/api/products/<int:product_id>')
    def api_delete_product(product_id):
        user = api_user()
        product = db().execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            abort(404)
        if not can(user, 'delete', product):
            abort(403)
        db().execute('DELETE FROM products WHERE id=?', (product_id,))
        db().commit()
        return '', 204

    @app.get('/api/report')
    def api_report():
        user = api_user()
        if not can(user, 'report'):
            abort(403)
        if user['role'] == 'manager':
            rows = db().execute('SELECT store_id,COUNT(*) AS products,COALESCE(SUM(stock),0) AS units '
                                'FROM products WHERE store_id=? GROUP BY store_id', (user['store_id'],)).fetchall()
        else:
            rows = db().execute('SELECT store_id,COUNT(*) AS products,COALESCE(SUM(stock),0) AS units '
                                'FROM products GROUP BY store_id').fetchall()
        return jsonify([row_dict(row) for row in rows])

    @app.get('/api/token')
    def api_token():
        """Explicit token reveal for a logged-in browser session, used only for API demos."""
        user = html_user()
        return jsonify({'access_token': issue_jwt(user), 'token_type': 'Bearer', 'expires_in': 1800})

    @app.get('/oauth/<provider>/start')
    def oauth_start(provider):
        if provider not in providers:
            abort(404)
        callback = app.config['BASE_URL'] + url_for('oauth_callback', provider=provider)
        response = providers[provider].authorize_redirect(callback)
        state = parse_qs(urlparse(response.location).query).get('state', [None])[0]
        if not state:
            abort(500)
        session[f'oauth_mode_{state}'] = 'login'
        return response

    @app.get('/oauth/<provider>/link')
    def oauth_link(provider):
        if provider not in providers:
            abort(404)
        html_user()
        callback = app.config['BASE_URL'] + url_for('oauth_callback', provider=provider)
        response = providers[provider].authorize_redirect(callback)
        state = parse_qs(urlparse(response.location).query).get('state', [None])[0]
        if not state:
            abort(500)
        session[f'oauth_mode_{state}'] = 'link'
        return response

    @app.get('/oauth/<provider>/callback')
    def oauth_callback(provider):
        if provider not in providers:
            abort(404)
        state = request.args.get('state', '')
        mode = session.pop(f'oauth_mode_{state}', None) if state else None
        if mode not in ('login', 'link', 'replace'):
            abort(400)
        try:
            provider_username = None
            token = providers[provider].authorize_access_token()
            if provider == 'google':
                info = token.get('userinfo') or providers[provider].parse_id_token(token)
                subject = str(info['sub'])
                provider_email = info.get('email') if info.get('email_verified') is True else None
            else:
                response = providers[provider].get('user', token=token)
                response.raise_for_status()
                info = response.json()
                subject = str(info['id'])
                provider_username = info['login']
                provider_email = None
        except Exception:
            app.logger.exception('OAuth callback failed for %s', provider)
            abort(400, 'OAuth verification failed')
        existing = db().execute('SELECT user_id FROM oauth_links WHERE provider=? AND provider_subject=?',
                                (provider, subject)).fetchone()
        if mode in ('link', 'replace'):
            user = html_user()
            if existing and existing['user_id'] != user['id']:
                abort(409, 'Identity linked to another account')
            previous = db().execute('SELECT provider_subject FROM oauth_links WHERE user_id=? AND provider=?',
                                    (user['id'], provider)).fetchone()
            if mode == 'link' and previous and previous['provider_subject'] != subject:
                flash('Ya tienes otra cuenta vinculada. Usa Cambiar cuenta Google para reemplazarla.', 'error')
                return redirect(url_for('dashboard'))
            try:
                db().execute('INSERT INTO oauth_links (user_id,provider,provider_subject,provider_email,provider_username) VALUES (?,?,?,?,?) '
                             'ON CONFLICT(user_id,provider) DO UPDATE SET provider_subject=excluded.provider_subject, '
                             'provider_email=excluded.provider_email, provider_username=excluded.provider_username',
                             (user['id'], provider, subject, provider_email, provider_username))
                db().commit()
            except sqlite3.IntegrityError:
                db().rollback()
                abort(409, 'Account already linked to a different identity')
            flash(f'Cuenta {provider} vinculada' + (f': {provider_email}.' if provider_email else '.'), 'success')
            return redirect(url_for('dashboard'))
        if not existing:
            flash('Primero inicia sesión con contraseña y MFA; luego vincula esta cuenta social.', 'error')
            return redirect(url_for('login'))
        user = get_user(existing['user_id'])
        if not user or user['locked_until'] > int(time.time()):
            abort(401)
        if provider == 'github':
            db().execute('UPDATE oauth_links SET provider_username=? WHERE provider=? AND provider_subject=?',
                         (provider_username, provider, subject))
            db().commit()
        return begin_mfa(user)

    @app.post('/oauth/google/replace')
    def replace_google():
        html_user()
        if 'google' not in providers:
            abort(404)
        callback = app.config['BASE_URL'] + url_for('oauth_callback', provider='google')
        response = providers['google'].authorize_redirect(callback, prompt='select_account')
        state = parse_qs(urlparse(response.location).query).get('state', [None])[0]
        if not state:
            abort(500)
        session[f'oauth_mode_{state}'] = 'replace'
        return response

    @app.cli.command('bootstrap-admin')
    @click.option('--email', prompt=True)
    @click.option('--name', prompt=True)
    def bootstrap_admin(email, name):
        """Create the first administrator; password is read without terminal echo."""
        email = email.strip().lower()
        name = name.strip()
        password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
        if not valid_password(password):
            raise click.ClickException('Password needs 8+ chars, uppercase, number and special character')
        if db().execute('SELECT id FROM users WHERE role="admin"').fetchone():
            raise click.ClickException('An administrator already exists')
        db().execute(
            'INSERT INTO users (email,full_name,password_hash,role,store_id,totp_secret_encrypted) VALUES (?,?,?,?,?,?)',
            (email, name, generate_password_hash(password), 'admin', 1,
             fernet.encrypt(pyotp.random_base32().encode()).decode()),
        )
        db().commit()
        click.echo('Administrator created. Sign in and enroll TOTP before accessing the app.')

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=8088, debug=False)
