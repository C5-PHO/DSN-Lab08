CREATE TABLE IF NOT EXISTS stores (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'sales', 'auditor')),
  store_id INTEGER REFERENCES stores(id),
  totp_secret_encrypted TEXT NOT NULL,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  last_totp_counter INTEGER NOT NULL DEFAULT -1,
  password_failures INTEGER NOT NULL DEFAULT 0,
  mfa_failures INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
  stock INTEGER NOT NULL CHECK (stock >= 0),
  store_id INTEGER NOT NULL REFERENCES stores(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (store_id, sku)
);

CREATE TABLE IF NOT EXISTS oauth_links (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('google', 'github')),
  provider_subject TEXT NOT NULL,
  UNIQUE (provider, provider_subject),
  UNIQUE (user_id, provider)
);

INSERT OR IGNORE INTO stores (id, name) VALUES (1, 'Tienda Lima Centro');
INSERT OR IGNORE INTO stores (id, name) VALUES (2, 'Tienda Miraflores');
