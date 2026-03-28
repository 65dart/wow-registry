-- =============================================================
--  Warhammer Old World Registry — D1 Database Schema
--  Run with: wrangler d1 execute wow-registry --file=schema.sql --remote
-- =============================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
  email      TEXT    UNIQUE NOT NULL COLLATE NOCASE,
  password   TEXT    NOT NULL,  -- bcrypt hash
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Sessions table (token-based, stored in browser localStorage)
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT    PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT    NOT NULL
);

-- Armies table (each row is one army record belonging to a user)
CREATE TABLE IF NOT EXISTS armies (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  data       TEXT    NOT NULL,  -- full army JSON blob
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_armies_user    ON armies(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);

-- =============================================================
--  Seed admin accounts (password: BattleMarch)
--  Change these passwords after first login!
-- =============================================================
INSERT OR IGNORE INTO users (username, email, password) VALUES
  ('admin',         'admin@wowregistry.com',         'pbkdf2:2e0c7e425a30bade071e7ec60b3b5077:fbb9e4db5870b61f626608c6549ccb67100d9eb98ce17784b18920395c4220c6'),
  ('Admin',         'admin2@wowregistry.com',         'pbkdf2:1fe224ced72d52a92856b5cf1a501b54:0a51daeebcb0d00b04e5fbeea20845d51be4de55478f17cae0bf5729af5eda4b'),
  ('administrator', 'administrator@wowregistry.com',  'pbkdf2:ee1b5cb2f29e68ab529669d61e49f14a:3047bcadc63bec5082c02233a726209f9c747314f467de9102ef1bf072d741d1'),
  ('Administrator', 'administrator2@wowregistry.com', 'pbkdf2:3ad0c52ea2c13b9facedc433b329b171:13639884b779773fe5379df314a0d4a113eaead50f25e037efdb5dc9b1434bbd');

-- Moderator accounts (password: BattleMarch)
INSERT OR IGNORE INTO users (username, email, password) VALUES
  ('Mod',       'mod@wowregistry.com',       'pbkdf2:352e38074a2823ca2c5572d0e8725441:1db9bcab0af565899eb556d5304f09792318d0ed3ae5895807a5f4460dbb17aa'),
  ('mod',       'mod2@wowregistry.com',       'pbkdf2:91f4f27246db1ced848ea796ace4522a:fdabf617b8a176fb02cb5e42d87327496cfed1c13865e394909b2246fb05b18e'),
  ('Moderator', 'moderator@wowregistry.com',  'pbkdf2:6503263c16ab86dd1b11dec7601f6c66:5851ff3ab4f4d65629543ed1f9f8d706d71ecdb8985005dff94a667a583c3e18'),
  ('moderator', 'moderator2@wowregistry.com', 'pbkdf2:6c45b1cfcc4b6b3bb8e40f86ee978840:9ea4b890613dd952a58101dcbf649cd5e885ea0e7150863ce206753d8be720f4');
