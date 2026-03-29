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

-- =============================================================
--  Events System
-- =============================================================

-- Events table
CREATE TABLE IF NOT EXISTS events (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  organiser_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name           TEXT    NOT NULL,
  description    TEXT    DEFAULT '',
  pairing_system TEXT    NOT NULL DEFAULT 'swiss',  -- swiss, round_robin, elimination, manual
  total_rounds   INTEGER NOT NULL DEFAULT 3,
  current_round  INTEGER NOT NULL DEFAULT 0,        -- 0 = not started
  points_limit   INTEGER NOT NULL DEFAULT 0,        -- 0 = no limit
  max_participants INTEGER NOT NULL DEFAULT 0,      -- 0 = no limit
  status         TEXT    NOT NULL DEFAULT 'open',   -- open, active, complete
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Event participants
CREATE TABLE IF NOT EXISTS event_participants (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username   TEXT    NOT NULL,
  faction    TEXT    DEFAULT '',
  army_name  TEXT    DEFAULT '',
  units      TEXT    DEFAULT '[]',  -- JSON array of unit objects
  wins       INTEGER NOT NULL DEFAULT 0,
  losses     INTEGER NOT NULL DEFAULT 0,
  draws      INTEGER NOT NULL DEFAULT 0,
  points     INTEGER NOT NULL DEFAULT 0,  -- tournament points (3W/1D/0L)
  joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(event_id, user_id)
);

-- Event pairings (one row per game per round)
CREATE TABLE IF NOT EXISTS event_pairings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  round         INTEGER NOT NULL,
  player1_id    INTEGER NOT NULL REFERENCES users(id),
  player2_id    INTEGER,                              -- NULL = bye
  player1_name  TEXT    NOT NULL,
  player2_name  TEXT    DEFAULT 'BYE',
  result        TEXT    DEFAULT NULL,                 -- 'player1','player2','draw',NULL=pending
  player1_submitted TEXT DEFAULT NULL,               -- submitted result from p1
  player2_submitted TEXT DEFAULT NULL,               -- submitted result from p2
  approved      INTEGER NOT NULL DEFAULT 0,          -- 0=pending, 1=approved
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_organiser   ON events(organiser_id);
CREATE INDEX IF NOT EXISTS idx_participants_event ON event_participants(event_id);
CREATE INDEX IF NOT EXISTS idx_pairings_event     ON event_pairings(event_id);

-- =============================================================
--  Visitor counter
-- =============================================================
CREATE TABLE IF NOT EXISTS visitors (
  visitor_id TEXT PRIMARY KEY,           -- random ID stored in browser localStorage
  first_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
