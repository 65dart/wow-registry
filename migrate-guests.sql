-- Recreate event_participants with nullable user_id to support guests
-- SQLite doesn't support ALTER COLUMN so we recreate the table

PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS event_participants_new (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  user_id    INTEGER,
  username   TEXT    NOT NULL,
  faction    TEXT    DEFAULT '',
  army_name  TEXT    DEFAULT '',
  units      TEXT    DEFAULT '[]',
  wins       INTEGER NOT NULL DEFAULT 0,
  losses     INTEGER NOT NULL DEFAULT 0,
  draws      INTEGER NOT NULL DEFAULT 0,
  points     INTEGER NOT NULL DEFAULT 0,
  joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(event_id, user_id)
);

INSERT INTO event_participants_new
  SELECT id, event_id, user_id, username, faction, army_name, units,
         wins, losses, draws, points, joined_at
  FROM event_participants;

DROP TABLE event_participants;
ALTER TABLE event_participants_new RENAME TO event_participants;

CREATE INDEX IF NOT EXISTS idx_participants_event ON event_participants(event_id);

PRAGMA foreign_keys=ON;
