-- Remove foreign key constraint from event_pairings player1_id/player2_id
-- They now reference event_participants.id instead of users.id

PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS event_pairings_new (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  round         INTEGER NOT NULL,
  player1_id    INTEGER NOT NULL,
  player2_id    INTEGER,
  player1_name  TEXT    NOT NULL,
  player2_name  TEXT    DEFAULT 'BYE',
  result        TEXT    DEFAULT NULL,
  player1_submitted TEXT DEFAULT NULL,
  player2_submitted TEXT DEFAULT NULL,
  approved      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO event_pairings_new
  SELECT id, event_id, round, player1_id, player2_id, player1_name,
         player2_name, result, player1_submitted, player2_submitted,
         approved, created_at
  FROM event_pairings;

DROP TABLE event_pairings;
ALTER TABLE event_pairings_new RENAME TO event_pairings;

CREATE INDEX IF NOT EXISTS idx_pairings_event ON event_pairings(event_id);

PRAGMA foreign_keys=ON;
