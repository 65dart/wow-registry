-- Add battle points columns to event_pairings
ALTER TABLE event_pairings ADD COLUMN player1_points INTEGER DEFAULT NULL;
ALTER TABLE event_pairings ADD COLUMN player2_points INTEGER DEFAULT NULL;
ALTER TABLE event_participants ADD COLUMN battle_points INTEGER NOT NULL DEFAULT 0;
