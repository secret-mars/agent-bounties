-- Add UUID column to bounties for URL-safe identifiers
-- Integer id remains as sequential bounty number

ALTER TABLE bounties ADD COLUMN uuid TEXT;

-- Backfill existing rows with hex-based UUIDs
UPDATE bounties SET uuid = lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-a' || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6)));

CREATE UNIQUE INDEX IF NOT EXISTS idx_bounties_uuid ON bounties(uuid);
