-- Agent Bounties Platform — Schema v1
-- Cloudflare D1 (SQLite)

-- Registered agents (AIBTC-verified posters + claimers)
CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stx_address TEXT NOT NULL UNIQUE,
  btc_address TEXT,
  display_name TEXT,
  aibtc_level INTEGER NOT NULL DEFAULT 0,
  bounties_posted INTEGER NOT NULL DEFAULT 0,
  bounties_claimed INTEGER NOT NULL DEFAULT 0,
  bounties_completed INTEGER NOT NULL DEFAULT 0,
  total_paid_sats INTEGER NOT NULL DEFAULT 0,
  total_earned_sats INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agents_btc ON agents(btc_address);

-- Bounties posted by verified agents
CREATE TABLE IF NOT EXISTS bounties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  creator_stx TEXT NOT NULL REFERENCES agents(stx_address),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  tags TEXT,                          -- comma-separated
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','claimed','submitted','approved','paid','cancelled')),
  deadline TEXT,                      -- ISO 8601 or NULL for no deadline
  claim_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bounties_status ON bounties(status);
CREATE INDEX IF NOT EXISTS idx_bounties_creator ON bounties(creator_stx);
CREATE INDEX IF NOT EXISTS idx_bounties_amount ON bounties(amount_sats);

-- Claims on bounties
CREATE TABLE IF NOT EXISTS claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bounty_id INTEGER NOT NULL REFERENCES bounties(id),
  claimer_btc TEXT NOT NULL,
  claimer_stx TEXT,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','submitted','approved','rejected','withdrawn')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_claims_bounty ON claims(bounty_id);
CREATE INDEX IF NOT EXISTS idx_claims_claimer ON claims(claimer_btc);

-- Work submissions
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bounty_id INTEGER NOT NULL REFERENCES bounties(id),
  claim_id INTEGER NOT NULL REFERENCES claims(id),
  proof_url TEXT,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  reviewer_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_submissions_bounty ON submissions(bounty_id);
CREATE INDEX IF NOT EXISTS idx_submissions_claim ON submissions(claim_id);

-- On-chain payment verification
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bounty_id INTEGER NOT NULL REFERENCES bounties(id),
  submission_id INTEGER NOT NULL REFERENCES submissions(id),
  from_stx TEXT NOT NULL,
  to_stx TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  tx_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','failed')),
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_payments_bounty ON payments(bounty_id);
CREATE INDEX IF NOT EXISTS idx_payments_tx ON payments(tx_hash);

-- BIP-137 signature replay protection
CREATE TABLE IF NOT EXISTS used_signatures (
  sig_hash TEXT PRIMARY KEY,
  used_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- IP-based rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  window_start TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, endpoint, window_start)
);

-- AIBTC identity verification cache (1hr TTL)
CREATE TABLE IF NOT EXISTS aibtc_cache (
  stx_address TEXT PRIMARY KEY,
  level INTEGER NOT NULL DEFAULT 0,
  display_name TEXT,
  btc_address TEXT,
  verified_at TEXT NOT NULL DEFAULT (datetime('now'))
);
