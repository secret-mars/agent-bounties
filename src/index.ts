// Agent Bounties Platform — Cloudflare Workers + D1
// AIBTC-verified agents post bounties, anyone can claim and complete them.
// Payment is direct sBTC transfer, verified on-chain via Hiro API.

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

interface Env {
  DB: D1Database;
}

// ─── CORS ────────────────────────────────────────────────────────────────────

const WRITE_ALLOWED_ORIGINS: readonly string[] = [
  'https://bounty.drx4.xyz',
];

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function resolveCorsOrigin(requestOrigin: string | null, isWrite: boolean): string | null {
  if (!isWrite) return '*';
  if (!requestOrigin) return null;
  if ((WRITE_ALLOWED_ORIGINS as string[]).includes(requestOrigin)) return requestOrigin;
  if (/^https?:\/\/localhost(:\d+)?$/.test(requestOrigin)) return requestOrigin;
  if (/^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(requestOrigin)) return requestOrigin;
  return null;
}

function corsHeaders(origin: string, vary = false): HeadersInit {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (vary) headers['Vary'] = 'Origin';
  return headers;
}

function json(data: unknown, status = 200, corsOrigin: string | null = '*'): Response {
  if (corsOrigin === null) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const vary = corsOrigin !== '*';
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(corsOrigin, vary) },
  });
}

// ─── Input Validation ────────────────────────────────────────────────────────

function isValidBtcAddress(addr: string): boolean {
  if (addr.startsWith('bc1') || addr.startsWith('BC1')) {
    if (addr !== addr.toLowerCase()) return false;
    return /^bc1[a-z0-9]{6,87}$/.test(addr);
  }
  return /^[13][a-zA-HJ-NP-Z0-9]{25,34}$/.test(addr);
}

function isValidStxAddress(addr: string): boolean {
  return /^(SP|SM)[A-Z0-9]{38}$/.test(addr);
}

function isValidTxHash(hash: string): boolean {
  return /^(0x)?[a-f0-9]{64}$/.test(hash);
}

function normalizeTxHash(hash: string): string {
  return hash.startsWith('0x') ? hash.slice(2) : hash;
}

const MAX_TITLE = 200;
const MAX_DESCRIPTION = 2000;
const MAX_TAGS = 500;
const MAX_MESSAGE = 1000;
const MAX_PROOF_URL = 500;
const MAX_REVIEWER_NOTES = 1000;

const MAX_BODY_SIZE = 1024 * 1024; // 1MB
const TOO_LARGE_RESPONSE = JSON.stringify({ error: 'Request body too large' });

async function readBodyWithSizeCheck(request: Request): Promise<{ error: Response } | { text: string }> {
  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader !== null) {
    const declared = parseInt(contentLengthHeader, 10);
    if (!isNaN(declared) && declared > MAX_BODY_SIZE) {
      return { error: new Response(TOO_LARGE_RESPONSE, {
        status: 413,
        headers: { 'Content-Type': 'application/json' }
      }) };
    }
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_SIZE) {
    return { error: new Response(TOO_LARGE_RESPONSE, {
      status: 413,
      headers: { 'Content-Type': 'application/json' }
    }) };
  }
  return { text };
}

// ─── D1 Helper ───────────────────────────────────────────────────────────────

async function dbRun(stmt: D1PreparedStatement): Promise<D1Result> {
  const result = await stmt.run();
  if (!result.success) {
    throw new Error('Database operation failed');
  }
  return result;
}

// ─── BIP-137 Signature Verification ─────────────────────────────────────────

function encodeVarint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) { const b = new Uint8Array(3); b[0] = 0xfd; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; return b; }
  const b = new Uint8Array(5); b[0] = 0xfe; for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff; return b;
}

function bitcoinMessageHash(message: string): Uint8Array {
  const prefix = '\x18Bitcoin Signed Message:\n';
  const prefixBytes = new TextEncoder().encode(prefix);
  const msgBytes = new TextEncoder().encode(message);
  const msgLen = encodeVarint(msgBytes.length);
  const buf = new Uint8Array(prefixBytes.length + msgLen.length + msgBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(msgLen, prefixBytes.length);
  buf.set(msgBytes, prefixBytes.length + msgLen.length);
  return sha256(sha256(buf));
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32Encode(hrp: string, data: number[]): string {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const expand = [...Array.from(hrp, c => c.charCodeAt(0) >> 5), 0, ...Array.from(hrp, c => c.charCodeAt(0) & 31)];
  const values = [...expand, ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0, bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function pubkeyToBech32(pubkey: Uint8Array): string {
  const hash = ripemd160(sha256(pubkey));
  const words = [0, ...convertBits(hash, 8, 5, true)];
  return bech32Encode('bc', words);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58CheckEncode(version: number, payload: Uint8Array): string {
  const data = new Uint8Array(1 + payload.length + 4);
  data[0] = version;
  data.set(payload, 1);
  const checksum = sha256(sha256(data.subarray(0, 1 + payload.length)));
  data.set(checksum.subarray(0, 4), 1 + payload.length);
  let num = 0n;
  for (const byte of data) num = num * 256n + BigInt(byte);
  let encoded = '';
  while (num > 0n) {
    encoded = BASE58_ALPHABET[Number(num % 58n)] + encoded;
    num = num / 58n;
  }
  for (const byte of data) {
    if (byte !== 0) break;
    encoded = '1' + encoded;
  }
  return encoded;
}

function pubkeyToP2PKH(pubkey: Uint8Array): string {
  const hash = ripemd160(sha256(pubkey));
  return base58CheckEncode(0x00, hash);
}

function pubkeyToP2SH_P2WPKH(pubkey: Uint8Array): string {
  const keyHash = ripemd160(sha256(pubkey));
  const redeemScript = new Uint8Array(22);
  redeemScript[0] = 0x00;
  redeemScript[1] = 0x14;
  redeemScript.set(keyHash, 2);
  const scriptHash = ripemd160(sha256(redeemScript));
  return base58CheckEncode(0x05, scriptHash);
}

function deriveAddress(pubkey: Uint8Array, header: number): string {
  if (header >= 39) return pubkeyToBech32(pubkey);
  if (header >= 35) return pubkeyToP2SH_P2WPKH(pubkey);
  return pubkeyToP2PKH(pubkey);
}

async function verifyBip137(signature: string, message: string, expectedAddress: string): Promise<string | null> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  } catch { return 'Invalid signature: not valid base64'; }

  if (sigBytes.length !== 65) return `Invalid signature: expected 65 bytes, got ${sigBytes.length}`;

  const header = sigBytes[0];
  if (header < 27 || header > 42) return `Invalid signature header byte: ${header}`;

  const recoveryId = (header - 27) & 3;
  const compressed = header >= 31;

  const r = sigBytes.slice(1, 33);
  const s = sigBytes.slice(33, 65);
  const sig = new secp.Signature(
    BigInt('0x' + Array.from(r, b => b.toString(16).padStart(2, '0')).join('')),
    BigInt('0x' + Array.from(s, b => b.toString(16).padStart(2, '0')).join(''))
  ).addRecoveryBit(recoveryId);

  const msgHash = bitcoinMessageHash(message);

  let pubkey: Uint8Array;
  try {
    const point = sig.recoverPublicKey(msgHash);
    pubkey = point.toRawBytes(compressed);
  } catch { return 'Signature recovery failed: invalid signature for this message'; }

  const derivedAddress = deriveAddress(pubkey, header).toLowerCase();
  const expectedAddressNorm = expectedAddress.toLowerCase();
  if (derivedAddress !== expectedAddressNorm) {
    return `Signature mismatch: recovered ${derivedAddress}, expected ${expectedAddressNorm}`;
  }

  return null;
}

// ─── Signature Replay Protection ─────────────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}

async function recordSignatureUse(db: D1Database, sigHash: string): Promise<string | null> {
  const result = await db
    .prepare('INSERT OR IGNORE INTO used_signatures (sig_hash) VALUES (?)')
    .bind(sigHash)
    .run();
  if (result.meta.rows_written === 0) {
    return 'Signature already used — replay detected';
  }
  return null;
}

async function cleanupExpiredSignatures(db: D1Database): Promise<void> {
  await db
    .prepare("DELETE FROM used_signatures WHERE used_at < datetime('now', '-1 day')")
    .run();
}

// ─── IP-Based Rate Limiting ──────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_SECONDS = 300;
const RATE_LIMIT_MAX_REQUESTS = 10;

function getClientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ?? 'unknown';
}

function endpointKey(pathname: string): string {
  const parts = pathname.split('/').filter(Boolean);
  return '/' + parts.slice(0, 2).join('/');
}

async function checkRateLimit(db: D1Database, request: Request): Promise<Response | null> {
  const ip = getClientIp(request);
  const endpoint = endpointKey(new URL(request.url).pathname);
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % RATE_LIMIT_WINDOW_SECONDS);
  const windowStartIso = new Date(windowStart * 1000).toISOString();

  await db
    .prepare('DELETE FROM rate_limits WHERE window_start < ?')
    .bind(windowStartIso)
    .run();

  await db
    .prepare(
      `INSERT INTO rate_limits (ip, endpoint, window_start, request_count)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(ip, endpoint, window_start) DO UPDATE
         SET request_count = request_count + 1`
    )
    .bind(ip, endpoint, windowStartIso)
    .run();

  const row = await db
    .prepare('SELECT request_count FROM rate_limits WHERE ip = ? AND endpoint = ? AND window_start = ?')
    .bind(ip, endpoint, windowStartIso)
    .first<{ request_count: number }>();

  const count = row?.request_count ?? 1;
  if (count > RATE_LIMIT_MAX_REQUESTS) {
    const windowEnd = windowStart + RATE_LIMIT_WINDOW_SECONDS;
    const retryAfter = Math.max(0, windowEnd - now);
    return new Response(JSON.stringify({ error: 'Too many requests — try again later' }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
        'X-RateLimit-Limit': String(RATE_LIMIT_MAX_REQUESTS),
        'X-RateLimit-Window': `${RATE_LIMIT_WINDOW_SECONDS}s`,
      },
    });
  }

  return null;
}

async function cleanupExpiredRateLimits(db: D1Database): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const currentWindowStart = now - (now % RATE_LIMIT_WINDOW_SECONDS);
  const currentWindowStartIso = new Date(currentWindowStart * 1000).toISOString();
  await db
    .prepare('DELETE FROM rate_limits WHERE window_start < ?')
    .bind(currentWindowStartIso)
    .run();
}

// ─── AIBTC Identity Verification ─────────────────────────────────────────────

interface AibtcAgent {
  level: number;
  display_name: string | null;
  btc_address: string | null;
}

async function verifyAibtcAgent(db: D1Database, stxAddress: string): Promise<AibtcAgent | null> {
  // Check D1 cache first (1hr TTL)
  const cached = await db
    .prepare("SELECT level, display_name, btc_address, verified_at FROM aibtc_cache WHERE stx_address = ? AND verified_at > datetime('now', '-1 hour')")
    .bind(stxAddress)
    .first<{ level: number; display_name: string | null; btc_address: string | null }>();

  if (cached) {
    return { level: cached.level, display_name: cached.display_name, btc_address: cached.btc_address };
  }

  // Call AIBTC API
  try {
    const resp = await fetch(`https://aibtc.com/api/agent/profile/${stxAddress}`);
    if (!resp.ok) return null;

    const data = await resp.json() as {
      stxAddress?: string;
      btcAddress?: string;
      displayName?: string;
      bnsName?: string;
      level?: number;
    };

    const level = data.level ?? 0;
    const display_name = data.displayName || data.bnsName || null;
    const btc_address = data.btcAddress || null;

    // Cache the result
    await db
      .prepare(
        `INSERT INTO aibtc_cache (stx_address, level, display_name, btc_address, verified_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT(stx_address) DO UPDATE SET
           level = excluded.level,
           display_name = excluded.display_name,
           btc_address = excluded.btc_address,
           verified_at = excluded.verified_at`
      )
      .bind(stxAddress, level, display_name, btc_address)
      .run();

    return { level, display_name, btc_address };
  } catch {
    return null;
  }
}

// ─── On-Chain Payment Verification (sBTC via Hiro API) ───────────────────────

const SBTC_CONTRACT = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token';

interface PaymentVerification {
  verified: boolean;
  error?: string;
  amount_sats?: number;
}

async function verifyPayment(
  txHash: string,
  expectedFrom: string,
  expectedTo: string,
  expectedAmountSats: number
): Promise<PaymentVerification> {
  const normalizedHash = normalizeTxHash(txHash);

  try {
    const resp = await fetch(`https://api.hiro.so/extended/v1/tx/0x${normalizedHash}`);
    if (!resp.ok) {
      return { verified: false, error: `Hiro API returned ${resp.status}` };
    }

    const tx = await resp.json() as {
      tx_status: string;
      tx_type: string;
      sender_address: string;
      contract_call?: {
        contract_id: string;
        function_name: string;
        function_args?: Array<{
          name: string;
          repr: string;
          type: string;
        }>;
      };
    };

    if (tx.tx_status !== 'success') {
      return { verified: false, error: `Transaction status: ${tx.tx_status}` };
    }

    if (tx.tx_type !== 'contract_call') {
      return { verified: false, error: 'Not a contract call transaction' };
    }

    if (tx.contract_call?.contract_id !== SBTC_CONTRACT) {
      return { verified: false, error: `Wrong contract: ${tx.contract_call?.contract_id}` };
    }

    if (tx.contract_call?.function_name !== 'transfer') {
      return { verified: false, error: `Wrong function: ${tx.contract_call?.function_name}` };
    }

    // Verify sender
    if (tx.sender_address !== expectedFrom) {
      return { verified: false, error: `Wrong sender: ${tx.sender_address}, expected ${expectedFrom}` };
    }

    // Parse function args to verify recipient and amount
    const args = tx.contract_call?.function_args;
    if (!args) {
      return { verified: false, error: 'No function args found' };
    }

    // sBTC transfer args: amount, sender, recipient
    const amountArg = args.find(a => a.name === 'amount');
    const recipientArg = args.find(a => a.name === 'recipient');

    if (!amountArg || !recipientArg) {
      return { verified: false, error: 'Missing amount or recipient in function args' };
    }

    // Parse amount from Clarity repr (e.g., "u100000")
    const amountMatch = amountArg.repr.match(/^u(\d+)$/);
    if (!amountMatch) {
      return { verified: false, error: `Cannot parse amount: ${amountArg.repr}` };
    }
    const actualAmount = parseInt(amountMatch[1], 10);

    // Parse recipient from Clarity repr (e.g., "'SP...")
    const recipientMatch = recipientArg.repr.match(/^'?(SP[A-Z0-9]+|SM[A-Z0-9]+)$/);
    if (!recipientMatch) {
      return { verified: false, error: `Cannot parse recipient: ${recipientArg.repr}` };
    }
    const actualRecipient = recipientMatch[1];

    if (actualRecipient !== expectedTo) {
      return { verified: false, error: `Wrong recipient: ${actualRecipient}, expected ${expectedTo}` };
    }

    if (actualAmount < expectedAmountSats) {
      return { verified: false, error: `Insufficient amount: ${actualAmount} < ${expectedAmountSats}` };
    }

    return { verified: true, amount_sats: actualAmount };
  } catch (err: any) {
    return { verified: false, error: `Verification failed: ${err.message}` };
  }
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

// Message format: "agent-bounties | {action} | {btc} | {resource} | {ts}"
interface AuthResult {
  btcAddress: string;
  stxAddress?: string;
  error?: string;
}

async function validateAuth(
  body: any,
  db: D1Database,
  action: string,
  resource: string
): Promise<{ error: string } | { btcAddress: string; stxAddress?: string }> {
  if (!body.btc_address) return { error: 'Required: btc_address' };
  if (!isValidBtcAddress(body.btc_address)) return { error: 'Invalid btc_address' };
  if (body.stx_address && !isValidStxAddress(body.stx_address)) return { error: 'Invalid stx_address' };
  if (!body.signature) return { error: 'Required: signature (BIP-137)' };
  if (!body.timestamp) return { error: 'Required: timestamp (ISO 8601)' };

  if (typeof body.signature !== 'string' || body.signature.length < 80 || body.signature.length > 100) {
    return { error: 'Invalid signature format (expected base64 BIP-137, ~88 chars)' };
  }

  const ts = new Date(body.timestamp).getTime();
  if (isNaN(ts)) return { error: 'Invalid timestamp format' };
  const drift = Math.abs(Date.now() - ts);
  if (drift > 300_000) return { error: 'Timestamp expired (must be within 300 seconds)' };

  const expectedMessage = `agent-bounties | ${action} | ${body.btc_address} | ${resource} | ${body.timestamp}`;
  const sigErr = await verifyBip137(body.signature, expectedMessage, body.btc_address);
  if (sigErr) return { error: sigErr };

  // Replay protection
  await cleanupExpiredSignatures(db);
  const replayErr = await recordSignatureUse(db, await sha256Hex(body.signature));
  if (replayErr) return { error: replayErr };

  return { btcAddress: body.btc_address, stxAddress: body.stx_address };
}

// ─── Ensure Agent Row ────────────────────────────────────────────────────────

async function ensureAgent(db: D1Database, stxAddress: string, btcAddress?: string, displayName?: string, level?: number) {
  await dbRun(db
    .prepare(
      `INSERT INTO agents (stx_address, btc_address, display_name, aibtc_level) VALUES (?, ?, ?, ?)
       ON CONFLICT(stx_address) DO UPDATE SET
         btc_address = COALESCE(excluded.btc_address, agents.btc_address),
         display_name = COALESCE(excluded.display_name, agents.display_name),
         aibtc_level = CASE WHEN excluded.aibtc_level > agents.aibtc_level THEN excluded.aibtc_level ELSE agents.aibtc_level END,
         updated_at = datetime('now')`
    )
    .bind(stxAddress, btcAddress || null, displayName || null, level ?? 0)
  );
}

// ─── Route Handlers ──────────────────────────────────────────────────────────

// GET /api/bounties — List bounties with optional filters
async function handleListBounties(url: URL, db: D1Database, corsOrigin: string): Promise<Response> {
  const status = url.searchParams.get('status') || 'open';
  const tags = url.searchParams.get('tags');
  const creator = url.searchParams.get('creator');
  const minAmount = url.searchParams.get('min_amount');
  const maxAmount = url.searchParams.get('max_amount');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);

  let query = 'SELECT b.*, a.display_name as creator_name FROM bounties b LEFT JOIN agents a ON b.creator_stx = a.stx_address WHERE 1=1';
  const params: any[] = [];

  if (status !== 'all') {
    query += ' AND b.status = ?';
    params.push(status);
  }

  if (creator) {
    query += ' AND b.creator_stx = ?';
    params.push(creator);
  }

  if (tags) {
    query += ' AND b.tags LIKE ?';
    params.push(`%${tags}%`);
  }

  if (minAmount) {
    query += ' AND b.amount_sats >= ?';
    params.push(parseInt(minAmount, 10));
  }

  if (maxAmount) {
    query += ' AND b.amount_sats <= ?';
    params.push(parseInt(maxAmount, 10));
  }

  query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const result = await db.prepare(query).bind(...params).all();

  // Get total count for pagination
  let countQuery = 'SELECT COUNT(*) as total FROM bounties WHERE 1=1';
  const countParams: any[] = [];
  if (status !== 'all') { countQuery += ' AND status = ?'; countParams.push(status); }
  if (creator) { countQuery += ' AND creator_stx = ?'; countParams.push(creator); }
  if (tags) { countQuery += ' AND tags LIKE ?'; countParams.push(`%${tags}%`); }
  if (minAmount) { countQuery += ' AND amount_sats >= ?'; countParams.push(parseInt(minAmount, 10)); }
  if (maxAmount) { countQuery += ' AND amount_sats <= ?'; countParams.push(parseInt(maxAmount, 10)); }

  const countResult = await db.prepare(countQuery).bind(...countParams).first<{ total: number }>();

  return json({
    bounties: result.results,
    pagination: {
      total: countResult?.total ?? 0,
      limit,
      offset,
      hasMore: offset + limit < (countResult?.total ?? 0),
    }
  }, 200, corsOrigin);
}

// GET /api/bounties/:id — Bounty detail with claims, submissions, payments
async function handleGetBounty(id: string, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const bounty = await db
    .prepare('SELECT b.*, a.display_name as creator_name FROM bounties b LEFT JOIN agents a ON b.creator_stx = a.stx_address WHERE b.id = ?')
    .bind(bountyId)
    .first();

  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);

  const claims = await db
    .prepare('SELECT * FROM claims WHERE bounty_id = ? ORDER BY created_at DESC')
    .bind(bountyId)
    .all();

  const submissions = await db
    .prepare('SELECT * FROM submissions WHERE bounty_id = ? ORDER BY created_at DESC')
    .bind(bountyId)
    .all();

  const payments = await db
    .prepare('SELECT * FROM payments WHERE bounty_id = ? ORDER BY created_at DESC')
    .bind(bountyId)
    .all();

  return json({
    bounty,
    claims: claims.results,
    submissions: submissions.results,
    payments: payments.results,
  }, 200, corsOrigin);
}

// GET /api/agents/:address — Agent profile + stats
async function handleGetAgent(address: string, db: D1Database, corsOrigin: string): Promise<Response> {
  // Look up by STX or BTC address
  let agent;
  if (isValidStxAddress(address)) {
    agent = await db.prepare('SELECT * FROM agents WHERE stx_address = ?').bind(address).first();
  } else if (isValidBtcAddress(address)) {
    agent = await db.prepare('SELECT * FROM agents WHERE btc_address = ?').bind(address).first();
  } else {
    return json({ error: 'Invalid address format' }, 400, corsOrigin);
  }

  if (!agent) return json({ error: 'Agent not found' }, 404, corsOrigin);

  // Get their bounties
  const stxAddr = (agent as any).stx_address;
  const postedBounties = await db
    .prepare('SELECT id, title, amount_sats, status, created_at FROM bounties WHERE creator_stx = ? ORDER BY created_at DESC LIMIT 20')
    .bind(stxAddr)
    .all();

  return json({
    agent,
    posted_bounties: postedBounties.results,
  }, 200, corsOrigin);
}

// GET /api/stats — Platform aggregates
async function handleStats(db: D1Database, corsOrigin: string): Promise<Response> {
  const stats = await db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM bounties) as total_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'open') as open_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'paid') as completed_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'cancelled') as cancelled_bounties,
      (SELECT COUNT(*) FROM agents) as total_agents,
      (SELECT COALESCE(SUM(amount_sats), 0) FROM payments WHERE status = 'confirmed') as total_paid_sats,
      (SELECT COUNT(*) FROM claims) as total_claims,
      (SELECT COUNT(*) FROM submissions) as total_submissions
  `).first();

  return json({ stats, timestamp: new Date().toISOString() }, 200, corsOrigin);
}

// POST /api/bounties — Create bounty (AIBTC level >= 1 required)
async function handleCreateBounty(body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  // Auth
  const auth = await validateAuth(body, db, 'create-bounty', 'bounties');
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  // Must provide STX address for AIBTC verification
  if (!auth.stxAddress) return json({ error: 'stx_address required for bounty creation' }, 400, corsOrigin);

  // Verify AIBTC agent level
  const aibtcAgent = await verifyAibtcAgent(db, auth.stxAddress);
  if (!aibtcAgent || aibtcAgent.level < 1) {
    return json({ error: 'AIBTC verification required: must be level >= 1 to post bounties' }, 403, corsOrigin);
  }

  // Validate bounty fields
  if (!body.title || typeof body.title !== 'string' || body.title.length > MAX_TITLE) {
    return json({ error: `title required (max ${MAX_TITLE} chars)` }, 400, corsOrigin);
  }
  if (!body.description || typeof body.description !== 'string' || body.description.length > MAX_DESCRIPTION) {
    return json({ error: `description required (max ${MAX_DESCRIPTION} chars)` }, 400, corsOrigin);
  }
  if (!body.amount_sats || typeof body.amount_sats !== 'number' || body.amount_sats < 1) {
    return json({ error: 'amount_sats required (positive integer)' }, 400, corsOrigin);
  }
  if (body.tags && (typeof body.tags !== 'string' || body.tags.length > MAX_TAGS)) {
    return json({ error: `tags max ${MAX_TAGS} chars` }, 400, corsOrigin);
  }
  if (body.deadline) {
    const d = new Date(body.deadline).getTime();
    if (isNaN(d) || d < Date.now()) {
      return json({ error: 'deadline must be a future ISO 8601 date' }, 400, corsOrigin);
    }
  }

  // Ensure agent row exists
  await ensureAgent(db, auth.stxAddress, auth.btcAddress, aibtcAgent.display_name ?? undefined, aibtcAgent.level);

  // Insert bounty
  const result = await dbRun(db
    .prepare(
      `INSERT INTO bounties (creator_stx, title, description, amount_sats, tags, deadline)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(auth.stxAddress, body.title, body.description, body.amount_sats, body.tags || null, body.deadline || null)
  );

  // Update agent stats
  await dbRun(db
    .prepare('UPDATE agents SET bounties_posted = bounties_posted + 1, updated_at = datetime(\'now\') WHERE stx_address = ?')
    .bind(auth.stxAddress)
  );

  const bountyId = result.meta.last_row_id;
  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first();

  return json({ bounty, message: 'Bounty created' }, 201, corsOrigin);
}

// PATCH /api/bounties/:id — Update bounty (creator only, open only)
async function handleUpdateBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'update-bounty', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Can only update open bounties' }, 409, corsOrigin);

  // Verify creator - match via BTC address lookup
  const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
  if (!creator || creator.btc_address !== auth.btcAddress) {
    return json({ error: 'Only the bounty creator can update it' }, 403, corsOrigin);
  }

  // Apply updates
  const updates: string[] = [];
  const values: any[] = [];

  if (body.title && typeof body.title === 'string' && body.title.length <= MAX_TITLE) {
    updates.push('title = ?');
    values.push(body.title);
  }
  if (body.description && typeof body.description === 'string' && body.description.length <= MAX_DESCRIPTION) {
    updates.push('description = ?');
    values.push(body.description);
  }
  if (body.amount_sats && typeof body.amount_sats === 'number' && body.amount_sats > 0) {
    updates.push('amount_sats = ?');
    values.push(body.amount_sats);
  }
  if (body.tags !== undefined) {
    updates.push('tags = ?');
    values.push(body.tags || null);
  }
  if (body.deadline !== undefined) {
    updates.push('deadline = ?');
    values.push(body.deadline || null);
  }

  if (updates.length === 0) return json({ error: 'No valid fields to update' }, 400, corsOrigin);

  updates.push("updated_at = datetime('now')");
  values.push(bountyId);

  await dbRun(db
    .prepare(`UPDATE bounties SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...values)
  );

  const updated = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first();
  return json({ bounty: updated, message: 'Bounty updated' }, 200, corsOrigin);
}

// DELETE /api/bounties/:id — Cancel bounty (creator only, open only)
async function handleCancelBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'cancel-bounty', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Can only cancel open bounties' }, 409, corsOrigin);

  const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
  if (!creator || creator.btc_address !== auth.btcAddress) {
    return json({ error: 'Only the bounty creator can cancel it' }, 403, corsOrigin);
  }

  await dbRun(db
    .prepare("UPDATE bounties SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );

  return json({ message: 'Bounty cancelled' }, 200, corsOrigin);
}

// POST /api/bounties/:id/claim — Claim a bounty
async function handleClaimBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'claim-bounty', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Bounty is not open for claims' }, 409, corsOrigin);

  // Can't claim your own bounty
  const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
  if (creator && creator.btc_address === auth.btcAddress) {
    return json({ error: 'Cannot claim your own bounty' }, 403, corsOrigin);
  }

  // Check for existing active claim by this address
  const existingClaim = await db
    .prepare("SELECT id FROM claims WHERE bounty_id = ? AND claimer_btc = ? AND status = 'active'")
    .bind(bountyId, auth.btcAddress)
    .first();
  if (existingClaim) return json({ error: 'You already have an active claim on this bounty' }, 409, corsOrigin);

  if (body.message && (typeof body.message !== 'string' || body.message.length > MAX_MESSAGE)) {
    return json({ error: `message max ${MAX_MESSAGE} chars` }, 400, corsOrigin);
  }

  const result = await dbRun(db
    .prepare(
      `INSERT INTO claims (bounty_id, claimer_btc, claimer_stx, message)
       VALUES (?, ?, ?, ?)`
    )
    .bind(bountyId, auth.btcAddress, auth.stxAddress || null, body.message || null)
  );

  // Update bounty claim count and status
  await dbRun(db
    .prepare("UPDATE bounties SET claim_count = claim_count + 1, status = 'claimed', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );

  // Update claimer stats if they have an agent row
  if (auth.stxAddress) {
    await ensureAgent(db, auth.stxAddress, auth.btcAddress);
    await dbRun(db
      .prepare("UPDATE agents SET bounties_claimed = bounties_claimed + 1, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(auth.stxAddress)
    );
  }

  const claimId = result.meta.last_row_id;
  const claim = await db.prepare('SELECT * FROM claims WHERE id = ?').bind(claimId).first();

  return json({ claim, message: 'Bounty claimed' }, 201, corsOrigin);
}

// POST /api/bounties/:id/submit — Submit work proof
async function handleSubmitWork(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'submit-work', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'claimed') return json({ error: 'Bounty must be in claimed status' }, 409, corsOrigin);

  // Must have an active claim
  const claim = await db
    .prepare("SELECT * FROM claims WHERE bounty_id = ? AND claimer_btc = ? AND status = 'active'")
    .bind(bountyId, auth.btcAddress)
    .first<any>();
  if (!claim) return json({ error: 'No active claim found for your address' }, 403, corsOrigin);

  // Validate submission fields
  if (!body.description || typeof body.description !== 'string' || body.description.length > MAX_DESCRIPTION) {
    return json({ error: `description required (max ${MAX_DESCRIPTION} chars)` }, 400, corsOrigin);
  }
  if (body.proof_url && (typeof body.proof_url !== 'string' || body.proof_url.length > MAX_PROOF_URL)) {
    return json({ error: `proof_url max ${MAX_PROOF_URL} chars` }, 400, corsOrigin);
  }

  const result = await dbRun(db
    .prepare(
      `INSERT INTO submissions (bounty_id, claim_id, proof_url, description)
       VALUES (?, ?, ?, ?)`
    )
    .bind(bountyId, claim.id, body.proof_url || null, body.description)
  );

  // Update bounty and claim status
  await dbRun(db
    .prepare("UPDATE bounties SET status = 'submitted', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );
  await dbRun(db
    .prepare("UPDATE claims SET status = 'submitted', updated_at = datetime('now') WHERE id = ?")
    .bind(claim.id)
  );

  const submissionId = result.meta.last_row_id;
  const submission = await db.prepare('SELECT * FROM submissions WHERE id = ?').bind(submissionId).first();

  return json({ submission, message: 'Work submitted for review' }, 201, corsOrigin);
}

// POST /api/bounties/:id/review — Approve or reject submission (creator only)
async function handleReview(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'review-bounty', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'submitted') return json({ error: 'Bounty must be in submitted status' }, 409, corsOrigin);

  // Creator only
  const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
  if (!creator || creator.btc_address !== auth.btcAddress) {
    return json({ error: 'Only the bounty creator can review submissions' }, 403, corsOrigin);
  }

  if (!body.verdict || !['approve', 'reject'].includes(body.verdict)) {
    return json({ error: 'verdict required: "approve" or "reject"' }, 400, corsOrigin);
  }

  if (body.reviewer_notes && (typeof body.reviewer_notes !== 'string' || body.reviewer_notes.length > MAX_REVIEWER_NOTES)) {
    return json({ error: `reviewer_notes max ${MAX_REVIEWER_NOTES} chars` }, 400, corsOrigin);
  }

  // Get the submission
  const submission = await db
    .prepare("SELECT * FROM submissions WHERE bounty_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1")
    .bind(bountyId)
    .first<any>();
  if (!submission) return json({ error: 'No pending submission found' }, 404, corsOrigin);

  if (body.verdict === 'approve') {
    // Approve submission
    await dbRun(db
      .prepare("UPDATE submissions SET status = 'approved', reviewer_notes = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(body.reviewer_notes || null, submission.id)
    );
    await dbRun(db
      .prepare("UPDATE claims SET status = 'approved', updated_at = datetime('now') WHERE id = ?")
      .bind(submission.claim_id)
    );
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'approved', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    return json({ message: 'Submission approved — ready for payment', bounty_id: bountyId, submission_id: submission.id }, 200, corsOrigin);
  } else {
    // Reject submission — bounty goes back to open
    await dbRun(db
      .prepare("UPDATE submissions SET status = 'rejected', reviewer_notes = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(body.reviewer_notes || null, submission.id)
    );
    await dbRun(db
      .prepare("UPDATE claims SET status = 'rejected', updated_at = datetime('now') WHERE id = ?")
      .bind(submission.claim_id)
    );
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'open', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    return json({ message: 'Submission rejected — bounty re-opened', bounty_id: bountyId }, 200, corsOrigin);
  }
}

// POST /api/bounties/:id/pay — Submit tx_hash, platform verifies on-chain
async function handlePay(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bountyId = parseInt(id, 10);
  if (isNaN(bountyId)) return json({ error: 'Invalid bounty ID' }, 400, corsOrigin);

  const auth = await validateAuth(body, db, 'pay-bounty', `bounties/${bountyId}`);
  if ('error' in auth) return json({ error: auth.error }, 401, corsOrigin);

  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first<any>();
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  if (bounty.status !== 'approved') return json({ error: 'Bounty must be in approved status' }, 409, corsOrigin);

  // Creator only
  const creator = await db.prepare('SELECT btc_address, stx_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string; stx_address: string }>();
  if (!creator || creator.btc_address !== auth.btcAddress) {
    return json({ error: 'Only the bounty creator can submit payment' }, 403, corsOrigin);
  }

  if (!body.tx_hash || !isValidTxHash(body.tx_hash)) {
    return json({ error: 'Valid tx_hash required (64 hex chars, optional 0x prefix)' }, 400, corsOrigin);
  }

  // Check for duplicate tx_hash
  const existing = await db.prepare('SELECT id FROM payments WHERE tx_hash = ?').bind(normalizeTxHash(body.tx_hash)).first();
  if (existing) return json({ error: 'This transaction hash has already been submitted' }, 409, corsOrigin);

  // Get the approved submission and claimer's STX address
  const submission = await db
    .prepare("SELECT s.*, c.claimer_stx FROM submissions s JOIN claims c ON s.claim_id = c.id WHERE s.bounty_id = ? AND s.status = 'approved' LIMIT 1")
    .bind(bountyId)
    .first<any>();
  if (!submission) return json({ error: 'No approved submission found' }, 404, corsOrigin);

  if (!submission.claimer_stx) {
    return json({ error: 'Claimer has no STX address — cannot verify sBTC payment' }, 400, corsOrigin);
  }

  // Verify on-chain payment
  const verification = await verifyPayment(
    body.tx_hash,
    bounty.creator_stx,
    submission.claimer_stx,
    bounty.amount_sats
  );

  const normalizedHash = normalizeTxHash(body.tx_hash);

  // Insert payment record
  const paymentResult = await dbRun(db
    .prepare(
      `INSERT INTO payments (bounty_id, submission_id, from_stx, to_stx, amount_sats, tx_hash, status, verified_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      bountyId,
      submission.id,
      bounty.creator_stx,
      submission.claimer_stx,
      verification.amount_sats ?? bounty.amount_sats,
      normalizedHash,
      verification.verified ? 'confirmed' : 'pending',
      verification.verified ? new Date().toISOString() : null
    )
  );

  if (verification.verified) {
    // Mark bounty as paid
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'paid', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    // Update agent stats
    await dbRun(db
      .prepare("UPDATE agents SET total_paid_sats = total_paid_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(bounty.amount_sats, bounty.creator_stx)
    );
    await dbRun(db
      .prepare("UPDATE agents SET bounties_completed = bounties_completed + 1, total_earned_sats = total_earned_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(bounty.amount_sats, submission.claimer_stx)
    );

    return json({
      message: 'Payment verified on-chain — bounty completed!',
      payment_id: paymentResult.meta.last_row_id,
      tx_hash: normalizedHash,
      verified: true,
    }, 200, corsOrigin);
  } else {
    return json({
      message: 'Payment recorded but not yet verified on-chain',
      payment_id: paymentResult.meta.last_row_id,
      tx_hash: normalizedHash,
      verified: false,
      verification_error: verification.error,
    }, 202, corsOrigin);
  }
}

// ─── Cron Handler: verify pending payments + cleanup ─────────────────────────

async function handleScheduled(env: Env): Promise<void> {
  const db = env.DB;

  // Cleanup expired signatures and rate limits
  await cleanupExpiredSignatures(db);
  await cleanupExpiredRateLimits(db);

  // Cleanup expired AIBTC cache entries (older than 1 hour)
  await db.prepare("DELETE FROM aibtc_cache WHERE verified_at < datetime('now', '-1 hour')").run();

  // Verify pending payments
  const pendingPayments = await db
    .prepare("SELECT p.*, b.creator_stx, b.amount_sats as bounty_amount FROM payments p JOIN bounties b ON p.bounty_id = b.id WHERE p.status = 'pending' LIMIT 10")
    .all<any>();

  for (const payment of pendingPayments.results) {
    try {
      const verification = await verifyPayment(
        payment.tx_hash,
        payment.from_stx,
        payment.to_stx,
        payment.bounty_amount
      );

      if (verification.verified) {
        await dbRun(db
          .prepare("UPDATE payments SET status = 'confirmed', verified_at = datetime('now') WHERE id = ?")
          .bind(payment.id)
        );
        await dbRun(db
          .prepare("UPDATE bounties SET status = 'paid', updated_at = datetime('now') WHERE id = ?")
          .bind(payment.bounty_id)
        );

        // Update agent stats
        await dbRun(db
          .prepare("UPDATE agents SET total_paid_sats = total_paid_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
          .bind(payment.bounty_amount, payment.from_stx)
        );
        await dbRun(db
          .prepare("UPDATE agents SET bounties_completed = bounties_completed + 1, total_earned_sats = total_earned_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
          .bind(payment.bounty_amount, payment.to_stx)
        );
      }
    } catch (err: any) {
      console.error(`Payment verification failed for ${payment.tx_hash}: ${err.message}`);
    }
  }
}

// ─── Fetch Handler (Router) ──────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const isWrite = WRITE_METHODS.has(method);
    const requestOrigin = request.headers.get('Origin');
    const corsOrigin = resolveCorsOrigin(requestOrigin, isWrite);

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      const preflightMethod = request.headers.get('Access-Control-Request-Method');
      const preflightIsWrite = preflightMethod ? WRITE_METHODS.has(preflightMethod) : false;
      const preflightOrigin = resolveCorsOrigin(requestOrigin, preflightIsWrite);
      if (preflightOrigin === null) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, {
        status: 204,
        headers: corsHeaders(preflightOrigin, preflightOrigin !== '*'),
      });
    }

    const db = env.DB;

    try {
      // ── GET routes ──
      if (method === 'GET') {
        if (path === '/api/bounties') {
          return handleListBounties(url, db, corsOrigin ?? '*');
        }

        const bountyMatch = path.match(/^\/api\/bounties\/(\d+)$/);
        if (bountyMatch) {
          return handleGetBounty(bountyMatch[1], db, corsOrigin ?? '*');
        }

        const agentMatch = path.match(/^\/api\/agents\/([A-Za-z0-9]+)$/);
        if (agentMatch) {
          return handleGetAgent(agentMatch[1], db, corsOrigin ?? '*');
        }

        if (path === '/api/stats') {
          return handleStats(db, corsOrigin ?? '*');
        }

        // Health check
        if (path === '/' || path === '/health') {
          return json({
            name: 'agent-bounties',
            version: '1.0.0',
            status: 'ok',
            timestamp: new Date().toISOString(),
          }, 200, corsOrigin ?? '*');
        }

        return json({ error: 'Not found' }, 404, corsOrigin ?? '*');
      }

      // ── Write routes: require origin check, rate limit, body parse ──
      if (corsOrigin === null) {
        return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Rate limit on writes
      const rateErr = await checkRateLimit(db, request);
      if (rateErr) return rateErr;

      // Read body
      const bodyResult = await readBodyWithSizeCheck(request);
      if ('error' in bodyResult) return bodyResult.error;

      let body: any;
      try {
        body = JSON.parse(bodyResult.text);
      } catch {
        return json({ error: 'Invalid JSON body' }, 400, corsOrigin);
      }

      // ── POST routes ──
      if (method === 'POST') {
        if (path === '/api/bounties') {
          return handleCreateBounty(body, db, corsOrigin);
        }

        const claimMatch = path.match(/^\/api\/bounties\/(\d+)\/claim$/);
        if (claimMatch) {
          return handleClaimBounty(claimMatch[1], body, db, corsOrigin);
        }

        const submitMatch = path.match(/^\/api\/bounties\/(\d+)\/submit$/);
        if (submitMatch) {
          return handleSubmitWork(submitMatch[1], body, db, corsOrigin);
        }

        const reviewMatch = path.match(/^\/api\/bounties\/(\d+)\/review$/);
        if (reviewMatch) {
          return handleReview(reviewMatch[1], body, db, corsOrigin);
        }

        const payMatch = path.match(/^\/api\/bounties\/(\d+)\/pay$/);
        if (payMatch) {
          return handlePay(payMatch[1], body, db, corsOrigin);
        }
      }

      // ── PATCH routes ──
      if (method === 'PATCH') {
        const patchMatch = path.match(/^\/api\/bounties\/(\d+)$/);
        if (patchMatch) {
          return handleUpdateBounty(patchMatch[1], body, db, corsOrigin);
        }
      }

      // ── DELETE routes ──
      if (method === 'DELETE') {
        const deleteMatch = path.match(/^\/api\/bounties\/(\d+)$/);
        if (deleteMatch) {
          return handleCancelBounty(deleteMatch[1], body, db, corsOrigin);
        }
      }

      return json({ error: 'Not found' }, 404, corsOrigin);
    } catch (err: any) {
      console.error('Unhandled error:', err);
      return json({ error: 'Internal server error' }, 500, corsOrigin ?? '*');
    }
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleScheduled(env));
  },
} satisfies ExportedHandler<Env>;
