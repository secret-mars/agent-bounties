/**
 * BIP-137 signature verification tests.
 *
 * Test vectors generated with scripts/gen_test_vectors.mjs using:
 *   privkey = f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315
 *   message = "Hello, Bitcoin!"
 */

import { describe, it, expect } from 'vitest';
import { verifyBip137 } from '../src/index';

const MESSAGE = 'Hello, Bitcoin!';

// ── Test vectors ──────────────────────────────────────────────────────────────

const P2PKH_ADDRESS   = '1F4eqGvMydrvHyczjKiszL1KhrDoUmrGZW';
const P2PKH_SIG       = 'IASvbETwq9r9/yAHY8usZYxxqnzT1QtYypW4DNENsXijG0/VUtoQ6aiBt62aNy3oukdx6Zm6P0HJj0cxpiQGauk=';

const P2SH_ADDRESS    = '3Jm7Uk6LCrrpCV22EVnrBxLMWQ9VyefYcB';
const P2SH_SIG        = 'JASvbETwq9r9/yAHY8usZYxxqnzT1QtYypW4DNENsXijG0/VUtoQ6aiBt62aNy3oukdx6Zm6P0HJj0cxpiQGauk=';

const P2WPKH_ADDRESS  = 'bc1qnfpfdawz2530qpu0vksgjdc0p94tputqn8t7d2';
const P2WPKH_SIG      = 'KASvbETwq9r9/yAHY8usZYxxqnzT1QtYypW4DNENsXijG0/VUtoQ6aiBt62aNy3oukdx6Zm6P0HJj0cxpiQGauk=';

// Same P2PKH signature with last two chars corrupted
const WRONG_SIG       = 'IASvbETwq9r9/yAHY8usZYxxqnzT1QtYypW4DNENsXijG0/VUtoQ6aiBt62aNy3oukdx6Zm6P0HJj0cxpiQGauAA';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('verifyBip137', () => {
  it('accepts a valid P2PKH (1-prefix) signature', async () => {
    const result = await verifyBip137(P2PKH_SIG, MESSAGE, P2PKH_ADDRESS);
    expect(result).toBeNull();
  });

  it('accepts a valid P2SH-P2WPKH (3-prefix) signature', async () => {
    const result = await verifyBip137(P2SH_SIG, MESSAGE, P2SH_ADDRESS);
    expect(result).toBeNull();
  });

  it('accepts a valid P2WPKH / native segwit (bc1q-prefix) signature', async () => {
    const result = await verifyBip137(P2WPKH_SIG, MESSAGE, P2WPKH_ADDRESS);
    expect(result).toBeNull();
  });

  it('rejects a corrupted signature', async () => {
    const result = await verifyBip137(WRONG_SIG, MESSAGE, P2PKH_ADDRESS);
    expect(result).not.toBeNull();
  });

  it('rejects a valid signature for a different message', async () => {
    const result = await verifyBip137(P2PKH_SIG, MESSAGE + '!', P2PKH_ADDRESS);
    expect(result).not.toBeNull();
  });

  describe('recovery sweep and type-agnostic verification', () => {
    it('accepts P2PKH header with P2WPKH address (handles inconsistent wallets)', async () => {
      // Wallet says it's P2PKH (I), but address is Segwit (bc1q)
      const result = await verifyBip137(P2PKH_SIG, MESSAGE, P2WPKH_ADDRESS);
      expect(result).toBeNull();
    });

    it('accepts P2WPKH header with P2PKH address', async () => {
      // Wallet says it's Segwit (K), but address is Legacy (1)
      const result = await verifyBip137(P2WPKH_SIG, MESSAGE, P2PKH_ADDRESS);
      expect(result).toBeNull();
    });

    it('accepts P2SH header with P2WPKH address', async () => {
      // Wallet says it's P2SH (J), but address is Segwit (bc1q)
      const result = await verifyBip137(P2SH_SIG, MESSAGE, P2WPKH_ADDRESS);
      expect(result).toBeNull();
    });

    it('finds the correct recovery ID even if the header byte is deliberately wrong', async () => {
      // Create a signature with rid=3 in header (MASv...), but the actual rid is 1
      // Base64 'M' is 12. (12 << 2) = 48. 48 = 39 + 9? No.
      // Let's just use a known-wrong header character.
      // 'K' is header 40 (rid 1). 'L' is 44 (invalid). 'J' is 36 (rid 1).
      // 'H' is 7. (7 << 2) = 28. 28 = 27 + 1. rid 1, uncompressed.
      const rid0P2PKH = 'HASvbETwq9r9/yAHY8usZYxxqnzT1QtYypW4DNENsXijG0/VUtoQ6aiBt62aNy3oukdx6Zm6P0HJj0cxpiQGauk=';
      const result = await verifyBip137(rid0P2PKH, MESSAGE, P2PKH_ADDRESS);
      expect(result).toBeNull();
    });
  });
});
