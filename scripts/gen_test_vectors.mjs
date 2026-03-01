/**
 * Generate BIP-137 test vectors for all three address types:
 * - P2PKH  (1-prefix, compressed)
 * - P2SH-P2WPKH  (3-prefix)
 * - P2WPKH / native segwit  (bc1q-prefix)
 *
 * Uses the same libraries as src/index.ts so vectors are guaranteed correct.
 * Run once:  node scripts/gen_test_vectors.mjs
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256.js';
import { ripemd160 } from '@noble/hashes/ripemd160.js';

// ── Helpers copied from src/index.ts ──────────────────────────────────────────

function encodeVarint(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) { const b = new Uint8Array(3); b[0] = 0xfd; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; return b; }
  const b = new Uint8Array(5); b[0] = 0xfe; for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff; return b;
}

function bitcoinMessageHash(message) {
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

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32Encode(hrp, data) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const expand = [...Array.from(hrp, c => c.charCodeAt(0) >> 5), 0, ...Array.from(hrp, c => c.charCodeAt(0) & 31)];
  const values = [...expand, ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0, bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function pubkeyToBech32(pubkey) {
  const hash = ripemd160(sha256(pubkey));
  const words = [0, ...convertBits(hash, 8, 5, true)];
  return bech32Encode('bc', words);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58CheckEncode(version, payload) {
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

function pubkeyToP2PKH(pubkey) {
  const hash = ripemd160(sha256(pubkey));
  return base58CheckEncode(0x00, hash);
}

function pubkeyToP2SH_P2WPKH(pubkey) {
  const keyHash = ripemd160(sha256(pubkey));
  const redeemScript = new Uint8Array(22);
  redeemScript[0] = 0x00;
  redeemScript[1] = 0x14;
  redeemScript.set(keyHash, 2);
  const scriptHash = ripemd160(sha256(redeemScript));
  return base58CheckEncode(0x05, scriptHash);
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

// ── Sign with BIP-137 header ──────────────────────────────────────────────────

async function signBip137(privkeyHex, message, addressType) {
  const privkey = Uint8Array.from(Buffer.from(privkeyHex, 'hex'));
  const pubkeyCompressed = secp.getPublicKey(privkey, true);

  // Address type → base header
  // P2PKH compressed:     31-34
  // P2SH-P2WPKH:          35-38
  // P2WPKH (bc1q):        39-42
  const baseHeader = addressType === 'p2pkh' ? 31 : addressType === 'p2sh' ? 35 : 39;

  const msgHash = bitcoinMessageHash(message);

  // Sign deterministically (noble secp256k1 v2 returns {r,s,recovery})
  const sig = await secp.signAsync(msgHash, privkey);
  const rid = sig.recovery;
  const header = baseHeader + rid;

  const sigBytes = new Uint8Array(65);
  sigBytes[0] = header;
  const rBytes = sig.r.toString(16).padStart(64, '0');
  const sBytes = sig.s.toString(16).padStart(64, '0');
  for (let i = 0; i < 32; i++) sigBytes[1 + i] = parseInt(rBytes.slice(i * 2, i * 2 + 2), 16);
  for (let i = 0; i < 32; i++) sigBytes[33 + i] = parseInt(sBytes.slice(i * 2, i * 2 + 2), 16);

  const address =
    addressType === 'p2pkh' ? pubkeyToP2PKH(pubkeyCompressed) :
    addressType === 'p2sh'  ? pubkeyToP2SH_P2WPKH(pubkeyCompressed) :
    pubkeyToBech32(pubkeyCompressed);

  return { address, signature: toBase64(sigBytes), header, rid };
}

// ── Main ──────────────────────────────────────────────────────────────────────

const PRIVKEY = 'f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315';
const MESSAGE = 'Hello, Bitcoin!';

console.log('Generating BIP-137 test vectors...\n');

for (const type of ['p2pkh', 'p2sh', 'p2wpkh']) {
  const vec = await signBip137(PRIVKEY, MESSAGE, type);
  console.log(`// ${type.toUpperCase()}`);
  console.log(`address:   "${vec.address}"`);
  console.log(`signature: "${vec.signature}"`);
  console.log(`header: ${vec.header}, recovery: ${vec.rid}`);
  console.log();
}

// Also produce a wrong-sig vector for negative tests
const vec = await signBip137(PRIVKEY, MESSAGE, 'p2pkh');
const wrongSig = vec.signature.slice(0, -2) + (vec.signature.slice(-2) === 'AA' ? 'AB' : 'AA');
console.log('// WRONG SIG (last 2 chars flipped)');
console.log(`wrongSig: "${wrongSig}"`);
