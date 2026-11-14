// Helpers shared by the page (app.js), the scan workers (worker.js) and tests.

export const TAPROOT_HEIGHT = 709632;

export function hexToBytes(hex) {
  if (hex.length % 2 || /[^0-9a-fA-F]/.test(hex)) throw new Error("not hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(2 * i, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- bech32m (BIP350), for sp1... addresses (BIP352: hrp "sp", version 0) ----

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M = 0x2bc830a3;

function polymod(values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= gen[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

// Returns {scanPubkey, spendPubkey} (33 bytes each) or throws.
export function decodeSpAddress(address) {
  const text = address.trim();
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) throw new Error("mixed case");
  const lower = text.toLowerCase();
  const sep = lower.lastIndexOf("1");
  const hrp = lower.slice(0, sep);
  if (hrp !== "sp") throw new Error("not a mainnet silent payment address (sp1...)");
  const data = [];
  for (const c of lower.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error("invalid character");
    data.push(v);
  }
  if (data.length < 7 || polymod(hrpExpand(hrp).concat(data)) !== BECH32M) {
    throw new Error("checksum does not match (typo?)");
  }
  const version = data[0];
  if (version !== 0) throw new Error(`unsupported address version ${version}`);
  let acc = 0, bits = 0;
  const bytes = [];
  for (const v of data.slice(1, -6)) {
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1))) throw new Error("bad padding");
  if (bytes.length !== 66) throw new Error("wrong length for a version 0 address");
  const out = Uint8Array.from(bytes);
  return { scanPubkey: out.slice(0, 33), spendPubkey: out.slice(33) };
}

// ---- /v1/blocks binary format (see spscand/web.py encode_blocks) ----

export function parseBlocks(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  if (String.fromCharCode(...bytes.subarray(0, 4)) !== "SPB1") throw new Error("bad block data");
  const count = view.getUint32(4, true);
  const blocks = [];
  let at = 8;
  for (let i = 0; i < count; i++) {
    const height = view.getUint32(at, true);
    const hash = bytes.slice(at + 4, at + 36);
    const nTweaks = view.getUint32(at + 36, true);
    at += 40;
    const tweaks = bytes.slice(at, at + 33 * nTweaks);
    at += 33 * nTweaks;
    const filterLen = view.getUint32(at, true);
    const filter = bytes.slice(at + 4, at + 4 + filterLen);
    at += 4 + filterLen;
    blocks.push({ height, hash, tweaks, filter });
  }
  if (at !== bytes.length) throw new Error("bad block data length");
  return blocks;
}

// Decoy heights to ask for alongside the real ones, so the server cannot tell
// which blocks may pay this wallet. Picked uniformly from the scanned range.
export function withDecoys(real, from, to, perReal = 3, random = Math.random) {
  const all = new Set(real);
  const span = to - from + 1;
  const want = Math.min(span, real.length * (perReal + 1));
  while (all.size < want) all.add(from + Math.floor(random() * span));
  return [...all].sort((a, b) => a - b);
}

// Rough height for a date (10 minutes per block, counted back from the tip),
// moved two days earlier to be safe.
export function heightForDate(date, tip, now = Date.now()) {
  const blocks = Math.ceil((now - date.getTime()) / 600000) + 288;
  return Math.max(TAPROOT_HEIGHT, Math.min(tip, tip - blocks));
}

export function formatBtc(sats) {
  const whole = Math.floor(sats / 1e8);
  const frac = String(sats % 1e8).padStart(8, "0");
  return `${whole}.${frac}`;
}
