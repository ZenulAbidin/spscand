// The browser scan (web/app.js + web/worker.js) without the page: fetch
// /v1/blocks, check filters with the wasm receiver, fetch /v1/outputs with
// decoys, match. Used by tests/test_web.py.
//   node tests/web_scan.mjs http://127.0.0.1:PORT ADDRESS SCAN_KEY_HEX FROM [LABELS]
import { readFileSync } from "node:fs";
import { loadSpscan } from "../web/spscan.js";
import { decodeSpAddress, hexToBytes, parseBlocks, withDecoys } from "../web/scanner.js";

const [base, address, keyHex, fromText, labelText = ""] = process.argv.slice(2);
const lib = await loadSpscan(readFileSync(new URL("../libspscan/spscan.wasm", import.meta.url)));
const { scanPubkey, spendPubkey } = decodeSpAddress(address);
const labels = labelText.split(",").filter(Boolean).map(Number);
const receiver = lib.receiver(hexToBytes(keyHex), spendPubkey, labels);
if (Buffer.compare(Buffer.from(receiver.scanPubkey()), Buffer.from(scanPubkey))) {
  throw new Error("scan key does not match the address");
}
const info = await (await fetch(`${base}/v1/info`)).json();
const from = Number(fromText);
const candidates = [];
let fetched = 0;
for (let h = from; h <= info.tip;) {
  const res = await fetch(`${base}/v1/blocks?from=${h}&count=7`); // small pages: test paging
  const blocks = parseBlocks(await res.arrayBuffer());
  if (!blocks.length) throw new Error("empty page");
  for (const b of blocks) {
    if (b.height !== h) throw new Error(`expected block ${h}, got ${b.height}`);
    if (b.tweaks.length && receiver.filterCheck(b.tweaks, b.filter, b.hash)) candidates.push(b.height);
    h++;
    fetched++;
  }
}
const asked = withDecoys(candidates, from, info.tip, 3);
const outputs = candidates.length
  ? await (await fetch(`${base}/v1/outputs?heights=${asked.join(",")}`)).json() : {};
const payments = [];
for (const height of candidates) {
  for (const tx of outputs[height].txs) {
    if (!tx.outputs.length) continue;
    const keys = new Uint8Array(32 * tx.outputs.length);
    tx.outputs.forEach((o, i) => keys.set(hexToBytes(o[2]), 32 * i));
    for (const m of receiver.scan(hexToBytes(tx.tweak), keys)) {
      const [vout, amount] = tx.outputs[m.output];
      payments.push({ height, txid: tx.txid, vout, amount, label: m.label });
    }
  }
}
receiver.destroy();
process.stdout.write(JSON.stringify({ fetched, candidates, asked, payments }));
