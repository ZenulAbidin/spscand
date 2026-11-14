// Test runner for spscan.wasm under Node.js (used by tests/test_wasm.py).
// stdin: {"cases": [{scan_key, spend_pubkey, labels, flags, tweaks, outputs,
//                    filter?, block_hash?}]} with hex strings (tweaks/outputs concatenated).
// stdout: {"version", "results": [{"matches": [[tweak, output, k, label, key_tweak], ...],
//          "filter": bool|null, "scanPubkey": hex}]}
import { readFileSync } from "node:fs";
import { loadSpscan } from "../../web/spscan.js";

const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const lib = await loadSpscan(readFileSync(new URL("../spscan.wasm", import.meta.url)));
const { cases } = JSON.parse(readFileSync(0, "utf8"));
const results = cases.map((c) => {
  const r = lib.receiver(hex(c.scan_key), hex(c.spend_pubkey), c.labels, c.flags);
  try {
    const matches = r.scan(hex(c.tweaks), hex(c.outputs)).map((m) =>
      [m.tweak, m.output, m.k, m.label, Buffer.from(m.keyTweak).toString("hex")]);
    const filter = c.filter === undefined ? null
      : r.filterCheck(hex(c.tweaks), hex(c.filter), hex(c.block_hash));
    const scanPubkey = Buffer.from(r.scanPubkey()).toString("hex");
    return { matches, filter, scanPubkey };
  } finally {
    r.destroy();
  }
});
process.stdout.write(JSON.stringify({ version: lib.version(), results }));
