// Scan worker: holds one receiver (the scan key stays in this worker's memory)
// and checks blocks with libspscan (WebAssembly).
//
// Messages in:  {type: "init", scanKey, spendPubkey, labels}  -> {type: "ready", scanPubkey}
//               {type: "check", id, blocks: [{height, hash, tweaks, filter}]}
//                                                         -> {type: "checked", id, heights}
//               {type: "match", id, blocks: {height: {txs: [{txid, tweak, outputs}]}}}
//                                                         -> {type: "matched", id, payments}
//               {type: "close"}
import { loadSpscan } from "./spscan.js";
import { hexToBytes } from "./scanner.js";

let receiver = null;
const libReady = loadSpscan(fetch(new URL("./spscan.wasm", import.meta.url)));

function concat(chunks, size) {
  const out = new Uint8Array(chunks.length * size);
  chunks.forEach((c, i) => out.set(c, i * size));
  return out;
}

self.onmessage = async ({ data: msg }) => {
  try {
    if (msg.type === "init") {
      const lib = await libReady;
      receiver = lib.receiver(msg.scanKey, msg.spendPubkey, msg.labels);
      msg.scanKey.fill(0);
      self.postMessage({ type: "ready", scanPubkey: receiver.scanPubkey() });
    } else if (msg.type === "check") {
      const heights = [];
      for (const b of msg.blocks) {
        if (b.tweaks.length && receiver.filterCheck(b.tweaks, b.filter, b.hash)) heights.push(b.height);
      }
      self.postMessage({ type: "checked", id: msg.id, heights, count: msg.blocks.length });
    } else if (msg.type === "match") {
      const payments = [];
      for (const [height, block] of Object.entries(msg.blocks)) {
        for (const tx of block.txs) {
          if (!tx.outputs.length) continue;
          const keys = concat(tx.outputs.map((o) => hexToBytes(o[2])), 32);
          for (const m of receiver.scan(hexToBytes(tx.tweak), keys)) {
            const [vout, amount] = tx.outputs[m.output];
            payments.push({ height: Number(height), txid: tx.txid, vout, amount, label: m.label });
          }
        }
      }
      self.postMessage({ type: "matched", id: msg.id, payments });
    } else if (msg.type === "close") {
      if (receiver) receiver.destroy();
      receiver = null;
      self.close();
    }
  } catch (err) {
    self.postMessage({ type: "error", id: msg.id, message: String(err.message || err) });
  }
};
