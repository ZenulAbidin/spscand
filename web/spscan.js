// JavaScript binding to libspscan compiled to WebAssembly (libspscan/spscan.wasm).
// Works in browsers, web workers and Node.js. The module has no imports.
//
//   const lib = await loadSpscan(wasmBytesOrResponse);
//   const r = lib.receiver(scanKey32, spendPubkey33, labels, flags, seed32);
//   r.scan(tweaks, outputs)        // tweaks: Uint8Array of 33-byte points,
//                                  // outputs: Uint8Array of 32-byte x-only keys
//   r.filterCheck(tweaks, filter, blockHash32)
//   r.scanPubkey()                 // 33 bytes, to check the key against an address
//   r.destroy()                    // wipes and frees the scan key in wasm memory

export const OK = 0, ERR_ARG = -1, ERR_NOMEM = -2, ERR_SCALAR = -3, ERR_INFINITY = -4,
  ERR_FILTER = -5, ERR_SPACE = -6;
export const NO_CHANGE_LABEL = 1, LABELS_BY_ADDITION = 2, LABELS_BY_SUBTRACTION = 4;
const MATCH_SIZE = 56; // uint32 tweak, output, k; 4 bytes padding; int64 label; 32-byte key tweak

export class SpscanError extends Error {
  constructor(fn, code) {
    super(`${fn} failed with error ${code}`);
    this.code = code;
  }
}

export async function loadSpscan(source) {
  let instance;
  if (source instanceof Response || (typeof source?.then === "function")) {
    const response = await source;
    if (WebAssembly.instantiateStreaming && response.headers?.get("content-type") === "application/wasm") {
      ({ instance } = await WebAssembly.instantiateStreaming(response, {}));
    } else {
      ({ instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {}));
    }
  } else {
    ({ instance } = await WebAssembly.instantiate(source, {}));
  }
  return new Spscan(instance.exports);
}

class Spscan {
  constructor(x) {
    this.x = x;
  }

  get bytes() {
    return new Uint8Array(this.x.memory.buffer); // re-read: the buffer changes when memory grows
  }

  alloc(size) {
    const ptr = this.x.malloc(Math.max(size, 1));
    if (!ptr) throw new SpscanError("malloc", ERR_NOMEM);
    return ptr;
  }

  copyIn(data) {
    const ptr = this.alloc(data.length);
    this.bytes.set(data, ptr);
    return ptr;
  }

  wipeFree(ptr, size) {
    this.bytes.fill(0, ptr, ptr + size);
    this.x.free(ptr);
  }

  version() {
    const bytes = this.bytes;
    let end = this.x.spscan_version();
    const start = end;
    while (bytes[end]) end++;
    return new TextDecoder().decode(bytes.subarray(start, end));
  }

  receiver(scanKey, spendPubkey, labels = [], flags = 0, seed = null) {
    if (scanKey.length !== 32 || spendPubkey.length !== 33) throw new SpscanError("receiver", ERR_ARG);
    seed = seed || crypto.getRandomValues(new Uint8Array(32));
    const out = this.alloc(4);
    const key = this.copyIn(scanKey);
    const spend = this.copyIn(spendPubkey);
    const labelPtr = this.alloc(4 * labels.length);
    new Uint32Array(this.x.memory.buffer, labelPtr, labels.length).set(labels);
    const seedPtr = this.copyIn(seed);
    const code = this.x.spscan_receiver_create(out, key, spend, labelPtr, labels.length, flags, seedPtr);
    const handle = new Uint32Array(this.x.memory.buffer, out, 1)[0];
    this.wipeFree(key, 32);
    this.wipeFree(seedPtr, 32);
    this.x.free(spend);
    this.x.free(labelPtr);
    this.x.free(out);
    if (code !== OK) throw new SpscanError("spscan_receiver_create", code);
    return new Receiver(this, handle);
  }
}

class Receiver {
  constructor(lib, handle) {
    this.lib = lib;
    this.handle = handle;
  }

  // Returns [{tweak, output, k, label, keyTweak}] with label null when unlabelled.
  scan(tweaks, outputs) {
    const { lib } = this;
    const nTweaks = tweaks.length / 33, nOutputs = outputs.length / 32;
    if (!this.handle || !Number.isInteger(nTweaks) || !Number.isInteger(nOutputs)) {
      throw new SpscanError("spscan_scan", ERR_ARG);
    }
    const t = lib.copyIn(tweaks), o = lib.copyIn(outputs), count = lib.alloc(4);
    let room = 16, code, matches;
    try {
      for (;;) {
        matches = lib.alloc(room * MATCH_SIZE);
        new Uint32Array(lib.x.memory.buffer, count, 1)[0] = room;
        code = lib.x.spscan_scan(this.handle, t, nTweaks, o, nOutputs, matches, count);
        if (code !== ERR_SPACE) break;
        lib.x.free(matches);
        room = new Uint32Array(lib.x.memory.buffer, count, 1)[0];
      }
      if (code !== OK) throw new SpscanError("spscan_scan", code);
      const n = new Uint32Array(lib.x.memory.buffer, count, 1)[0];
      const view = new DataView(lib.x.memory.buffer);
      const result = [];
      for (let i = 0; i < n; i++) {
        const at = matches + i * MATCH_SIZE;
        const label = view.getBigInt64(at + 16, true);
        result.push({
          tweak: view.getUint32(at, true),
          output: view.getUint32(at + 4, true),
          k: view.getUint32(at + 8, true),
          label: label < 0n ? null : Number(label),
          keyTweak: lib.bytes.slice(at + 24, at + 56),
        });
      }
      lib.wipeFree(matches, room * MATCH_SIZE);
      return result;
    } finally {
      lib.x.free(t);
      lib.x.free(o);
      lib.x.free(count);
    }
  }

  scanPubkey() {
    const { lib } = this;
    const out = lib.alloc(33);
    try {
      const code = lib.x.spscan_receiver_scan_pubkey(this.handle, out);
      if (code !== OK) throw new SpscanError("spscan_receiver_scan_pubkey", code);
      return lib.bytes.slice(out, out + 33);
    } finally {
      lib.x.free(out);
    }
  }

  filterCheck(tweaks, filter, blockHash) {
    const { lib } = this;
    const nTweaks = tweaks.length / 33;
    if (!this.handle || !Number.isInteger(nTweaks) || blockHash.length !== 32) {
      throw new SpscanError("spscan_filter_check", ERR_ARG);
    }
    const t = lib.copyIn(tweaks), f = lib.copyIn(filter), h = lib.copyIn(blockHash), m = lib.alloc(4);
    try {
      const code = lib.x.spscan_filter_check(this.handle, t, nTweaks, f, filter.length, h, m);
      if (code !== OK) throw new SpscanError("spscan_filter_check", code);
      return new Int32Array(lib.x.memory.buffer, m, 1)[0] !== 0;
    } finally {
      for (const p of [t, f, h, m]) lib.x.free(p);
    }
  }

  destroy() {
    if (this.handle) this.lib.x.spscan_receiver_destroy(this.handle);
    this.handle = 0;
  }
}
