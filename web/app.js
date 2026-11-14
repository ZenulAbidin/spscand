// spscan page: scan in the browser (workers + WebAssembly) or on the server (/v1/jobs).
import {
  TAPROOT_HEIGHT, bytesToHex, decodeSpAddress, formatBtc, heightForDate, hexToBytes,
  parseBlocks, withDecoys,
} from "./scanner.js";

const $ = (id) => document.getElementById(id);
const EXPLORER = "https://mempool.bitmixlist.org/tx/";
let info = null;
let current = null; // {stop()} for the running scan

function setStatus(text) {
  $("progress").textContent = text;
}

function setError(text) {
  $("error").textContent = text || "";
  $("error").hidden = !text;
}

function setRunning(on) {
  $("start").disabled = on;
  $("stop").hidden = !on;
  for (const el of $("form").querySelectorAll("input")) el.disabled = on;
}

async function loadInfo() {
  const response = await fetch("/v1/info");
  if (!response.ok) throw new Error("the server is not answering; try again shortly");
  info = await response.json();
  $("tip").textContent = info.tip.toLocaleString("en-US");
  return info;
}

function fmtDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

// ---- results table ----

const shown = new Set();
let showSpent = false;

function resetResults(spentColumn) {
  shown.clear();
  showSpent = spentColumn;
  $("rows").replaceChildren();
  $("spent-head").hidden = !spentColumn;
  $("results").hidden = true;
  $("total").textContent = "";
}

function addPayments(payments) {
  for (const p of payments) {
    const key = `${p.txid}:${p.vout}`;
    if (shown.has(key)) continue;
    shown.add(key);
    const row = document.createElement("tr");
    row.dataset.amount = p.amount;
    row.dataset.spent = p.spent === true ? "1" : "0";
    const cells = [String(p.height)];
    const tx = document.createElement("a");
    tx.href = `${EXPLORER}${p.txid}#vout=${p.vout}`;
    tx.target = "_blank";
    tx.rel = "noreferrer noopener";
    tx.textContent = `${p.txid.slice(0, 12)}…${p.txid.slice(-6)}:${p.vout}`;
    tx.title = `${p.txid}:${p.vout}`;
    row.append(...cells.map((t) => Object.assign(document.createElement("td"), { textContent: t })));
    row.append(Object.assign(document.createElement("td"), { className: "mono" }));
    row.lastChild.append(tx);
    row.append(Object.assign(document.createElement("td"), {
      textContent: formatBtc(p.amount), className: "num",
    }));
    row.append(Object.assign(document.createElement("td"), {
      textContent: p.label === null || p.label === undefined ? "" : p.label === 0 ? "change" : String(p.label),
    }));
    if (showSpent) {
      row.append(Object.assign(document.createElement("td"), {
        textContent: p.spent === true ? "spent" : p.spent === false ? "unspent" : "?",
      }));
    }
    // keep rows ordered by height
    const after = [...$("rows").children].find((r) => Number(r.firstChild.textContent) > p.height);
    $("rows").insertBefore(row, after || null);
  }
  const rows = [...$("rows").children];
  $("results").hidden = rows.length === 0;
  const total = rows.reduce((s, r) => s + Number(r.dataset.amount), 0);
  let text = `${rows.length} payment${rows.length === 1 ? "" : "s"}, ${formatBtc(total)} BTC received`;
  if (showSpent) {
    const unspent = rows.filter((r) => r.dataset.spent !== "1")
      .reduce((s, r) => s + Number(r.dataset.amount), 0);
    text += `, ${formatBtc(unspent)} BTC unspent`;
  }
  $("total").textContent = text;
}

// ---- form ----

function readForm() {
  const address = $("address").value.trim();
  const { scanPubkey, spendPubkey } = decodeSpAddress(address);
  const keyText = $("key").value.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(keyText)) throw new Error("the scan key must be 64 hex characters");
  let start;
  if ($("height").value.trim()) {
    start = Number($("height").value.trim());
    if (!Number.isInteger(start)) throw new Error("the block height must be a number");
  } else if ($("date").value) {
    start = heightForDate(new Date(`${$("date").value}T00:00:00Z`), info.tip);
  } else {
    throw new Error("pick a start date or block height (when the wallet was made)");
  }
  if (start < TAPROOT_HEIGHT || start > info.tip) {
    throw new Error(`the start block must be between ${TAPROOT_HEIGHT} and ${info.tip}`);
  }
  const labels = $("labels").value.split(/[\s,]+/).filter(Boolean).map(Number);
  if (labels.some((m) => !Number.isInteger(m) || m < 1 || m >= 2 ** 31) || labels.length > 100) {
    throw new Error("labels must be whole numbers from 1 (up to 100 of them)");
  }
  const mode = $("form").querySelector("input[name=mode]:checked").value;
  return { address, scanPubkey, spendPubkey, keyText, start, labels, mode };
}

// ---- scanning in the browser ----

async function fetchJson(url) {
  const response = await fetch(url);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `server error ${response.status}`);
  return body;
}

async function fetchBlocks(from, count, signal) {
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(`/v1/blocks?from=${from}&count=${count}`, { signal });
    if (response.ok) return parseBlocks(await response.arrayBuffer());
    if (attempt >= 5 || ![429, 502, 503, 504].includes(response.status)) {
      throw new Error(`could not get block data (error ${response.status})`);
    }
    await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
  }
}

function startWorkers(n, form) {
  const workers = [];
  const pending = new Map();
  let nextId = 1;
  const call = (worker, msg, transfer = []) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ ...msg, id }, transfer);
  });
  const ready = [];
  for (let i = 0; i < n; i++) {
    const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    worker.onmessage = ({ data }) => {
      if (data.type === "ready") return worker.onready(data);
      const p = pending.get(data.id);
      if (!p) return;
      pending.delete(data.id);
      if (data.type === "error") p.reject(new Error(data.message));
      else p.resolve(data);
    };
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(e.message || "scanner crashed"));
      pending.clear();
    };
    ready.push(new Promise((resolve, reject) => {
      worker.onready = resolve;
      setTimeout(() => reject(new Error("the scanner did not start (is WebAssembly blocked?)")), 30000);
    }));
    const scanKey = hexToBytes(form.keyText);
    worker.postMessage({ type: "init", scanKey, spendPubkey: form.spendPubkey, labels: form.labels },
      [scanKey.buffer]);
    workers.push(worker);
  }
  return {
    workers, ready: Promise.all(ready), call,
    close() {
      for (const w of workers) {
        w.postMessage({ type: "close" });
        setTimeout(() => w.terminate(), 1000);
      }
    },
  };
}

async function browserScan(form) {
  const n = Math.max(1, Math.min((navigator.hardwareConcurrency || 2) - 1, 8));
  const pool = startWorkers(n, form);
  const abort = new AbortController();
  let stopped = false;
  current = { stop() { stopped = true; abort.abort(); } };
  try {
    const [first] = await pool.ready;
    if (bytesToHex(first.scanPubkey) !== bytesToHex(form.scanPubkey)) {
      throw new Error("this scan key does not belong to this address");
    }
    const from = form.start, to = info.tip, total = to - from + 1;
    const started = performance.now();
    let done = 0, checked = 0;
    let candidates = [];
    const found = async (final) => {
      while (candidates.length && (final || candidates.length >= 8)) {
        const real = candidates.splice(0, 8);
        const heights = withDecoys(real, from, Math.max(to, from), 3).slice(0, info.max_output_heights);
        for (const h of real) if (!heights.includes(h)) heights.push(h);
        const blocks = await fetchJson(`/v1/outputs?heights=${heights.join(",")}`);
        const wanted = Object.fromEntries(real.map((h) => [h, blocks[h]]));
        const { payments } = await pool.call(pool.workers[0], { type: "match", blocks: wanted });
        addPayments(payments);
      }
    };
    const chunk = 504;
    let next = fetchBlocks(from, Math.min(chunk, total), abort.signal);
    for (let h = from; h <= to && !stopped;) {
      const blocks = await next;
      if (!blocks.length) throw new Error("no block data for this range yet; try again later");
      const after = blocks[blocks.length - 1].height + 1;
      next = after <= to ? fetchBlocks(after, Math.min(chunk, to - after + 1), abort.signal) : null;
      next?.catch(() => {});
      const parts = pool.workers.map(() => []);
      blocks.forEach((b, i) => parts[i % parts.length].push(b));
      const results = await Promise.all(parts.map((part, i) => part.length
        ? pool.call(pool.workers[i], { type: "check", blocks: part }) : { heights: [] }));
      for (const r of results) candidates.push(...r.heights);
      candidates.sort((a, b) => a - b);
      checked += blocks.length;
      done = after - from;
      h = after;
      const elapsed = (performance.now() - started) / 1000;
      $("bar").value = done / total;
      setStatus(`Block ${(after - 1).toLocaleString("en-US")} of ${to.toLocaleString("en-US")} · ` +
        `${Math.round(100 * done / total)}% · ${fmtDuration(elapsed / checked * (total - done))} left`);
      await found(false);
    }
    await found(true);
    if (stopped) {
      setStatus(`Stopped at block ${(from + done - 1).toLocaleString("en-US")}.`);
    } else {
      $("bar").value = 1;
      setStatus(`Done: scanned blocks ${from.toLocaleString("en-US")} to ${to.toLocaleString("en-US")}` +
        ` in ${fmtDuration((performance.now() - started) / 1000)}.` + (shown.size ? "" : " No payments found."));
    }
  } finally {
    pool.close();
  }
}

// ---- scanning on the server ----

async function serverScan(form) {
  const response = await fetch("/v1/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: form.address, scan_key: form.keyText, from: form.start,
      labels: form.labels }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `server error ${response.status}`);
  history.replaceState(null, "", `#scan=${body.id}`);
  await followJob(body.id);
}

async function followJob(id) {
  let stopped = false;
  current = {
    stop() {
      stopped = true;
      fetch(`/v1/jobs/${id}`, { method: "DELETE" }).catch(() => {});
      history.replaceState(null, "", location.pathname);
    },
  };
  for (;;) {
    if (stopped) {
      setStatus("Stopped. The scan and its results were deleted from the server.");
      return;
    }
    const response = await fetch(`/v1/jobs/${id}`);
    const job = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(job.error || `server error ${response.status}`);
    $("bar").value = job.progress;
    if (job.status === "queued") {
      setStatus(`Waiting in line (position ${job.position}).`);
    } else if (job.status === "running") {
      setStatus(`Block ${(job.scanned_to ?? job.from).toLocaleString("en-US")} of ` +
        `${job.to.toLocaleString("en-US")} · ${Math.round(100 * job.progress)}%`);
    } else if (job.status === "done") {
      addPayments(job.payments);
      setStatus(`Done: scanned blocks ${job.from.toLocaleString("en-US")} to ` +
        `${job.to.toLocaleString("en-US")}.` + (job.payments.length ? "" : " No payments found.") +
        " The server deletes this scan within 24 hours.");
      $("forget").hidden = false;
      $("forget").onclick = async () => {
        await fetch(`/v1/jobs/${id}`, { method: "DELETE" }).catch(() => {});
        history.replaceState(null, "", location.pathname);
        $("forget").hidden = true;
        setStatus("Deleted from the server.");
      };
      return;
    } else {
      throw new Error(job.error || "the scan failed");
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

// ---- wiring ----

async function run(task) {
  setError("");
  setRunning(true);
  $("status").hidden = false;
  $("bar").value = 0;
  try {
    await task();
  } catch (err) {
    if (err.name !== "AbortError") setError(err.message || String(err));
  } finally {
    current = null;
    setRunning(false);
  }
}

function syncMode() {
  const server = $("mode-server").checked;
  $("consent").hidden = !server;
  $("start").disabled = server && !$("agree").checked;
}

$("form").addEventListener("submit", (event) => {
  event.preventDefault();
  let form;
  try {
    form = readForm();
  } catch (err) {
    setError(err.message);
    return;
  }
  $("key").value = "";
  $("forget").hidden = true;
  resetResults(form.mode === "server");
  run(() => (form.mode === "server" ? serverScan(form) : browserScan(form)));
});
$("stop").addEventListener("click", () => current?.stop());
for (const el of document.querySelectorAll("input[name=mode], #agree")) el.addEventListener("change", syncMode);
$("height").addEventListener("input", () => { if ($("height").value) $("date").value = ""; });
$("date").addEventListener("input", () => { if ($("date").value) $("height").value = ""; });

loadInfo().then(() => {
  syncMode();
  const resume = /^#scan=([\w-]+)$/.exec(location.hash);
  if (resume) {
    resetResults(true);
    run(() => followJob(resume[1]));
  }
}).catch((err) => setError(err.message));
