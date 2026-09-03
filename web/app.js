// Tailcat Rust web app. The Rust WebAssembly module exposes
// globals tailcatListen and tailcatDial.
import init from "./tailcat.js";

const CHUNK = 64 * 1024;
const KEY_STORAGE = "tailcat-web-key";

const params = new URLSearchParams(location.search);
const verbose = params.has("verbose");

// canonicalDERPMapURL is the public tailcat DERP map, which allows
// cross-origin fetches with CORS headers.
const canonicalDERPMapURL = "https://tailcat.dev/derpmap.json";

// pickDERPMapURL returns the DERP map URL to hand to
// tailcatListen/tailcatDial: the ?derpmap= query parameter if given,
// and the canonical public map when hosted on GitHub Pages, which
// serves no map of its own. Anywhere else (tailcat-web, the
// integration tests, or this page copied onto some other site), it
// prefers a same-origin derpmap.json if the host serves one and
// otherwise falls back to the canonical map.
async function pickDERPMapURL() {
  if (params.get("derpmap")) {
    return new URL(params.get("derpmap"), location.href).toString();
  }
  if (location.hostname.endsWith(".github.io")) {
    return canonicalDERPMapURL;
  }
  const sameOrigin = new URL("derpmap.json", location.href).toString();
  try {
    const resp = await fetch(sameOrigin, { method: "HEAD" });
    if (resp.ok) {
      return sameOrigin;
    }
  } catch (e) {}
  return canonicalDERPMapURL;
}
const derpMapURL = await pickDERPMapURL();

// tcTest is the state surface polled by the headless-browser
// interoperability tests in the external Go reference repository.
window.tcTest = {
  ready: false,
  listenAddr: null,
  recvBytes: 0,
  recvSha256: null,
  recvDone: false,
  sentBytes: 0,
  sentSha256: null,
  sendDone: false,
  errors: [],
};
window.addEventListener("error", (e) => window.tcTest.errors.push(String(e.message)));
window.addEventListener("unhandledrejection", (e) => window.tcTest.errors.push(String(e.reason)));

const $ = (id) => document.getElementById(id);
const setStatus = (msg) => { $("status").textContent = msg; };

async function hex(digest) {
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

// countProgress wraps a stream, updating the page's progress bar and
// status line as bytes pass through: loaded/total drives the bar,
// wireBytes is the transfer size shown to the user.
function countProgress(stream, total, wireBytes) {
  const ofMB = wireBytes > 0 ? ` of ${(wireBytes / (1 << 20)).toFixed(1)} MB` : "";
  const bar = $("load-progress");
  let loaded = 0;
  return stream.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      loaded += chunk.byteLength;
      if (total > 0) {
        bar.value = loaded / total;
        const pct = Math.min(100, Math.floor(100 * loaded / total));
        setStatus(`Loading WebAssembly… ${pct}%${ofMB}`);
      } else {
        setStatus(`Loading WebAssembly…`);
      }
      controller.enqueue(chunk);
    },
  }));
}

// fetchWasm fetches the wasm with load progress. Static hosts like
// GitHub Pages can't do Content-Encoding negotiation (and don't
// compress wasm), so they serve only the pre-gzipped main.wasm.gz,
// fetched raw here and decompressed in the page. Servers that
// negotiate (the webdemo package) don't serve that name; on 404 the
// plain main.wasm fetch below gets the negotiated encoding, which the
// browser decompresses itself.
async function fetchWasm() {
  const gz = await fetch("main.wasm.gz");
  if (gz.ok) {
    // The counted stream sees compressed bytes, so progress runs
    // against the compressed size on the wire.
    const size = Number(gz.headers.get("Content-Length")) || 0;
    const wasm = countProgress(gz.body, size, size)
      .pipeThrough(new DecompressionStream("gzip"));
    return new Response(wasm, { headers: { "Content-Type": "application/wasm" } });
  }

  const resp = await fetch("main.wasm");
  if (!resp.ok) {
    throw new Error(`fetching main.wasm: ${resp.status}`);
  }
  // The body stream yields decompressed bytes, so progress is
  // tracked against the uncompressed size, but the size shown to the
  // user is what actually crosses the wire.
  const total = Number(resp.headers.get("X-Uncompressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const wireBytes = Number(resp.headers.get("X-Compressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const counted = countProgress(resp.body, total, wireBytes);
  return new Response(counted, { headers: { "Content-Type": "application/wasm" } });
}

// Boot the Rust WebAssembly module.
await init({ module_or_path: fetchWasm() });
window.tcTest.ready = true;
$("load-progress").remove();
setStatus("Ready.");
$("listen-btn").disabled = false;
$("send-btn").disabled = false;
$("send-text-btn").disabled = false;

// --- Receive side ---

async function startListener() {
  $("listen-btn").disabled = true;
  setStatus("Starting listener…");
  const persist = $("persist-key").checked;
  const privateKey = persist ? (localStorage.getItem(KEY_STORAGE) || "") : "";
  try {
    const ln = await tailcatListen({ derpMapURL, privateKey, verbose, onConnection });
    if (persist) {
      localStorage.setItem(KEY_STORAGE, ln.privateKeyJSON);
    }
    $("listen-addr").textContent = ln.addr;
    $("listen-info").classList.remove("hidden");
    setStatus("Listening. Share the address with the sender.");
    window.tcTest.listenAddr = ln.addr;
  } catch (err) {
    setStatus("Listen failed: " + err.message);
    window.tcTest.errors.push(String(err));
    $("listen-btn").disabled = false;
  }
}

function onConnection(conn) {
  if (params.get("sink") === "hash") {
    hashSink(conn);
    return;
  }
  const li = document.createElement("li");
  const btn = document.createElement("button");
  btn.textContent = "Save incoming file…";
  const textBtn = document.createElement("button");
  textBtn.textContent = "Show as text";
  const progress = document.createElement("span");
  li.append(btn, " ", textBtn, " ", progress);
  $("incoming").append(li);
  const chose = () => {
    btn.disabled = true;
    textBtn.disabled = true;
  };
  textBtn.onclick = () => {
    chose();
    receiveText(conn, li, progress);
  };
  btn.onclick = async () => {
    chose();
    try {
      // Stream to disk. The pull-based conn.read means the sender
      // stalls on TCP backpressure while the user picks a file, and
      // while the disk keeps up; nothing is buffered in memory.
      const handle = await showSaveFilePicker({ suggestedName: "tailcat-download" });
      const w = await handle.createWritable();
      let n = 0;
      for (let chunk; (chunk = await conn.read()) !== null; ) {
        await w.write(chunk);
        n += chunk.length;
        progress.textContent = `${n} bytes`;
      }
      await w.close();
      conn.close();
      progress.textContent = `done, ${n} bytes`;
    } catch (err) {
      conn.close();
      progress.textContent = "failed: " + err.message;
      window.tcTest.errors.push(String(err));
    }
  };
}

// receiveText reads the whole incoming stream into memory and shows
// it as copyable text under the connection's list item.
async function receiveText(conn, li, progress) {
  try {
    const chunks = [];
    let n = 0;
    for (let chunk; (chunk = await conn.read()) !== null; ) {
      chunks.push(chunk);
      n += chunk.length;
      progress.textContent = `${n} bytes`;
    }
    conn.close();
    const all = new Uint8Array(n);
    let off = 0;
    for (const c of chunks) {
      all.set(c, off);
      off += c.length;
    }
    const text = new TextDecoder().decode(all);
    const box = document.createElement("code");
    box.className = "recv-text";
    box.textContent = text;
    const copyBtn = document.createElement("button");
    copyBtn.textContent = "Copy";
    copyBtn.onclick = () => navigator.clipboard.writeText(text);
    li.append(box, copyBtn);
    progress.textContent = `done, ${n} bytes`;
  } catch (err) {
    conn.close();
    progress.textContent = "failed: " + err.message;
    window.tcTest.errors.push(String(err));
  }
}

// hashSink is the test-mode receiver: instead of the file picker
// (which needs a user gesture that headless Chrome can't provide), it
// counts and hashes the received bytes into tcTest.
async function hashSink(conn) {
  const chunks = [];
  let n = 0;
  for (let chunk; (chunk = await conn.read()) !== null; ) {
    chunks.push(chunk);
    n += chunk.length;
    window.tcTest.recvBytes = n;
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  window.tcTest.recvSha256 = await sha256Hex(all);
  window.tcTest.recvDone = true;
  conn.close();
}

$("listen-btn").onclick = startListener;
$("copy-addr").onclick = () => navigator.clipboard.writeText($("listen-addr").textContent);

// --- Send side ---

async function sendStream(addr, size, readChunk, progressEl) {
  const conn = await tailcatDial({ addr, derpMapURL, verbose });
  let off = 0;
  while (off < size) {
    const chunk = await readChunk(off, Math.min(CHUNK, size - off));
    await conn.write(chunk);
    off += chunk.length;
    progressEl.textContent = `${off} / ${size} bytes`;
  }
  await conn.closeWrite();
  // Wait for the receiver's close: like the CLI, the peer's EOF is
  // the confirmation that everything we sent was delivered.
  while ((await conn.read()) !== null) {}
  conn.close();
  window.tcTest.sentBytes = off;
  window.tcTest.sendDone = true;
  progressEl.textContent = `sent ${off} bytes`;
}

$("send-btn").onclick = async () => {
  const addr = $("send-addr").value.trim();
  const file = $("send-file").files[0];
  if (!addr || !file) {
    setStatus("Enter an address and pick a file first.");
    return;
  }
  $("send-btn").disabled = true;
  setStatus("Connecting…");
  try {
    await sendStream(addr, file.size,
      async (off, n) => new Uint8Array(await file.slice(off, off + n).arrayBuffer()),
      $("send-progress"));
    setStatus("Done.");
  } catch (err) {
    setStatus("Send failed: " + err.message);
    window.tcTest.errors.push(String(err));
  }
  $("send-btn").disabled = false;
};

$("send-text-btn").onclick = async () => {
  const addr = $("send-addr").value.trim();
  const text = $("send-text").value;
  if (!addr || !text) {
    setStatus("Enter an address and type some text first.");
    return;
  }
  $("send-text-btn").disabled = true;
  setStatus("Connecting…");
  try {
    const data = new TextEncoder().encode(text);
    await sendStream(addr, data.length,
      async (off, n) => data.subarray(off, off + n),
      $("send-progress"));
    setStatus("Done.");
  } catch (err) {
    setStatus("Send failed: " + err.message);
    window.tcTest.errors.push(String(err));
  }
  $("send-text-btn").disabled = false;
};

// --- Test automation via query parameters ---

if (params.get("mode") === "listen") {
  startListener();
} else if (params.get("mode") === "send") {
  const addr = params.get("addr");
  const size = parseInt(params.get("bytes"), 10);
  const data = new Uint8Array(size);
  // crypto.getRandomValues caps each call at 64 KiB.
  for (let off = 0; off < size; off += CHUNK) {
    crypto.getRandomValues(data.subarray(off, Math.min(off + CHUNK, size)));
  }
  window.tcTest.sentSha256 = await sha256Hex(data);
  try {
    await sendStream(addr, size, async (off, n) => data.subarray(off, off + n), $("send-progress"));
  } catch (err) {
    window.tcTest.errors.push(String(err));
  }
}
