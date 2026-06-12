// 15.4 SRI — placeholders rewritten by scripts/build-sri.sh on release build.
// Until rewritten, runtime check short-circuits with a dev-mode warning.
const CRYPTO_JS_SRI   = "sha384-VlqKsEfGZXBbbOzYa95XrbRww3j56CFXwTVcOi6QgO6LbUOz+N4QqjR2/j55J2Uh";
const CRYPTO_WASM_SRI = "sha384-o85xZSK3Djr9z0KikYeON5OoXpxxwCNSNQZMMbYZHafJRxbxwULiciZ3qWNpLo64";
const SRI_PLACEHOLDER_PREFIX = "__SRI_";

async function sha384Base64(buf) {
    const digest = await crypto.subtle.digest("SHA-384", buf);
    let bin = "";
    for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b);
    return btoa(bin);
}

// Cache-busting: derive a version tag from the expected SRI hash so the URL
// changes whenever the file content changes. Old edge/browser cache entries
// (keyed on the previous URL) can then never be served against a new hash.
function sriVersion(sri) {
    return sri.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12);
}

async function verifyAndLoadCrypto() {
    const jsResp = await fetch(`./pkg/beem_crypto.js?v=${sriVersion(CRYPTO_JS_SRI)}`);
    if (!jsResp.ok) throw new Error(`crypto.js fetch ${jsResp.status}`);
    const jsBytes = await jsResp.arrayBuffer();
    const jsHash  = `sha384-${await sha384Base64(jsBytes)}`;

    const wasmResp = await fetch(`./pkg/beem_crypto_bg.wasm?v=${sriVersion(CRYPTO_WASM_SRI)}`);
    if (!wasmResp.ok) throw new Error(`wasm fetch ${wasmResp.status}`);
    const wasmBytes = await wasmResp.arrayBuffer();
    const wasmHash  = `sha384-${await sha384Base64(wasmBytes)}`;

    const devMode = CRYPTO_JS_SRI.startsWith(SRI_PLACEHOLDER_PREFIX)
                 || CRYPTO_WASM_SRI.startsWith(SRI_PLACEHOLDER_PREFIX);
    if (devMode) {
        console.warn("[beem] SRI dev mode — hashes not yet injected. Run scripts/build-sri.sh before release.");
        console.warn(`[beem] observed crypto.js  ${jsHash}`);
        console.warn(`[beem] observed wasm       ${wasmHash}`);
    } else {
        if (jsHash !== CRYPTO_JS_SRI) {
            throw new Error(`SRI fail: crypto.js expected ${CRYPTO_JS_SRI} got ${jsHash}`);
        }
        if (wasmHash !== CRYPTO_WASM_SRI) {
            throw new Error(`SRI fail: crypto.wasm expected ${CRYPTO_WASM_SRI} got ${wasmHash}`);
        }
    }

    const blobUrl = URL.createObjectURL(new Blob([jsBytes], { type: "text/javascript" }));
    const mod     = await import(blobUrl);
    URL.revokeObjectURL(blobUrl);
    await mod.default({ module_or_path: wasmBytes });
    return mod;
}

const $ = (id) => document.getElementById(id);

// Hide every top-level view and surface #view-fatal. Used for unrecoverable
// errors (SRI mismatch, pre-chat connection error). Optional title/body
// override the markup defaults.
function showFatalView(title, body) {
    for (const id of ["view-landing", "view-sender", "view-receiver", "view-chat"]) {
        const el = $(id);
        if (el) el.hidden = true;
    }
    if (title) {
        const t = document.querySelector("#view-fatal .bm-fatal-title");
        if (t) t.textContent = title;
    }
    if (body) {
        const b = document.querySelector("#view-fatal .bm-fatal-body");
        if (b) b.textContent = body;
    }
    const fatal = $("view-fatal");
    if (fatal) fatal.hidden = false;
}

let cryptoMod;
try {
    cryptoMod = await verifyAndLoadCrypto();
} catch (e) {
    showFatalView("Integrity check failed", e && e.message ? e.message : "Cryptographic module verification failed.");
    throw e;
}
const {
    start_pake, finish_pake,
    encrypt, decrypt,
    x25519_keypair, x25519_shared,
    mlkem_keygen, mlkem_encaps, mlkem_decaps,
    hkdf_combine,
} = cryptoMod;

const views = {
    landing:  $("view-landing"),
    sender:   $("view-sender"),
    receiver: $("view-receiver"),
    chat:     $("view-chat"),
};

function show(name) {
    for (const k in views) views[k].hidden = (k !== name);
}

let rateCountdownTimer = null;

function clearRateBanners() {
    document.querySelectorAll(".bm-rate-banner").forEach(el => { el.hidden = true; });
    if (rateCountdownTimer !== null) {
        clearInterval(rateCountdownTimer);
        rateCountdownTimer = null;
    }
}

function fmtMMSS(seconds) {
    const s = Math.max(0, seconds | 0);
    return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function startRateCountdown(targetEl, totalSeconds) {
    if (rateCountdownTimer !== null) clearInterval(rateCountdownTimer);
    let remaining = totalSeconds;
    const tick = () => {
        if (remaining <= 0) {
            targetEl.textContent = "0:00";
            clearInterval(rateCountdownTimer);
            rateCountdownTimer = null;
            return;
        }
        targetEl.textContent = fmtMMSS(remaining);
        remaining -= 1;
    };
    tick();
    rateCountdownTimer = setInterval(tick, 1000);
}

// 15.10 App-defined WS close codes — must match server/src/main.rs.
// Numeric codes survive Cloudflare / reverse proxies; reason strings don't.
const CLOSE = {
    RATE_COOLDOWN: 4001,
    BAN_30M: 4002,
    BAN_24H: 4003,
    CODE_FORMAT: 4004,
    CODE_MISSING: 4005,
    SESSION_TIMEOUT: 4006,
    PEER_LEFT: 4007,
};

// Reason (when preserved) carries remaining seconds as plain digits.
function reasonSeconds(reason, fallback) {
    if (!reason) return fallback;
    const m = String(reason).match(/(\d+)/);
    return m ? parseInt(m[1], 10) : fallback;
}

// Map a server close code to the matching tiered-ban banner.
function showRateBanner(code, reason) {
    if (code === CLOSE.BAN_24H) {
        clearRateBanners();
        const b = document.querySelector(".bm-rate-banner--24h");
        if (b) b.hidden = false;
        return true;
    }
    if (code === CLOSE.BAN_30M) {
        clearRateBanners();
        const b = document.querySelector(".bm-rate-banner--30min");
        if (b) b.hidden = false;
        return true;
    }
    if (code === CLOSE.RATE_COOLDOWN) {
        clearRateBanners();
        const banner = document.querySelector(".bm-rate-banner--5min");
        if (banner) {
            const secs = reasonSeconds(reason, 300);
            const t = banner.querySelector("#rate-countdown");
            if (t) startRateCountdown(t, secs);
            banner.hidden = false;
        }
        return true;
    }
    return false;
}

// Update the sender-side status chip without nuking its dot+label structure.
// tone: "warn" (waiting, pulsing) | "err" (failure, static) | "ok" (success).
function setWaitMsg(text, tone) {
    const chip = $("wait-msg");
    if (!chip) return;
    chip.classList.remove("bm-status-chip--warn", "bm-status-chip--err", "bm-status-chip--ok");
    chip.classList.add(`bm-status-chip--${tone}`);
    const dot = chip.querySelector(".bm-status-dot");
    if (dot) dot.classList.toggle("bm-status-dot--waiting", tone === "warn");
    const label = chip.querySelector(".bm-wait-label");
    if (label) label.textContent = text;
}

async function fileChecksum(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesEq(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// Chat / file frame type tags
const T_TEXT      = 0x00;
const T_FILE_HDR  = 0x01;
const T_FILE_CHK  = 0x02;
const T_FILE_END  = 0x03;
const T_KEEPALIVE = 0x04; // WS heartbeat during DC transfers — keeps tunnel alive, receiver silently ignores
const T_BYE       = 0x05; // immediate vanish signal — peer calls endChatSession() without waiting for server grace
const T_FILE_NACK = 0x06; // missing chunk indices (uint32 BE each) — receiver→sender retransmit request
const T_FILE_ACK  = 0x07; // chunk receipt acknowledgement — receiver→sender, one per chunk over WS relay
const T_FILE_CANCEL = 0x08; // 16.8.2 — payload[0]: 0x00 sender aborted its outgoing file, 0x01 receiver rejects the incoming file. Always sent via WS, so it overtakes queued DC chunks.
const T_FILE_DONE = 0x09; // delivery confirmation — receiver→sender after successful assembly; flips the sender row "Sent" → "Delivered"
// WebRTC signaling — travel over existing encrypted WS relay, no server changes needed
const T_RTC_OFFER = 0x10;
const T_RTC_ANSWER = 0x11;
const T_RTC_ICE   = 0x12;

// Handshake byte sizes
const PAKE_MSG_LEN  = 33;
const X25519_PK_LEN = 32;
const MLKEM_EK_LEN  = 1184;
const MLKEM_DK_LEN  = 2400;
const MLKEM_CT_LEN  = 1088;
const MLKEM_SS_LEN  = 32;
const RX_INFO_LEN   = PAKE_MSG_LEN + X25519_PK_LEN;                 // 65 (receiver -> sender)
const TX_INFO_LEN   = PAKE_MSG_LEN + X25519_PK_LEN + MLKEM_EK_LEN;  // 1249 (sender -> receiver)

let ws = null;
let wsGen = 0; // incremented each openWs() call; stale close handlers self-discard
let role = null;
let currentCode = null;
let pakeState = null;
let ownPakeMsg = null;   // sender only
let xSk = null, xPk = null;
let rxXPk = null; // receiver's X25519 pk, saved by sender during await-rx-info for transcript
let mlDk = null, mlEk = null; // sender only
let pakeKey = null;
let xShared = null;
let derivedKey = null;   // final combined 32-byte key
let myHash = null;           // own confirmation tag (sent to peer)
let expectedPeerHash = null;  // peer's expected confirmation tag (directional)
// Sender: "await-rx-info" -> "await-ct" -> "await-hash" -> "chat"
// Receiver: "await-sender-info" -> "await-hash" -> "chat"
let step = null;
let aborted = false;
let sendCounterWS = 0n;
let recvCounterWS = -1n; // per-transport strictly increasing; prevents cross-transport replay drops
// 16.9.2: one counter pair per DC path; nonce[3] = 1 + pathId keeps the four
// counter spaces disjoint from each other and from WS (0x00) — no nonce reuse
// across paths even though every path encrypts under the same directional key.
// 16.9.5: DC paths are ordered:false, so frames legitimately arrive out of
// order WITHIN a path — strict-greater would drop the late ones. recvCountersDC
// is now the highest-seen watermark per path; recvMasksDC is a sliding bitmap
// (DTLS/IPsec style) of the REPLAY_WINDOW counters below it: bit d set means
// counter (watermark − d) was already accepted.
let sendCountersDC = [0n, 0n, 0n, 0n];
let recvCountersDC = [-1n, -1n, -1n, -1n];
let recvMasksDC = [0n, 0n, 0n, 0n];

// Window depth: reorder span on a path is bounded by what's in flight there
// (DC_BUFFER_CAP 2 MB ≈ 16 chunk frames + network BDP) — 1024 is ~60× that.
const REPLAY_WINDOW = 1024n;
const REPLAY_MASK_ALL = (1n << REPLAY_WINDOW) - 1n;

// Pre-decrypt gate: true if this counter could be fresh (ahead of the
// watermark, or inside the window and not yet seen). Cheap reject for replays.
function dcReplayFresh(pid, c) {
    const high = recvCountersDC[pid];
    if (c > high) return true;
    const d = high - c;
    if (d >= REPLAY_WINDOW) return false; // older than the window tracks — drop
    return ((recvMasksDC[pid] >> d) & 1n) === 0n;
}

// Record an accepted counter. Call ONLY after the frame authenticated
// (decrypt succeeded) — otherwise forged counters could race the watermark
// forward and the window would drop the legitimate frames behind it (DoS).
function dcReplayMark(pid, c) {
    const high = recvCountersDC[pid];
    if (c > high) {
        const shift = c - high;
        recvMasksDC[pid] = shift >= REPLAY_WINDOW
            ? 1n
            : ((recvMasksDC[pid] << shift) | 1n) & REPLAY_MASK_ALL;
        recvCountersDC[pid] = c;
    } else {
        recvMasksDC[pid] |= 1n << (high - c);
    }
}

// WebRTC direct channels — set up after PAKE completes, falls back to WS relay silently.
// 16.9.2 parallel striping: N independent peer connections (separate SCTP
// associations — channels on ONE connection would share a single congestion
// window and gain nothing). File chunks stripe across whichever paths are open,
// lifting the per-stream window÷RTT ceiling on high-latency links ~N×.
const DC_PATHS = 4; // Ookla's own floor; more streams self-congest past the sweet spot
let rtcPaths = []; // pathId → { id, pc, dc, pendingIce } or null
let useRTC = false;
// 16.9.1 DataChannel auto-reconnect: on mid-session DC loss the sender (offerer)
// rebuilds the peer connection with a fresh offer over WS signalling; active
// chunk loops park on waitDcSettled() instead of silently downgrading to the
// WS relay. Counters are NOT reset — same AEAD key, nonces must stay unique.
const DC_RECONNECT_TRIES = 3;
const DC_RECONNECT_OPEN_MS = 5000;
let dcReconnecting = false;
let dcWaiters = [];

// 15.10b Cloudflare Tunnel drops WS close frames — ev.code arrives as 1006.
// Server now prepends a "BEEM-CLOSE:<code>:<reason>" text frame before every close.
// We stash it here so the close handler can fall back when the real frame is lost.
let preCloseCode = 0;
let preCloseReason = "";

// Mobile resume: when iOS/Android freezes the tab (file picker, gallery scroll)
// the OS can kill the WS. Server holds the room for RESUME_GRACE_SECS; the
// client gets that same window to silently reopen the WS and re-enter chat
// mode with the existing derivedKey + counters. Deadline is absolute (ms epoch)
// so repeated reconnect attempts don't extend the total grace.
const RESUME_GRACE_MS = 30_000;
let resumeUntil = 0;
let resumeAttempt = 0;   // backoff step within the current grace window
let resumeTimer = null;
let wsKeepaliveTimer = null;
let wakeLock = null;

const COUNTER_MAX = (1n << 64n) - 1n;

// mirror of server MAX_WS_FRAME (200 KiB). The server enforces this on relayed
// traffic, but the relay itself is untrusted — cap incoming frames client-side
// before decrypt so a hostile relay/peer can't force a giant allocation. Largest
// legitimate frame is a 128 KiB chunk + 29 B crypto overhead.
const MAX_FRAME = 200 * 1024;

// transport: 0 = WebSocket, 1+pathId = DataChannel path (16.9.2) — byte 3 of the
// nonce separates the counter spaces so no nonce repeats across transports/paths
function makeNonce(counter, transport = 0) {
    if (counter >= COUNTER_MAX) { abort("Session ended: counter exhausted."); return null; }
    // 12-byte nonce: [0,0,0,transport(1B)] || 8-byte big-endian counter
    const n = new Uint8Array(12);
    n[3] = transport;
    const view = new DataView(n.buffer);
    view.setBigUint64(4, counter, false);
    return n;
}

const textEnc = new TextEncoder();
const textDec = new TextDecoder();

// Directional AEAD key separation — fixes bidirectional nonce reuse.
// Both peers derive the SAME combined secret `derivedKey`. The nonce is built only
// from (counter, transport), so without a per-direction split the sender and the
// receiver would both start at counter 0 and encrypt different plaintexts under the
// identical (key, nonce) pair — catastrophic for ChaCha20-Poly1305 (keystream reuse
// + Poly1305 forgery, exploitable by the relay). HKDF-Expand splits the shared secret
// into two independent traffic keys so sender->receiver and receiver->sender never
// share a key, even though both counter spaces still start at 0.
let sendKey = null, recvKey = null;

async function hkdfExpand(keyBytes, infoStr) {
    const base = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: textEnc.encode(infoStr) },
        base, 256);
    return new Uint8Array(bits);
}

// Called once on each side right after `derivedKey` is computed, before chat begins.
async function deriveDirectionalKeys() {
    const s2r = await hkdfExpand(derivedKey, "beem-v1 s2r"); // sender -> receiver traffic
    const r2s = await hkdfExpand(derivedKey, "beem-v1 r2s"); // receiver -> sender traffic
    if (role === "sender") { sendKey = s2r; recvKey = r2s; }
    else                   { sendKey = r2s; recvKey = s2r; }
}

// directional key-confirmation tags. Both sides previously sent the identical
// SHA-256(derivedKey) prefix and compared incoming frames against their OWN tag,
// so the (untrusted) relay could reflect each side's tag back and fake a passed
// confirmation on a mismatched code. Distinct HKDF info labels per direction make
// a reflected tag fail the comparison; failure then surfaces as the clean
// "Wrong code" abort instead of decrypt noise mid-chat.
async function deriveConfirmTags() {
    const mine   = role === "sender" ? "beem-v1 confirm-A" : "beem-v1 confirm-B";
    const theirs = role === "sender" ? "beem-v1 confirm-B" : "beem-v1 confirm-A";
    myHash           = (await hkdfExpand(derivedKey, mine)).slice(0, 16);
    expectedPeerHash = (await hkdfExpand(derivedKey, theirs)).slice(0, 16);
}

// Defense-in-depth: overwrite secret bytes with zeros, then drop the
// references. Every line is guarded, so this is safe to call in ANY state —
// including before keys exist (values are null) or post-handshake. Hoisted
// function declaration so teardown paths above can call it.
function zeroizeKeys() {
    for (const k of [derivedKey, sendKey, recvKey, pakeKey, xShared, xSk, xPk, mlDk, mlEk, ownPakeMsg, myHash, expectedPeerHash]) {
        if (k && typeof k.fill === "function") { try { k.fill(0); } catch (_) {} }
    }
    // pakeState is a wasm-bindgen handle, not a typed array — fill() can't reach
    // the SPAKE2 scalar inside WASM memory; only free() drops it. Guard on
    // __wbg_ptr: finish_pake consumes the handle (ptr becomes 0) and freeing a
    // consumed handle would pass a null pointer into Rust.
    if (pakeState && pakeState.__wbg_ptr) { try { pakeState.free(); } catch (_) {} }
    pakeState = null;
    derivedKey = sendKey = recvKey = pakeKey = xShared = null;
    xSk = xPk = mlDk = mlEk = ownPakeMsg = myHash = expectedPeerHash = null;
}

$("btn-send").addEventListener("click", startSender);
$("btn-receive").addEventListener("click", () => {
    $("receiver-error").textContent = "";
    clearRateBanners();
    $("code-input").value = "";
    show("receiver");
    $("code-input").focus();
});

$("btn-join").addEventListener("click", joinAsReceiver);
$("code-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") joinAsReceiver();
});
$("code-input").addEventListener("input", () => {
    if ($("code-input").value.length === 5) joinAsReceiver();
});

$("btn-chat-send").addEventListener("click", sendChat);
$("chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChat();
    }
});

// Copy 5-digit pairing code to clipboard. localhost + https are both
// secure contexts, so navigator.clipboard is available; falls back silently.
const copyBtn = document.querySelector(".bm-copy-btn");
if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
        if (!currentCode) return;
        try {
            await navigator.clipboard.writeText(currentCode);
        } catch (_) {
            return;
        }
        const label = copyBtn.querySelector(".bm-copy-label");
        const prev  = label ? label.textContent : null;
        copyBtn.classList.add("bm-copy-btn--copied");
        if (label) label.textContent = "Copied";
        setTimeout(() => {
            copyBtn.classList.remove("bm-copy-btn--copied");
            if (label && prev !== null) label.textContent = prev;
        }, 2000);
    });
}

$("btn-file-pick").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) sendFile(f);
    e.target.value = "";
});

// Clipboard paste — intercept only when clipboard contains a file (screenshot, copied file).
// Text pastes fall through untouched to the textarea.
document.addEventListener("paste", (e) => {
    if (step !== "chat") return;
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
        if (item.kind === "file") {
            const file = item.getAsFile();
            if (file) { e.preventDefault(); sendFile(file); return; }
        }
    }
});

// Drag & drop — overlay approach prevents dragleave-on-child flicker
$("view-chat").addEventListener("dragenter", (e) => {
    if (step !== "chat" || !e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    $("drop-overlay").hidden = false;
});
$("drop-overlay").addEventListener("dragover", (e) => e.preventDefault());
$("drop-overlay").addEventListener("dragleave", () => { $("drop-overlay").hidden = true; });
$("drop-overlay").addEventListener("drop", (e) => {
    e.preventDefault();
    $("drop-overlay").hidden = true;
    const file = e.dataTransfer.files[0];
    if (file) sendFile(file);
});

async function startSender() {
    try {
        const res = await fetch("/new", { method: "POST" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const { code } = await res.json();
        role = "sender";
        currentCode = code;
        const bc = $("big-code");
        bc.textContent = "";
        for (const digit of code) {
            const sp = document.createElement("span");
            sp.textContent = digit;
            bc.appendChild(sp);
        }
        setWaitMsg("Waiting for peer\u2026", "warn");
        show("sender");
        acquireWakeLock();
        openWs(code);
    } catch (e) {
        showFatalView("Could not start session", e && e.message ? e.message : "Failed to generate pairing code.");
    }
}

function joinAsReceiver() {
    // Re-entry guard. CONNECTING alone is not enough: the 5th-digit auto-submit
    // opens the WS in ~ms, so an Enter press right after it finds the socket
    // already OPEN, fires a second join, and the duplicate 65-byte hello lands
    // on the sender's await-ct as a wrong-size frame → "ct size" abort.
    if (ws && (ws.readyState === WebSocket.CONNECTING ||
               (ws.readyState === WebSocket.OPEN && step !== null && step !== "chat"))) return;
    const code = $("code-input").value.trim();
    if (!/^\d{5}$/.test(code)) {
        $("receiver-error").textContent = "Please enter exactly 5 digits.";
        return;
    }
    $("receiver-error").textContent = "";
    role = "receiver";
    currentCode = code;
    openWs(code);
}

function openWs(code, resume = false) {
    const myGen = ++wsGen;
    if (ws) { try { ws.close(); } catch (_) {} }
    if (!resume) {
        pakeState = ownPakeMsg = null;
        xSk = xPk = null;
        mlDk = mlEk = null;
        pakeKey = xShared = derivedKey = myHash = expectedPeerHash = null;
        sendKey = recvKey = null;
        aborted = false;
        sendCounterWS = 0n;
        recvCounterWS = -1n;
        sendCountersDC = [0n, 0n, 0n, 0n];
        recvCountersDC = [-1n, -1n, -1n, -1n];
        recvMasksDC = [0n, 0n, 0n, 0n];
        drainAckWaiters();
    }
    preCloseCode = 0;
    preCloseReason = "";

    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws?code=${code}`);
    ws.binaryType = "arraybuffer";

    ws.addEventListener("open", () => {
        if (resume) {
            // Handshake state is already in memory; server just relays bytes.
            step = "chat";
            resumeUntil = 0;
            // Chunks in flight on the dead socket will never be ACKed — reset the
            // window so a parked sendFile loop resumes; losses are repaired by the
            // receiver's T_FILE_NACK round at T_FILE_END.
            drainAckWaiters();
            // Don't flicker chip if DC is still actively transferring
            if (openDcPaths().length === 0) {
                setChatChip("ok", "Connected");
            }
            return;
        }
        const xkp = x25519_keypair();
        xSk = xkp.slice(0, 32);
        xPk = xkp.slice(32, 64);
        xkp.fill(0); // wipe intermediate containing the secret key
        pakeState = start_pake(code, role === "sender" ? "A" : "B");
        ownPakeMsg = pakeState.msg; // save before finish_pake consumes state

        if (role === "sender") {
            const kp = mlkem_keygen();
            mlDk = kp.slice(0, MLKEM_DK_LEN);
            mlEk = kp.slice(MLKEM_DK_LEN, MLKEM_DK_LEN + MLKEM_EK_LEN);
            kp.fill(0); // wipe intermediate containing the decapsulation key
            step = "await-rx-info"; // sender waits — broadcast drops early msgs
        } else {
            const frame = new Uint8Array(RX_INFO_LEN);
            frame.set(ownPakeMsg, 0);
            frame.set(xPk, PAKE_MSG_LEN);
            ws.send(frame);
            step = "await-sender-info";
        }
    });

    // Serialize message processing. The handler awaits (deriveDirectionalKeys,
    // deriveConfirmTags) mid-handshake; the browser delivers the next WS message during
    // that pause, which then reads a stale `step` — e.g. receiver's kemCt+hash
    // arrive coalesced through the tunnel and the 16-byte hash hits "await-ct"
    // as a wrong-size frame ("ct size" abort). FIFO chain closes the race.
    let msgChain = Promise.resolve();
    ws.addEventListener("message", (e) => {
        msgChain = msgChain.then(() => handleWsMessage(e)).catch(() => {});
    });
    const handleWsMessage = async (e) => {
        // 15.10b Pre-close marker from server (Cloudflare strips Close frames).
        if (typeof e.data === "string") {
            const m = e.data.match(/^BEEM-CLOSE:(\d+):(.*)$/);
            if (m) {
                preCloseCode = parseInt(m[1], 10);
                preCloseReason = m[2];
            }
            return;
        }

        if (step === "chat") {
            if (!(e.data instanceof ArrayBuffer)) return;
            const frame = new Uint8Array(e.data);
            if (frame.length < 1 + 12 || frame.length > MAX_FRAME) return;
            const type  = frame[0];
            const nonce = frame.slice(1, 13);
            const ct    = frame.slice(13);
            if (nonce[3] !== 0) { appendSystemMsg("(transport mismatch \u2014 frame rejected)"); return; }
            const incomingCounter = new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4, false);
            if (incomingCounter <= recvCounterWS) { appendSystemMsg("(replay rejected)"); return; }
            let pt;
            try {
                pt = decrypt(recvKey, nonce, ct);
            } catch (_) {
                appendSystemMsg("(decrypt failed \u2014 frame rejected)");
                return;
            }
            recvCounterWS = incomingCounter;
            handleChatPayload(type, pt);
            return;
        }

        if (!(e.data instanceof ArrayBuffer)) return;
        const buf = new Uint8Array(e.data);
        if (role === "sender" && step === "await-rx-info") {
            if (buf.length !== RX_INFO_LEN) { abort("Handshake failed (size)."); return; }
            const peerPake = buf.slice(0, PAKE_MSG_LEN);
            const peerXPk  = buf.slice(PAKE_MSG_LEN, RX_INFO_LEN);
            rxXPk = peerXPk; // save for HKDF transcript
            try { pakeKey = finish_pake(pakeState, peerPake); }
            catch (_) { abort("Pairing failed."); return; }
            pakeState = null;
            try { xShared = x25519_shared(xSk, peerXPk); }
            catch (_) { abort("ECDH failed."); return; }

            const out = new Uint8Array(TX_INFO_LEN);
            out.set(ownPakeMsg, 0);
            out.set(xPk, PAKE_MSG_LEN);
            out.set(mlEk, PAKE_MSG_LEN + X25519_PK_LEN);
            ws.send(out);
            step = "await-ct";
            return;
        }

        if (role === "sender" && step === "await-ct") {
            if (buf.length !== MLKEM_CT_LEN) { abort("Handshake failed (ct size)."); return; }
            let kemSs;
            try { kemSs = mlkem_decaps(mlDk, buf); }
            catch (_) { abort("ML-KEM decaps failed."); return; }
            // transcript = xPkA(sender) ‖ xPkB(receiver) ‖ mlEk ‖ mlCt
            const tr = new Uint8Array(xPk.length + rxXPk.length + mlEk.length + buf.length);
            let off = 0;
            tr.set(xPk,   off); off += xPk.length;
            tr.set(rxXPk, off); off += rxXPk.length;
            tr.set(mlEk,  off); off += mlEk.length;
            tr.set(buf,   off);
            try { derivedKey = hkdf_combine(pakeKey, xShared, kemSs, tr); }
            catch (_) { abort("HKDF failed."); return; }
            kemSs.fill(0); // KEM shared secret no longer needed
            await deriveDirectionalKeys();
            await deriveConfirmTags();
            ws.send(myHash);
            step = "await-hash";
            return;
        }

        if (role === "receiver" && step === "await-sender-info") {
            if (buf.length !== TX_INFO_LEN) { abort("Handshake failed (size)."); return; }
            const peerPake = buf.slice(0, PAKE_MSG_LEN);
            const peerXPk  = buf.slice(PAKE_MSG_LEN, PAKE_MSG_LEN + X25519_PK_LEN);
            const peerEk   = buf.slice(PAKE_MSG_LEN + X25519_PK_LEN, TX_INFO_LEN);
            try { pakeKey = finish_pake(pakeState, peerPake); }
            catch (_) { abort("Pairing failed."); return; }
            pakeState = null;
            try { xShared = x25519_shared(xSk, peerXPk); }
            catch (_) { abort("ECDH failed."); return; }

            let encapsOut;
            try { encapsOut = mlkem_encaps(peerEk); }
            catch (_) { abort("ML-KEM encaps failed."); return; }
            const kemCt = encapsOut.slice(0, MLKEM_CT_LEN);
            const kemSs = encapsOut.slice(MLKEM_CT_LEN, MLKEM_CT_LEN + MLKEM_SS_LEN);
            // transcript = xPkA(sender) ‖ xPkB(receiver) ‖ mlEk ‖ mlCt — must match sender side
            const tr = new Uint8Array(peerXPk.length + xPk.length + peerEk.length + kemCt.length);
            let off = 0;
            tr.set(peerXPk, off); off += peerXPk.length;
            tr.set(xPk,     off); off += xPk.length;
            tr.set(peerEk,  off); off += peerEk.length;
            tr.set(kemCt,   off);
            try { derivedKey = hkdf_combine(pakeKey, xShared, kemSs, tr); }
            catch (_) { abort("HKDF failed."); return; }
            kemSs.fill(0);     // KEM shared secret no longer needed
            encapsOut.fill(0); // encaps output still holds a copy of the shared secret
            await deriveDirectionalKeys();

            ws.send(kemCt);
            await deriveConfirmTags();
            ws.send(myHash);
            step = "await-hash";
            return;
        }

        if (step === "await-hash") {
            if (buf.length !== 16) return;
            if (!bytesEq(buf, expectedPeerHash)) {
                abort("Wrong code \u2014 codes did not match.");
                return;
            }
            step = "chat";
            enterChat(code);
            setupWebRTC();
        }
    };

    ws.addEventListener("close", (ev) => {
        if (wsGen !== myGen) return; // stale handler from a replaced WS — ignore
        if (aborted) return;
        // 15.10b If the real close frame was stripped (CF Tunnel → 1006), fall back
        // to the text marker the server sent just before closing.
        const rawCode = ev && ev.code;
        const useMarker = rawCode === 1006 && preCloseCode !== 0;
        const code = useMarker ? preCloseCode : rawCode;
        const reason = useMarker ? preCloseReason : ((ev && ev.reason) ? ev.reason : "");

        if (step === "chat") {
            // Known end-of-session codes: actually end the chat.
            if (code === CLOSE.SESSION_TIMEOUT || code === CLOSE.PEER_LEFT) {
                appendSystemMsg(code === CLOSE.SESSION_TIMEOUT
                    ? "(session time limit reached)"
                    : "(peer disconnected)");
                endChatSession();
                return;
            }
            // Anything else during chat (1006 from OS-killed TCP when the tab is
            // backgrounded for a file picker) — try to silently resume.
            attemptResume();
            return;
        }

        if (role === "receiver") {
            if (showRateBanner(code, reason)) {
                $("receiver-error").textContent = "";
            } else if (code === CLOSE.CODE_FORMAT) {
                $("receiver-error").textContent = "Invalid code format. Please enter exactly 5 digits.";
            } else if (code === CLOSE.CODE_MISSING) {
                $("receiver-error").textContent = "Invalid or expired code. Please try again.";
            } else if (code === CLOSE.SESSION_TIMEOUT) {
                $("receiver-error").textContent = "Session time limit reached.";
            } else {
                $("receiver-error").textContent = "Connection lost. Please try again.";
            }
            show("receiver");
        } else {
            let txt;
            if (code === CLOSE.RATE_COOLDOWN) {
                const secs = reasonSeconds(reason, 300);
                const mins = Math.max(1, Math.ceil(secs / 60));
                txt = `Rate limited. Try again in ${mins} min.`;
            } else if (code === CLOSE.BAN_30M) {
                txt = "Blocked for 30 minutes due to repeated failed attempts.";
            } else if (code === CLOSE.BAN_24H) {
                txt = "Blocked for 24 hours due to repeated failed attempts.";
            } else if (code === CLOSE.CODE_MISSING) {
                txt = "Code expired.";
            } else if (code === CLOSE.SESSION_TIMEOUT) {
                txt = "Session time limit reached.";
            } else {
                txt = "Connection lost. Please try again.";
            }
            setWaitMsg(txt, "err");
        }
    });

    ws.addEventListener("error", () => {
        if (aborted || step === "chat") return;
        // Pre-chat WS error (network drop, server unreachable). Unrecoverable
        // for this session — surface the fatal view instead of inline text.
        aborted = true;
        showFatalView("Could not connect", "Server unreachable or network error. Nothing was sent.");
    });
}

function abort(reason) {
    aborted = true;
    step = null;
    try { ws.close(); } catch (_) {}
    zeroizeKeys(); // don't leave key material in memory after a failed handshake
    if (role === "receiver") {
        $("receiver-error").textContent = reason;
        show("receiver");
    } else {
        setWaitMsg(reason, "err");
    }
}

function enterChat(_code) {
    $("chat-log").innerHTML = "";
    $("chat-input").value = "";
    for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
        const el = $(id);
        if (el) el.disabled = false;
    }
    $("btn-vanish").classList.remove("bm-vanish-btn--killing");
    setChatChip("ok", "Connected");
    show("chat");
    $("chat-input").focus();
    startWsKeepalive();
    acquireWakeLock();
}

// Sends a no-op frame over WS every 20 s when DC is active, preventing Cloudflare
// and other tunnel proxies from treating the idle signaling socket as dead.
function startWsKeepalive() {
    if (wsKeepaliveTimer !== null) clearInterval(wsKeepaliveTimer);
    wsKeepaliveTimer = setInterval(() => {
        if (step === "chat") sendPayload(T_KEEPALIVE, new Uint8Array(0));
    }, 20_000);
}

function stopWsKeepalive() {
    if (wsKeepaliveTimer !== null) { clearInterval(wsKeepaliveTimer); wsKeepaliveTimer = null; }
}

async function acquireWakeLock() {
    if (!("wakeLock" in navigator)) return;
    try {
        wakeLock = await navigator.wakeLock.request("screen");
        // OS can release the lock at any time (battery saver, background) — reacquire immediately
        wakeLock.addEventListener("release", () => {
            wakeLock = null;
            if (step === "chat" && document.visibilityState === "visible") acquireWakeLock();
        });
    } catch (_) {}
}

function releaseWakeLock() {
    if (wakeLock) { wakeLock.release(); wakeLock = null; }
}

// Registered once — handles tab restore after screen lock / app switch
document.addEventListener("visibilitychange", async () => {
    if (document.visibilityState !== "visible" || step !== "chat") return;
    if (wakeLock === null) await acquireWakeLock();
    // WS dies silently while screen is off — detect and reconnect immediately on unlock
    if (!ws || ws.readyState !== WebSocket.OPEN) attemptResume();
});

// Update the chat-header status chip without rewriting its DOM structure.
function setChatChip(tone, text) {
    const chip = document.querySelector("#chat-header .bm-status-chip");
    if (!chip) return;
    chip.classList.remove("bm-status-chip--ok", "bm-status-chip--warn", "bm-status-chip--err");
    chip.classList.add(`bm-status-chip--${tone}`);
    const label = chip.querySelector("span:last-child");
    if (label) label.textContent = text;
}

// Mobile resume: reopen the WS silently within the grace window. The AEAD key
// stays in JS memory across tab freeze, so the reopened socket goes straight
// into chat mode. If grace runs out, admit the disconnect for real.
function attemptResume() {
    if (resumeUntil === 0) {
        resumeUntil = Date.now() + RESUME_GRACE_MS;
        resumeAttempt = 0;
    }
    if (Date.now() > resumeUntil) {
        resumeUntil = 0;
        appendSystemMsg("(peer disconnected)");
        endChatSession();
        return;
    }
    // Don't flicker chip while DataChannels are carrying the transfer
    if (openDcPaths().length === 0) {
        setChatChip("warn", "Reconnecting…");
    }
    // Backoff 0s/3s/6s/12s (~4 attempts per grace window). Each failed connect
    // closes instantly and re-enters here; without spacing that hammers the
    // server and walks our own IP up the cooldown→ban ladder (5 attempts/60s
    // trips a cooldown).
    const delay = resumeAttempt === 0 ? 0 : Math.min(3000 * 2 ** (resumeAttempt - 1), 12_000);
    resumeAttempt += 1;
    if (resumeTimer !== null) clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => {
        resumeTimer = null;
        if (step !== "chat") return;                        // session ended while waiting
        if (ws && ws.readyState === WebSocket.OPEN) return; // already resumed (visibility race)
        openWs(currentCode, true);
    }, delay);
}

// 15.9 Peer gone / session ended: disable inputs, flip the header chip to err tone.
function endChatSession() {
    step = null;
    useRTC = false;
    drainAckWaiters(); // unblock any sendFile/handleFileNack loop waiting on ACK
    settleDcReconnect(); // abandon any in-flight DC rebuild + wake parked loops (16.9.1)
    stopWsKeepalive();
    releaseWakeLock();
    closeAllDcPaths();
    zeroizeKeys(); // session over (peer left / timeout) — wipe keys
    for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
        const el = $(id);
        if (el) el.disabled = true;
    }
    const chip = document.querySelector("#chat-header .bm-status-chip");
    if (chip) {
        chip.classList.remove("bm-status-chip--ok", "bm-status-chip--warn");
        chip.classList.add("bm-status-chip--err");
        const label = chip.querySelector("span:last-child");
        if (label) label.textContent = "Disconnected";
    }
}

// One-tap panic: signal peer immediately, kill connection, zero crypto material, clear chat.
// T_BYE goes out before we nuke local state so the peer sees instant disconnect,
// not the server's 30-second mobile-resume grace delay.
function panicVanish() {
    sendPayload(T_BYE, new Uint8Array(0)); // must be first — sendPayload checks step === "chat"
    const btn = $("btn-vanish");
    btn.classList.add("bm-vanish-btn--killing");
    setTimeout(_doVanish, 350);
}
function _doVanish() {
    aborted = true;
    step = null;
    useRTC = false;
    drainAckWaiters();
    settleDcReconnect(); // 16.9.1: abandon any DC rebuild + wake parked loops
    stopWsKeepalive();
    releaseWakeLock();
    try { ws && ws.close(); } catch (_) {}
    closeAllDcPaths();
    ws = null;
    zeroizeKeys(); // panic vanish — overwrite then drop all key material
    pakeState = null;
    sendCounterWS = 0n;
    recvCounterWS = -1n;
    sendCountersDC = [0n, 0n, 0n, 0n];
    recvCountersDC = [-1n, -1n, -1n, -1n];
    recvMasksDC = [0n, 0n, 0n, 0n];
    role = currentCode = null;
    $("chat-log").innerHTML = "";
    $("chat-input").value = "";
    $("file-status").textContent = "";
    for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
        const el = $(id);
        if (el) el.disabled = false;
    }
    show("landing");
}

$("btn-vanish").addEventListener("click", panicVanish);

// Fatal-view retry. Was an inline onclick in index.html, which our own CSP
// (script-src-attr) blocks — the button silently did nothing.
const fatalRetryBtn = document.querySelector(".bm-fatal-retry");
if (fatalRetryBtn) fatalRetryBtn.addEventListener("click", () => location.reload());

// ---- WebRTC direct path ----
// Signaling travels over the existing encrypted WS relay (T_RTC_* frames).
// Once DataChannel opens, file chunks bypass the server entirely.
// Falls back to WS relay silently if WebRTC is unavailable or fails.

// ICE candidates can arrive over the relay before this side has applied the
// remote description (offer/answer race). Adding them early throws, so each
// path buffers in path.pendingIce until its remote description is set.

// Self-hosted STUN/TURN: /turn.json exists only where TURN is configured
// (gitignored) so the relay address never enters the repo. Shape:
// { "urls": ["stun:host:3478", "turn:host:3478?transport=udp"], "username": "...", "credential": "..." }
// Absent or malformed → fall back to Google STUN (local dev / CI unchanged).
// A tampered turn.json can only redirect the relay path, which is untrusted by
// design — media stays E2E encrypted — so this file needs no SRI pin.
let turnConfig = null;
fetch("./turn.json")
    .then(r => (r.ok ? r.json() : null))
    .then(j => {
        if (j && Array.isArray(j.urls) && j.urls.every(u => typeof u === "string")
            && typeof j.username === "string" && typeof j.credential === "string") {
            turnConfig = j;
        }
    })
    .catch(() => {});

function setupWebRTC() {
    if (typeof RTCPeerConnection === "undefined") return;
    rtcPaths = [];
    // Receiver paths are created lazily when each offer arrives (ensureRecvPath).
    if (role === "sender") {
        for (let k = 0; k < DC_PATHS; k++) createSenderPath(k);
    }
}

function rtcConfig() {
    return { iceServers: turnConfig
        ? [{ urls: turnConfig.urls, username: turnConfig.username, credential: turnConfig.credential }]
        : [{ urls: "stun:stun.l.google.com:19302" }]
    };
}

function newDcPath(k) {
    const path = { id: k, pc: new RTCPeerConnection(rtcConfig()), dc: null, pendingIce: [] };
    path.pc.onicecandidate = (e) => {
        if (e.candidate) sendSignal(T_RTC_ICE, JSON.stringify({ p: k, d: e.candidate }));
    };
    rtcPaths[k] = path;
    return path;
}

function createSenderPath(k) {
    const path = newDcPath(k);
    // 16.9.5 ordered:false (still reliable): one lost packet no longer freezes
    // the whole path for a retransmit RTT (SCTP head-of-line blocking) — bench
    // measured +60% on the lossy mobile relay path. Receiver reassembles by
    // chunk index; anti-replay handles the reorder via the sliding window.
    path.dc = path.pc.createDataChannel("beem-" + k, { ordered: false });
    path.dc.binaryType = "arraybuffer";
    wireDataChannel(path);
    path.pc.createOffer().then(offer => {
        path.pc.setLocalDescription(offer);
        sendSignal(T_RTC_OFFER, JSON.stringify({ p: k, d: offer }));
    });
}

function ensureRecvPath(k) {
    if (rtcPaths[k]) return rtcPaths[k];
    const path = newDcPath(k);
    path.pc.ondatachannel = (e) => {
        path.dc = e.channel;
        path.dc.binaryType = "arraybuffer";
        wireDataChannel(path);
    };
    return path;
}

function openDcPaths() {
    return rtcPaths.filter(p => p && p.dc && p.dc.readyState === "open");
}

function closeAllDcPaths() {
    for (const p of rtcPaths) {
        if (!p) continue;
        try { p.dc?.close(); } catch (_) {}
        try { p.pc?.close(); } catch (_) {}
    }
    rtcPaths = [];
    useRTC = false;
}

// A path is stalled when bytes are stuck in its buffer with zero drain for
// DC_STALL_MS — the dead-route case (VPN drop, WiFi toggle) where readyState
// stays "open" and onclose never fires. Baseline resets on every observed
// drain; sends raising the buffer move the baseline without resetting the clock.
// Per-path high-water mark. BDP on the worst real path (~3 MB/s × ~130 ms) is
// ~400 KB, so 2 MB never starves the pipe — but it caps queued-yet-undelivered
// RAM at ~8 MB across 4 paths (the old 8 MB cap let "100%" run ~32–40 MB ahead
// of the receiver in the field).
const DC_BUFFER_CAP = 2 * 1024 * 1024;
const DC_STALL_MS = 5000;
function dcPathStalled(p, now) {
    const b = p.dc.bufferedAmount;
    if (p.lastBuf === undefined || b < p.lastBuf) {
        p.lastBuf = b;
        p.lastDrain = now;
        return false;
    }
    if (b > p.lastBuf) p.lastBuf = b;
    return b > 0 && (now - p.lastDrain) > DC_STALL_MS;
}

// Least-buffered open path — adaptive striping: fast paths drain quicker and
// naturally take more chunks; a slowing path stops being picked long before it
// stalls. Stalled paths are closed on sight so chunks stop vanishing into them.
function pickDcPath() {
    const now = Date.now();
    let best = null;
    for (const p of rtcPaths) {
        if (!p || !p.dc || p.dc.readyState !== "open") continue;
        if (dcPathStalled(p, now)) {
            try { p.dc.close(); } catch (_) {}
            handleDcPathClose(p); // don't wait for the onclose event
            continue;
        }
        if (!best || p.dc.bufferedAmount < best.dc.bufferedAmount) best = p;
    }
    return best;
}

function wireDataChannel(path) {
    const dc = path.dc;
    dc.onopen = async () => {
        const firstUp = !useRTC;
        useRTC = true;
        if (dcReconnecting) settleDcReconnect(); // unpark chunk loops on the rebuilt path
        if (!firstUp) return; // label the connection once, from the first path that opens
        let label = "Direct";
        try {
            const stats = await path.pc.getStats();
            let pair = null;
            stats.forEach(s => { if (s.type === "candidate-pair" && s.nominated) pair = s; });
            if (pair) {
                const local  = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                const bothHost = local?.candidateType === "host" && remote?.candidateType === "host";
                if (local?.candidateType === "relay" || remote?.candidateType === "relay")
                    label = "relay (turn)";
                else if (bothHost) label = "Direct LAN";
                else if (local?.candidateType === "srflx" || remote?.candidateType === "srflx")
                    label = "P2P (internet)";
            }
        } catch (_) {}
        appendSystemMsg(`${label} connection — server bypassed`);
    };
    dc.onclose = () => handleDcPathClose(path);
    dc.onerror = () => { useRTC = openDcPaths().length > 0; };
    dc.onmessage = (e) => {
        if (!(e.data instanceof ArrayBuffer)) return;
        const buf = new Uint8Array(e.data);
        if (buf.length < 13 || buf.length > MAX_FRAME) return;
        const type = buf[0];
        const nonce = buf.slice(1, 13);
        // 16.9.2: counter space indexed by the nonce transport byte (1 + pathId),
        // NOT by arrival channel — a frame replayed onto a different path still
        // lands in its original counter space and dies in the replay window.
        const pid = nonce[3] - 1;
        if (pid < 0 || pid >= DC_PATHS) return;
        const dcCounter = new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4, false);
        // 16.9.5 sliding window (unordered DC): reordered-but-fresh passes,
        // replays and beyond-window frames drop before paying for a decrypt.
        if (!dcReplayFresh(pid, dcCounter)) return;
        let pt;
        try { pt = decrypt(recvKey, nonce, buf.slice(13)); } catch (_) { return; }
        dcReplayMark(pid, dcCounter); // authenticated — only now may it move the window
        handleChatPayload(type, pt);
    };
}

// 16.9.1 — DC loss during an active session: rebuild P2P instead of permanently
// downgrading to the WS relay. Only the sender can offer; the receiver parks
// until the sender's reconnect offer reopens the channel or the window lapses.
function drainDcWaiters() {
    const w = dcWaiters;
    dcWaiters = [];
    for (const r of w) r();
}
function settleDcReconnect() {
    dcReconnecting = false;
    drainDcWaiters();
}
function waitDcSettled() {
    if (!dcReconnecting) return Promise.resolve();
    return new Promise(r => dcWaiters.push(r));
}
function handleDcPathClose(path) {
    if (rtcPaths[path.id] === path) {
        try { path.pc?.close(); } catch (_) {}
        rtcPaths[path.id] = null;
    }
    useRTC = openDcPaths().length > 0;
    if (useRTC) return; // 16.9.2 graceful degrade — surviving paths carry the transfer
    if (step !== "chat" || dcReconnecting) return; // teardown, or already rebuilding
    dcReconnecting = true;
    appendSystemMsg("(direct connection lost — reconnecting…)");
    if (role === "sender") {
        rebuildRTC();
    } else {
        // Bounded park covering the sender's full retry budget, plus slack.
        setTimeout(() => {
            if (!dcReconnecting) return;
            settleDcReconnect();
            if (step === "chat") appendSystemMsg("(direct reconnect failed — using relay)");
        }, DC_RECONNECT_TRIES * DC_RECONNECT_OPEN_MS + 2000);
    }
}
async function rebuildRTC() {
    for (let i = 0; i < DC_RECONNECT_TRIES && step === "chat"; i++) {
        closeAllDcPaths();
        setupWebRTC(); // fresh paths + offers over WS signalling
        const deadline = Date.now() + DC_RECONNECT_OPEN_MS;
        while (Date.now() < deadline && step === "chat" && openDcPaths().length === 0) {
            await new Promise(r => setTimeout(r, 100));
        }
        if (openDcPaths().length > 0) { settleDcReconnect(); return; }
    }
    settleDcReconnect();
    if (step === "chat") appendSystemMsg("(direct reconnect failed — using relay)");
}

// 16.9.2: park while every open path is above the buffer cap. Stalled paths are
// closed as they're found; returns as soon as one path has room, none remain
// (caller falls back to WS), the transfer is cancelled, or a rebuild starts.
async function dcBackpressure() {
    while (!sendCancelled && !dcReconnecting) {
        const now = Date.now();
        let anyAlive = false;
        let anyFree = false;
        for (const p of openDcPaths()) {
            if (dcPathStalled(p, now)) {
                try { p.dc.close(); } catch (_) {}
                handleDcPathClose(p);
                continue;
            }
            anyAlive = true;
            if (p.dc.bufferedAmount <= DC_BUFFER_CAP) anyFree = true;
        }
        if (!anyAlive || anyFree) return;
        await new Promise(r => setTimeout(r, 10));
    }
}

// Sum of bytes queued in the open path buffers — sent from the app's view but
// not yet handed to the network. Subtracted from displayed progress so the bar
// reflects bytes that actually left this machine.
function dcBufferedTotal() {
    let b = 0;
    for (const p of openDcPaths()) b += p.dc.bufferedAmount;
    return b;
}

// Post-loop drain: "Sent" must mean the buffers are empty, not "chunks queued
// in RAM" (field: at "100%" the receiver was ~40 MB behind and a kill-chat at
// that moment destroyed the tail). Stalled paths are closed — their queued
// chunks are lost, but the receiver's NACK round at T_FILE_END repairs that.
// Returns on cancel or reconnect too; both leave nothing more to drain here.
async function dcDrainBuffers(refs, sentBytes, totalBytes) {
    while (!sendCancelled && !dcReconnecting) {
        const now = Date.now();
        let buffered = 0;
        for (const p of openDcPaths()) {
            if (dcPathStalled(p, now)) {
                try { p.dc.close(); } catch (_) {}
                handleDcPathClose(p);
                continue;
            }
            buffered += p.dc.bufferedAmount;
        }
        if (buffered === 0) return;
        updateFileRow(refs, Math.max(0, sentBytes - buffered), totalBytes, "Sending", 0);
        await new Promise(r => setTimeout(r, 100));
    }
}

function sendSignal(type, jsonStr) {
    // Signaling goes over WS relay even when useRTC is true
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const nonce = makeNonce(sendCounterWS, 0);
    if (!nonce) return;
    sendCounterWS += 1n;
    const plaintext = textEnc.encode(jsonStr);
    let ct;
    try { ct = encrypt(sendKey, nonce, plaintext); } catch (_) { return; }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type;
    frame.set(nonce, 1);
    frame.set(ct, 13);
    ws.send(frame);
}

async function handleRTCSignal(type, pt) {
    if (typeof RTCPeerConnection === "undefined" || step !== "chat") return;
    // 16.9.2: every signal is wrapped { p: pathId, d: payload }
    const msg = JSON.parse(textDec.decode(pt));
    const k = msg.p >>> 0;
    if (k >= DC_PATHS || msg.d === undefined) return;
    const body = msg.d;
    if (type === T_RTC_OFFER) {
        let path = ensureRecvPath(k);
        if (path.pc.remoteDescription) {
            // 16.9.1 reconnect offer — the old peer connection for this path is dead
            try { path.pc.close(); } catch (_) {}
            rtcPaths[k] = null;
            path = ensureRecvPath(k);
        }
        await path.pc.setRemoteDescription(body);
        await flushPendingIce(path);
        const answer = await path.pc.createAnswer();
        await path.pc.setLocalDescription(answer);
        sendSignal(T_RTC_ANSWER, JSON.stringify({ p: k, d: answer }));
    } else if (type === T_RTC_ANSWER) {
        const path = rtcPaths[k];
        if (!path || path.pc.remoteDescription) return; // unknown path / duplicate answer
        await path.pc.setRemoteDescription(body);
        await flushPendingIce(path);
    } else if (type === T_RTC_ICE) {
        const path = rtcPaths[k];
        if (!path) return; // per-path WS ordering guarantees the offer precedes its ICE
        // Queue until the remote description exists; otherwise addIceCandidate throws.
        if (path.pc.remoteDescription && path.pc.remoteDescription.type) {
            path.pc.addIceCandidate(body).catch(() => {});
        } else {
            path.pendingIce.push(body);
        }
    }
}

async function flushPendingIce(path) {
    const queued = path.pendingIce;
    path.pendingIce = [];
    for (const c of queued) {
        try { await path.pc.addIceCandidate(c); } catch (_) {}
    }
}

function sendPayload(type, plaintext) {
    if (step !== "chat") return false;
    // File frames stripe across open DC paths (16.9.2, least-buffered first);
    // signaling + chat always via WS.
    const wantsDC = type === T_FILE_HDR || type === T_FILE_CHK || type === T_FILE_END;
    const path = wantsDC && useRTC ? pickDcPath() : null;
    if (!path && (!ws || ws.readyState !== WebSocket.OPEN)) return false;
    const nonce = path ? makeNonce(sendCountersDC[path.id], 1 + path.id)
                       : makeNonce(sendCounterWS, 0);
    if (!nonce) return false;
    if (path) { sendCountersDC[path.id] += 1n; } else { sendCounterWS += 1n; }
    let ct;
    try {
        ct = encrypt(sendKey, nonce, plaintext);
    } catch (_) {
        appendSystemMsg("(encrypt failed)");
        return false;
    }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type;
    frame.set(nonce, 1);
    frame.set(ct, 13);
    if (path) {
        path.dc.send(frame);
    } else {
        ws.send(frame);
    }
    return true;
}

function sendChat() {
    const text = $("chat-input").value;
    if (!text) return;
    if (sendPayload(T_TEXT, textEnc.encode(text))) {
        appendChatMsg("out", text);
        $("chat-input").value = "";
    }
}

function handleChatPayload(type, pt) {
    if (type === T_TEXT) {
        appendChatMsg("in", textDec.decode(pt));
        return;
    }
    if (type === T_FILE_HDR) { handleFileHdr(pt); return; }
    if (type === T_FILE_CHK) { handleFileChunk(pt); return; }
    if (type === T_FILE_END) { handleFileEnd(); return; }
    if (type === T_RTC_OFFER || type === T_RTC_ANSWER || type === T_RTC_ICE) {
        handleRTCSignal(type, pt);
        return;
    }
    if (type === T_FILE_NACK) { handleFileNack(pt); return; }
    if (type === T_FILE_ACK)  { ackReceived(); return; }
    if (type === T_FILE_CANCEL) { handleFileCancel(pt); return; }
    if (type === T_FILE_DONE) { handleFileDone(); return; }
    if (type === T_KEEPALIVE) return;
    if (type === T_BYE) { endChatSession(); return; }
    appendSystemMsg(`(unknown frame type 0x${type.toString(16)})`);
}

function appendChatMsg(direction, text) {
    const wrap = document.createElement("div");
    wrap.className = `bm-msg bm-msg--${direction}`;
    const bubble = document.createElement("div");
    bubble.className = "bm-msg-bubble";
    bubble.textContent = text;
    wrap.appendChild(bubble);
    $("chat-log").appendChild(wrap);
    wrap.scrollIntoView({ block: "end" });
}

function appendSystemMsg(text) {
    const div = document.createElement("div");
    div.className = "bm-sys-msg";
    div.textContent = text;
    $("chat-log").appendChild(div);
    div.scrollIntoView({ block: "end" });
}

function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function appendFileRow(name, sizeBytes, direction, onCancel) {
    const row = document.createElement("div");
    row.className = "bm-file-row";

    const nameEl = document.createElement("div");
    nameEl.className = "bm-file-name";
    // 16.8.1 direction badge — ↑ sending / ↓ receiving, so concurrent transfers
    // in both directions are distinguishable at a glance
    const dirEl = document.createElement("span");
    dirEl.className = `bm-file-dir bm-file-dir--${direction}`;
    dirEl.textContent = direction === "out" ? "↑" : "↓";
    nameEl.appendChild(dirEl);
    nameEl.appendChild(document.createTextNode(name));

    // 16.8.2 — cancel button lives in a head line beside the name; removed by
    // completeFileRow/failFileRow once the transfer reaches a terminal state.
    const head = document.createElement("div");
    head.className = "bm-file-head";
    head.appendChild(nameEl);
    let cancelBtn = null;
    if (onCancel) {
        cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "bm-file-cancel";
        cancelBtn.textContent = "✕";
        cancelBtn.title = "Cancel transfer";
        cancelBtn.addEventListener("click", onCancel);
        head.appendChild(cancelBtn);
    }

    const meta = document.createElement("div");
    meta.className = "bm-file-meta";
    meta.textContent = `${direction === "out" ? "Sending" : "Receiving"} \u00b7 0 / ${fmtBytes(sizeBytes)}`;

    const progress = document.createElement("div");
    progress.className = "bm-progress";
    const fill = document.createElement("div");
    fill.className = "bm-progress-fill";
    fill.style.width = "0%";
    progress.appendChild(fill);

    row.appendChild(head);
    row.appendChild(meta);
    row.appendChild(progress);

    $("chat-log").appendChild(row);
    row.scrollIntoView({ block: "end" });
    return { row, meta, fill, cancelBtn };
}

function removeCancelBtn(refs) {
    if (refs && refs.cancelBtn) {
        refs.cancelBtn.remove();
        refs.cancelBtn = null;
    }
}

function updateFileRow(refs, doneBytes, totalBytes, label, speedBps) {
    const pct = totalBytes > 0 ? Math.min(100, (doneBytes / totalBytes) * 100) : 0;
    refs.fill.style.width = `${pct.toFixed(1)}%`;
    const speed = speedBps > 0 ? ` \u00b7 ${fmtBytes(speedBps)}/s` : "";
    refs.meta.textContent = `${label} \u00b7 ${fmtBytes(doneBytes)} / ${fmtBytes(totalBytes)}${speed}`;
}

function completeFileRow(refs, totalBytes, finalLabel) {
    removeCancelBtn(refs);
    refs.fill.style.width = "100%";
    refs.fill.classList.add("bm-progress-fill--complete");
    refs.meta.textContent = `${finalLabel} \u00b7 ${fmtBytes(totalBytes)}`;
}

function failFileRow(refs, message) {
    removeCancelBtn(refs);
    refs.meta.textContent = message;
}

// ---- File transfer ----
const CHUNK_SIZE = 128 * 1024; // 128 KB → encrypted frame ~128 KB + 33 B, safely under Chrome DC 256 KB max
const MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024; // 1 GB
const MAX_WS_BUFFER = 512 * 1024; // pause sending when browser send buffer exceeds 512 KB

// Sender-side
async function sendFile(file) {
    if (step !== "chat") return;
    if (file.size > MAX_FILE_SIZE) {
        $("file-status").textContent =
            `File too big: ${file.size} bytes (max ${MAX_FILE_SIZE} bytes / 1 GB)`;
        return;
    }
    $("file-status").textContent = "";

    // Header: size(8 BE) || name_len(2 BE) || name_utf8
    const nameBytes = textEnc.encode(file.name);
    const hdr = new Uint8Array(8 + 2 + nameBytes.length);
    const hv = new DataView(hdr.buffer);
    hv.setBigUint64(0, BigInt(file.size), false);
    hv.setUint16(8, nameBytes.length, false);
    hdr.set(nameBytes, 10);
    if (!sendPayload(T_FILE_HDR, hdr)) return;

    sendCancelled = false;
    sendCancelMsg = "";
    pendingDelivery = null; // a new transfer supersedes the previous confirmation
    const refs = appendFileRow(file.name, file.size, "out", () => {
        if (sendCancelled) return;
        sendCancelled = true;
        sendCancelMsg = "Cancelled";
        sendPayload(T_FILE_CANCEL, new Uint8Array([0x00])); // tell peer to discard its partial
        drainAckWaiters(); // wake a parked window wait so the loop can observe the flag
        drainDcWaiters();  // likewise a loop parked on a DC reconnect (16.9.1)
    });
    currentSendRefs = refs;
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    let sentBytes = 0;
    // Sliding 1-second window: array of [timestamp, bytes] samples
    let speedSamples = [];

    for (let i = 0; i < totalChunks; i++) {
        if (sendCancelled) break;
        // 16.9.1: DC dropped mid-transfer — park until the rebuild settles
        // (reopened → resume via DC; gave up → chunks route via WS below).
        if (dcReconnecting) {
            await waitDcSettled();
            if (sendCancelled) break;
        }
        const offset = i * CHUNK_SIZE;
        const slice = file.slice(offset, Math.min(file.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        const payload = new Uint8Array(4 + buf.length);
        new DataView(payload.buffer).setUint32(0, i, false);
        payload.set(buf, 4);
        if (!sendPayload(T_FILE_CHK, payload)) {
            // Mobile WS blips mid-send and reopens within the resume grace —
            // park and retry this chunk instead of aborting the whole transfer.
            const retryUntil = Date.now() + RESUME_GRACE_MS + 5000;
            let sent = false;
            while (!sent && !sendCancelled && step === "chat" && Date.now() < retryUntil) {
                await new Promise(r => setTimeout(r, 250));
                sent = sendPayload(T_FILE_CHK, payload);
            }
            if (sendCancelled) break;
            if (!sent) {
                failFileRow(refs, `Send aborted at chunk ${i}`);
                currentSendRefs = null;
                return;
            }
        }
        sentBytes += buf.length;
        const now = Date.now();
        speedSamples.push([now, buf.length]);
        // Backpressure — two separate mechanisms for two separate paths:
        // WS relay: ACK-window. Receiver sends T_FILE_ACK after each chunk.
        //   Sender waits here when ACK_WINDOW chunks are already in flight.
        //   This caps the server broadcast ring buffer and paces sender to receiver speed.
        // DC (P2P/LAN): SCTP congestion control handles it; just cap OOM risk.
        if (useRTC && openDcPaths().length > 0) {
            await dcBackpressure();
        } else {
            wsChunksInFlight++;
            if (wsChunksInFlight >= ACK_WINDOW && !sendCancelled) {
                await new Promise(r => ackResolvers.push(r));
            }
        }
        if (sendCancelled) break;
        if ((i & 0x0f) === 0 || i === totalChunks - 1) {
            const t = Date.now();
            speedSamples = speedSamples.filter(s => t - s[0] <= 1000);
            const bps = speedSamples.reduce((a, s) => a + s[1], 0);
            updateFileRow(refs, Math.max(0, sentBytes - dcBufferedTotal()), file.size, "Sending", bps);
            await new Promise(r => setTimeout(r, 0));
        }
    }
    if (!sendCancelled) await dcDrainBuffers(refs, sentBytes, file.size);
    currentSendRefs = null;
    if (sendCancelled) {
        failFileRow(refs, sendCancelMsg || "Cancelled");
        drainAckWaiters(); // clear in-flight count; stray late ACKs floor at 0 in ackReceived
        return;
    }
    lastSentFile = file; // held so handleFileNack can re-read slices on retransmit request
    sendPayload(T_FILE_END, new Uint8Array(0));
    removeCancelBtn(refs);
    updateFileRow(refs, file.size, file.size, "Sent", 0);
    pendingDelivery = { refs, size: file.size }; // green "Delivered" only on T_FILE_DONE
    try {
        const cs = await fileChecksum(await file.arrayBuffer());
        appendSystemMsg(`SHA-256: ${cs}`);
    } catch (_) {}
}

// WS relay ACK-window flow control.
// Sender tracks how many chunks are in-flight (sent but not yet ACKed by receiver).
// When in-flight hits ACK_WINDOW the sender suspends until an ACK arrives, keeping
// the server's broadcast ring buffer well under its 2048-frame limit regardless of
// how much faster the sender is than the receiver.
const ACK_WINDOW = 32; // max chunks in flight over WS relay (~4 MB)
let wsChunksInFlight = 0;
let ackResolvers = []; // queue of resolve functions waiting for an ACK

function ackReceived() {
    wsChunksInFlight = Math.max(0, wsChunksInFlight - 1);
    if (ackResolvers.length > 0) ackResolvers.shift()();
}

function drainAckWaiters() {
    wsChunksInFlight = 0;
    ackResolvers.splice(0).forEach(r => r());
}

// Receiver-side
let recvFile = null; // { name, size, totalChunks, nackAttempts, parts: Uint8Array[], received: number, refs }
// Sender-side: held after sendFile completes so handleFileNack can re-read slices
let lastSentFile = null;
// Sender-side: { refs, size } after T_FILE_END — handleFileDone flips it to "Delivered"
let pendingDelivery = null;
// 16.8.2 cancel state
let sendCancelled = false;   // observed by the sendFile/handleFileNack loops; reset at sendFile start
let sendCancelMsg = "";      // terminal row label ("Cancelled" vs "Cancelled by peer")
let currentSendRefs = null;  // outgoing row refs so a peer-initiated cancel can mark the card
let dropStrayChunks = false; // after an incoming cancel, late in-flight chunks are expected — drop them silently
// 16.9.2: with striped paths, chunks (or even T_FILE_END) on a fast path can
// arrive before the header that went on a slower one — stash and replay on HDR.
let earlyChunks = [];
let earlyEnd = false;
const EARLY_CHUNK_CAP = 256; // 32 MB of path skew — far beyond any real race

function handleFileHdr(pt) {
    if (pt.length < 10) { appendSystemMsg("(bad file header)"); return; }
    const v = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    const size = Number(v.getBigUint64(0, false));
    const nameLen = v.getUint16(8, false);
    if (pt.length !== 10 + nameLen) { appendSystemMsg("(bad file header)"); return; }
    const name = textDec.decode(pt.slice(10, 10 + nameLen));
    dropStrayChunks = false; // new transfer — stray-chunk reporting is meaningful again
    const refs = appendFileRow(name, size, "in", () => {
        if (!recvFile || recvFile.refs !== refs) return; // stale button (already terminal)
        const f = recvFile;
        recvFile = null;
        dropStrayChunks = true; // chunks already in flight will keep landing — expected
        earlyChunks = [];
        earlyEnd = false;
        sendPayload(T_FILE_CANCEL, new Uint8Array([0x01])); // tell sender to stop
        failFileRow(f.refs, "Cancelled");
    });
    recvFile = { name, size, totalChunks: Math.max(1, Math.ceil(size / CHUNK_SIZE)), nackAttempts: 0, parts: [], received: 0, refs, speedSamples: [] };
    // Replay anything that beat this header across a faster path (16.9.2)
    const replay = earlyChunks;
    earlyChunks = [];
    for (const c of replay) handleFileChunk(c);
    if (earlyEnd) { earlyEnd = false; handleFileEnd(); }
}

function handleFileChunk(pt) {
    if (!recvFile) {
        if (!dropStrayChunks && earlyChunks.length < EARLY_CHUNK_CAP) {
            earlyChunks.push(pt); // header still in flight on another path (16.9.2)
        }
        return;
    }
    if (pt.length < 4) return;
    const idx = new DataView(pt.buffer, pt.byteOffset, pt.byteLength).getUint32(0, false);
    const data = pt.slice(4);
    if (recvFile.parts[idx] !== undefined) {
        // Duplicate (a retransmit raced the late original). Still ACK it: the sender
        // counted this (re)sent chunk in its in-flight window, so without an ACK back
        // wsChunksInFlight leaks one slot per duplicate. ackReceived() floors at 0,
        // so an extra ACK can never over-decrement.
        sendPayload(T_FILE_ACK, new Uint8Array(0));
        return;
    }
    recvFile.parts[idx] = data;
    recvFile.received += data.length;
    // ACK every chunk over WS relay so the sender's flow-control window advances.
    // Tiny frame (encrypted ~29B) — negligible overhead.
    sendPayload(T_FILE_ACK, new Uint8Array(0));
    const t = Date.now();
    recvFile.speedSamples.push([t, data.length]);
    recvFile.speedSamples = recvFile.speedSamples.filter(s => t - s[0] <= 1000);
    const bps = recvFile.speedSamples.reduce((a, s) => a + s[1], 0);
    updateFileRow(recvFile.refs, recvFile.received, recvFile.size, "Receiving", bps);
}

async function handleFileEnd() {
    if (!recvFile) {
        if (!dropStrayChunks) earlyEnd = true; // END beat the header across paths (16.9.2)
        return;
    }
    const f = recvFile;
    // 16.9.5 unordered DC: a tiny END routinely overtakes large fragmented
    // chunks still in flight on its path (unordered = deliver-on-assembly),
    // so "missing at END" usually means "still arriving". One short grace
    // before each NACK round keeps transfers from always ending in a spurious
    // repair; genuine loss (closed path) just repairs 1 s later. The flag
    // stays set through the grace re-entry (clearing it there would loop the
    // grace forever) and re-arms after each NACK so every round gets one.
    if (f.received !== f.size && step === "chat" && !f.endGraceSpent) {
        f.endGraceSpent = true;
        setTimeout(() => { if (recvFile === f) handleFileEnd(); }, 1000);
        return;
    }
    if (f.received !== f.size && f.nackAttempts < 3 && step === "chat") {
        const missing = [];
        for (let i = 0; i < f.totalChunks; i++) {
            if (f.parts[i] === undefined) missing.push(i);
        }
        if (missing.length > 0) {
            f.nackAttempts++;
            f.endGraceSpent = false; // fresh grace for the retransmit round's END
            // Keep recvFile alive \u2014 retransmitted chunks + new T_FILE_END will arrive
            const nackBuf = new Uint8Array(missing.length * 4);
            const dv = new DataView(nackBuf.buffer);
            missing.forEach((chunkIdx, i) => dv.setUint32(i * 4, chunkIdx, false));
            sendPayload(T_FILE_NACK, nackBuf);
            appendSystemMsg(`(requesting ${missing.length} missing chunk${missing.length === 1 ? "" : "s"}\u2026)`);
            return;
        }
    }
    recvFile = null;
    if (f.received !== f.size) {
        failFileRow(f.refs, `Incomplete \u00b7 ${fmtBytes(f.received)} / ${fmtBytes(f.size)}`);
        return;
    }
    const blob = new Blob(f.parts);
    const url = URL.createObjectURL(blob);

    completeFileRow(f.refs, f.size, "Received");
    sendPayload(T_FILE_DONE, new Uint8Array(0)); // assembly verified — confirm delivery to the sender

    // Replace meta with a download anchor inside the existing row.
    f.refs.meta.textContent = "";
    const link = document.createElement("a");
    link.href = url;
    link.download = f.name;
    link.textContent = `Download \u00b7 ${fmtBytes(f.size)}`;
    link.addEventListener("click", () => setTimeout(() => URL.revokeObjectURL(url), 100));
    f.refs.meta.appendChild(link);

    try {
        const cs = await fileChecksum(await blob.arrayBuffer());
        appendSystemMsg(`SHA-256: ${cs}`);
    } catch (_) {}
}

// Receiver confirmed assembly (T_FILE_DONE) — the only point where the sender
// may claim more than "Sent". A stray DONE with nothing pending is dropped.
function handleFileDone() {
    if (!pendingDelivery) return;
    completeFileRow(pendingDelivery.refs, pendingDelivery.size, "Delivered");
    pendingDelivery = null;
}

// 16.8.2 — peer cancelled a transfer. payload[0]: 0x00 = peer aborted the file
// it was sending to us (discard our partial); 0x01 = peer rejects the file we
// are sending (stop the loop; forget the file so NACK rounds can't resurrect it).
function handleFileCancel(pt) {
    if (pt.length !== 1) return;
    if (pt[0] === 0x00) {
        earlyChunks = [];
        earlyEnd = false;
        if (!recvFile) { dropStrayChunks = true; return; }
        const f = recvFile;
        recvFile = null;
        dropStrayChunks = true;
        failFileRow(f.refs, "Cancelled by peer");
        return;
    }
    if (pt[0] === 0x01) {
        sendCancelled = true;
        sendCancelMsg = "Cancelled by peer";
        lastSentFile = null; // a NACK round after this must not resurrect the transfer
        if (currentSendRefs) failFileRow(currentSendRefs, "Cancelled by peer");
        else if (pendingDelivery) failFileRow(pendingDelivery.refs, "Cancelled by peer"); // rejected during a post-"Sent" NACK round
        pendingDelivery = null;
        drainAckWaiters(); // unpark the send loop so it can observe the flag
        drainDcWaiters();  // likewise a loop parked on a DC reconnect (16.9.1)
    }
}

// Sender-side: receiver asked us to re-send specific chunks.
// Reads only the requested slices from the original File object and re-sends them,
// then fires T_FILE_END so the receiver can try assembly again.
async function handleFileNack(pt) {
    if (!lastSentFile || pt.length % 4 !== 0 || pt.length === 0) return;
    const count = pt.length / 4;
    const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    for (let j = 0; j < count; j++) {
        if (dcReconnecting) await waitDcSettled(); // 16.9.1: same park as the main loop
        // lastSentFile re-checked each pass: a T_FILE_CANCEL (0x01) arriving
        // mid-round nulls it and sets sendCancelled (16.8.2)
        if (step !== "chat" || sendCancelled || !lastSentFile) return;
        const idx = dv.getUint32(j * 4, false);
        const offset = idx * CHUNK_SIZE;
        const slice = lastSentFile.slice(offset, Math.min(lastSentFile.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        const payload = new Uint8Array(4 + buf.length);
        new DataView(payload.buffer).setUint32(0, idx, false);
        payload.set(buf, 4);
        if (!sendPayload(T_FILE_CHK, payload)) return;
        if (useRTC && openDcPaths().length > 0) {
            await dcBackpressure(); // same stall-safe park as the main chunk loop
        } else {
            wsChunksInFlight++;
            if (wsChunksInFlight >= ACK_WINDOW && !sendCancelled) {
                await new Promise(r => ackResolvers.push(r));
            }
        }
    }
    if (sendCancelled) return;
    sendPayload(T_FILE_END, new Uint8Array(0));
}

