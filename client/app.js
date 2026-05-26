// 15.4 SRI — placeholders rewritten by scripts/build-sri.sh on release build.
// Until rewritten, runtime check short-circuits with a dev-mode warning.
const CRYPTO_JS_SRI   = "sha384-m16i4fI+hLiDvPJHHgc6vq3lVxSNAaS7fGBtLldXNlHw3G76rMCw66Ik1zr7e3E4";
const CRYPTO_WASM_SRI = "sha384-v16TDqD88M0wwl/J+vJe7zkl9YuLwkZzGKsmins/VidwyD9A4833ebr2+Ru12D9i";
const SRI_PLACEHOLDER_PREFIX = "__SRI_";

async function sha384Base64(buf) {
    const digest = await crypto.subtle.digest("SHA-384", buf);
    let bin = "";
    for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b);
    return btoa(bin);
}

async function verifyAndLoadCrypto() {
    const jsResp = await fetch("./pkg/beem_crypto.js");
    if (!jsResp.ok) throw new Error(`crypto.js fetch ${jsResp.status}`);
    const jsBytes = await jsResp.arrayBuffer();
    const jsHash  = `sha384-${await sha384Base64(jsBytes)}`;

    const wasmResp = await fetch("./pkg/beem_crypto_bg.wasm");
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

async function hashPrefix4(bytes) {
    const full = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(full, 0, 4);
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
let mlDk = null, mlEk = null; // sender only
let pakeKey = null;
let xShared = null;
let derivedKey = null;   // final combined 32-byte key
let myHash = null;
// Sender: "await-rx-info" -> "await-ct" -> "await-hash" -> "chat"
// Receiver: "await-sender-info" -> "await-hash" -> "chat"
let step = null;
let aborted = false;
let sendCounterWS = 0n;
let sendCounterDC = 0n;
let recvCounterWS = -1n; // per-transport strictly increasing; prevents cross-transport replay drops
let recvCounterDC = -1n;

// WebRTC direct channel — set up after PAKE completes, falls back to WS relay silently
let rtcPeer = null;
let dataChannel = null;
let useRTC = false;

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
let wsKeepaliveTimer = null;
let wakeLock = null;

const COUNTER_MAX = (1n << 64n) - 1n;

// transport: 0 = WebSocket, 1 = DataChannel — byte 3 of nonce separates counter spaces
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
    if (ws && ws.readyState === WebSocket.CONNECTING) return;
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
        pakeKey = xShared = derivedKey = myHash = null;
        aborted = false;
        sendCounterWS = 0n;
        sendCounterDC = 0n;
        recvCounterWS = -1n;
        recvCounterDC = -1n;
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
            // Don't flicker chip if DC is still actively transferring
            if (!useRTC || dataChannel?.readyState !== "open") {
                setChatChip("ok", "Connected");
            }
            return;
        }
        const xkp = x25519_keypair();
        xSk = xkp.slice(0, 32);
        xPk = xkp.slice(32, 64);
        pakeState = start_pake(code, role === "sender" ? "A" : "B");
        ownPakeMsg = pakeState.msg; // save before finish_pake consumes state

        if (role === "sender") {
            const kp = mlkem_keygen();
            mlDk = kp.slice(0, MLKEM_DK_LEN);
            mlEk = kp.slice(MLKEM_DK_LEN, MLKEM_DK_LEN + MLKEM_EK_LEN);
            step = "await-rx-info"; // sender waits — broadcast drops early msgs
        } else {
            const frame = new Uint8Array(RX_INFO_LEN);
            frame.set(ownPakeMsg, 0);
            frame.set(xPk, PAKE_MSG_LEN);
            ws.send(frame);
            step = "await-sender-info";
        }
    });

    ws.addEventListener("message", async (e) => {
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
            if (frame.length < 1 + 12) return;
            const type  = frame[0];
            const nonce = frame.slice(1, 13);
            const ct    = frame.slice(13);
            if (nonce[3] !== 0) { appendSystemMsg("(transport mismatch \u2014 frame rejected)"); return; }
            const incomingCounter = new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4, false);
            if (incomingCounter <= recvCounterWS) { appendSystemMsg("(replay rejected)"); return; }
            let pt;
            try {
                pt = decrypt(derivedKey, nonce, ct);
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
            try { derivedKey = hkdf_combine(pakeKey, xShared, kemSs); }
            catch (_) { abort("HKDF failed."); return; }
            myHash = await hashPrefix4(derivedKey);
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
            try { derivedKey = hkdf_combine(pakeKey, xShared, kemSs); }
            catch (_) { abort("HKDF failed."); return; }

            ws.send(kemCt);
            myHash = await hashPrefix4(derivedKey);
            ws.send(myHash);
            step = "await-hash";
            return;
        }

        if (step === "await-hash") {
            if (buf.length !== 4) return;
            if (!bytesEq(buf, myHash)) {
                abort("Wrong code \u2014 codes did not match.");
                return;
            }
            step = "chat";
            enterChat(code);
            setupWebRTC();
        }
    });

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
    if (resumeUntil === 0) resumeUntil = Date.now() + RESUME_GRACE_MS;
    if (Date.now() > resumeUntil) {
        resumeUntil = 0;
        appendSystemMsg("(peer disconnected)");
        endChatSession();
        return;
    }
    // Don't flicker chip while DataChannel is carrying the transfer
    if (!useRTC || dataChannel?.readyState !== "open") {
        setChatChip("warn", "Reconnecting…");
    }
    openWs(currentCode, true);
}

// 15.9 Peer gone / session ended: disable inputs, flip the header chip to err tone.
function endChatSession() {
    step = null;
    useRTC = false;
    stopWsKeepalive();
    releaseWakeLock();
    if (dataChannel) { dataChannel.close(); dataChannel = null; }
    if (rtcPeer) { rtcPeer.close(); rtcPeer = null; }
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
    stopWsKeepalive();
    releaseWakeLock();
    try { ws && ws.close(); } catch (_) {}
    try { dataChannel && dataChannel.close(); } catch (_) {}
    try { rtcPeer && rtcPeer.close(); } catch (_) {}
    ws = null; dataChannel = null; rtcPeer = null;
    derivedKey = pakeKey = xShared = xSk = xPk = null;
    mlDk = mlEk = pakeState = ownPakeMsg = myHash = null;
    sendCounterWS = sendCounterDC = 0n;
    recvCounterWS = recvCounterDC = -1n;
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

// ---- WebRTC direct path ----
// Signaling travels over the existing encrypted WS relay (T_RTC_* frames).
// Once DataChannel opens, file chunks bypass the server entirely.
// Falls back to WS relay silently if WebRTC is unavailable or fails.

function setupWebRTC() {
    if (typeof RTCPeerConnection === "undefined") return;
    const cfg = { iceServers: [
        { urls: "stun:stun.l.google.com:19302" }
    ]};
    rtcPeer = new RTCPeerConnection(cfg);

    rtcPeer.onicecandidate = (e) => {
        if (e.candidate) {
            sendSignal(T_RTC_ICE, JSON.stringify(e.candidate));
        }
    };

    if (role === "sender") {
        dataChannel = rtcPeer.createDataChannel("beem", { ordered: true });
        dataChannel.binaryType = "arraybuffer";
        wireDataChannel(dataChannel);
        rtcPeer.createOffer().then(offer => {
            rtcPeer.setLocalDescription(offer);
            sendSignal(T_RTC_OFFER, JSON.stringify(offer));
        });
    } else {
        rtcPeer.ondatachannel = (e) => {
            dataChannel = e.channel;
            dataChannel.binaryType = "arraybuffer";
            wireDataChannel(dataChannel);
        };
    }
}

function wireDataChannel(dc) {
    dc.onopen = async () => {
        useRTC = true;
        let label = "Direct";
        try {
            const stats = await rtcPeer.getStats();
            let pair = null;
            stats.forEach(s => { if (s.type === "candidate-pair" && s.nominated) pair = s; });
            if (pair) {
                const local  = stats.get(pair.localCandidateId);
                const remote = stats.get(pair.remoteCandidateId);
                const bothHost = local?.candidateType === "host" && remote?.candidateType === "host";
                if (bothHost) label = "Direct LAN";
                else if (local?.candidateType === "srflx" || remote?.candidateType === "srflx")
                    label = "P2P (internet)";
            }
        } catch (_) {}
        appendSystemMsg(`${label} connection — server bypassed`);
    };
    dc.onclose = () => { useRTC = false; if (step === "chat") appendSystemMsg("(direct connection closed — fell back to relay)"); };
    dc.onerror = () => { useRTC = false; };
    dc.onmessage = (e) => {
        if (!(e.data instanceof ArrayBuffer)) return;
        const buf = new Uint8Array(e.data);
        if (buf.length < 13) return;
        const type = buf[0];
        const nonce = buf.slice(1, 13);
        if (nonce[3] !== 1) return;
        const dcCounter = new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4, false);
        if (dcCounter <= recvCounterDC) return;
        let pt;
        try { pt = decrypt(derivedKey, nonce, buf.slice(13)); } catch (_) { return; }
        recvCounterDC = dcCounter;
        handleChatPayload(type, pt);
    };
}

function sendSignal(type, jsonStr) {
    // Signaling goes over WS relay even when useRTC is true
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const nonce = makeNonce(sendCounterWS, 0);
    if (!nonce) return;
    sendCounterWS += 1n;
    const plaintext = textEnc.encode(jsonStr);
    let ct;
    try { ct = encrypt(derivedKey, nonce, plaintext); } catch (_) { return; }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type;
    frame.set(nonce, 1);
    frame.set(ct, 13);
    ws.send(frame);
}

async function handleRTCSignal(type, pt) {
    if (!rtcPeer) return;
    const msg = JSON.parse(textDec.decode(pt));
    if (type === T_RTC_OFFER) {
        await rtcPeer.setRemoteDescription(msg);
        const answer = await rtcPeer.createAnswer();
        await rtcPeer.setLocalDescription(answer);
        sendSignal(T_RTC_ANSWER, JSON.stringify(answer));
    } else if (type === T_RTC_ANSWER) {
        await rtcPeer.setRemoteDescription(msg);
    } else if (type === T_RTC_ICE) {
        rtcPeer.addIceCandidate(msg).catch(() => {});
    }
}

function sendPayload(type, plaintext) {
    if (step !== "chat") return false;
    // File chunks go direct when DataChannel is open; signaling + chat always via WS
    const viaDC = useRTC && dataChannel?.readyState === "open" &&
                  (type === T_FILE_HDR || type === T_FILE_CHK || type === T_FILE_END);
    if (!viaDC && (!ws || ws.readyState !== WebSocket.OPEN)) return false;
    const transport = viaDC ? 1 : 0;
    const nonce = makeNonce(viaDC ? sendCounterDC : sendCounterWS, transport);
    if (!nonce) return false;
    if (viaDC) { sendCounterDC += 1n; } else { sendCounterWS += 1n; }
    let ct;
    try {
        ct = encrypt(derivedKey, nonce, plaintext);
    } catch (_) {
        appendSystemMsg("(encrypt failed)");
        return false;
    }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type;
    frame.set(nonce, 1);
    frame.set(ct, 13);
    if (viaDC) {
        dataChannel.send(frame);
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

function appendFileRow(name, sizeBytes, direction) {
    const row = document.createElement("div");
    row.className = "bm-file-row";

    const nameEl = document.createElement("div");
    nameEl.className = "bm-file-name";
    nameEl.textContent = name;

    const meta = document.createElement("div");
    meta.className = "bm-file-meta";
    meta.textContent = `${direction === "out" ? "Sending" : "Receiving"} \u00b7 0 / ${fmtBytes(sizeBytes)}`;

    const progress = document.createElement("div");
    progress.className = "bm-progress";
    const fill = document.createElement("div");
    fill.className = "bm-progress-fill";
    fill.style.width = "0%";
    progress.appendChild(fill);

    row.appendChild(nameEl);
    row.appendChild(meta);
    row.appendChild(progress);

    $("chat-log").appendChild(row);
    row.scrollIntoView({ block: "end" });
    return { row, meta, fill };
}

function updateFileRow(refs, doneBytes, totalBytes, label, speedBps) {
    const pct = totalBytes > 0 ? Math.min(100, (doneBytes / totalBytes) * 100) : 0;
    refs.fill.style.width = `${pct.toFixed(1)}%`;
    const speed = speedBps > 0 ? ` \u00b7 ${fmtBytes(speedBps)}/s` : "";
    refs.meta.textContent = `${label} \u00b7 ${fmtBytes(doneBytes)} / ${fmtBytes(totalBytes)}${speed}`;
}

function completeFileRow(refs, totalBytes, finalLabel) {
    refs.fill.style.width = "100%";
    refs.fill.classList.add("bm-progress-fill--complete");
    refs.meta.textContent = `${finalLabel} \u00b7 ${fmtBytes(totalBytes)}`;
}

function failFileRow(refs, message) {
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

    const refs = appendFileRow(file.name, file.size, "out");
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    let sentBytes = 0;
    // Sliding 1-second window: array of [timestamp, bytes] samples
    let speedSamples = [];

    for (let i = 0; i < totalChunks; i++) {
        const offset = i * CHUNK_SIZE;
        const slice = file.slice(offset, Math.min(file.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        const payload = new Uint8Array(4 + buf.length);
        new DataView(payload.buffer).setUint32(0, i, false);
        payload.set(buf, 4);
        if (!sendPayload(T_FILE_CHK, payload)) {
            failFileRow(refs, `Send aborted at chunk ${i}`);
            return;
        }
        sentBytes += buf.length;
        const now = Date.now();
        speedSamples.push([now, buf.length]);
        // Backpressure: WS relay needs tight cap to avoid overflowing broadcast channel.
        // DataChannel has SCTP congestion control — use a loose cap just to avoid OOM.
        const bufTarget = (useRTC && dataChannel) ? dataChannel : ws;
        const bufCap = useRTC ? 8 * 1024 * 1024 : MAX_WS_BUFFER;
        while (bufTarget && bufTarget.bufferedAmount > bufCap) {
            await new Promise(r => setTimeout(r, 10));
        }
        if ((i & 0x0f) === 0 || i === totalChunks - 1) {
            const t = Date.now();
            speedSamples = speedSamples.filter(s => t - s[0] <= 1000);
            const bps = speedSamples.reduce((a, s) => a + s[1], 0);
            updateFileRow(refs, sentBytes, file.size, "Sending", bps);
            await new Promise(r => setTimeout(r, 0));
        }
    }
    lastSentFile = file; // held so handleFileNack can re-read slices on retransmit request
    sendPayload(T_FILE_END, new Uint8Array(0));
    completeFileRow(refs, file.size, "Sent");
    try {
        const cs = await fileChecksum(await file.arrayBuffer());
        appendSystemMsg(`SHA-256: ${cs}`);
    } catch (_) {}
}

// Receiver-side
let recvFile = null; // { name, size, totalChunks, nackAttempts, parts: Uint8Array[], received: number, refs }
// Sender-side: held after sendFile completes so handleFileNack can re-read slices
let lastSentFile = null;

function handleFileHdr(pt) {
    if (pt.length < 10) { appendSystemMsg("(bad file header)"); return; }
    const v = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    const size = Number(v.getBigUint64(0, false));
    const nameLen = v.getUint16(8, false);
    if (pt.length !== 10 + nameLen) { appendSystemMsg("(bad file header)"); return; }
    const name = textDec.decode(pt.slice(10, 10 + nameLen));
    const refs = appendFileRow(name, size, "in");
    recvFile = { name, size, totalChunks: Math.max(1, Math.ceil(size / CHUNK_SIZE)), nackAttempts: 0, parts: [], received: 0, refs, speedSamples: [] };
}

function handleFileChunk(pt) {
    if (!recvFile) { appendSystemMsg("(chunk without header)"); return; }
    if (pt.length < 4) return;
    const idx = new DataView(pt.buffer, pt.byteOffset, pt.byteLength).getUint32(0, false);
    const data = pt.slice(4);
    if (recvFile.parts[idx] !== undefined) return; // duplicate from retransmit — already counted
    recvFile.parts[idx] = data;
    recvFile.received += data.length;
    const t = Date.now();
    recvFile.speedSamples.push([t, data.length]);
    recvFile.speedSamples = recvFile.speedSamples.filter(s => t - s[0] <= 1000);
    const bps = recvFile.speedSamples.reduce((a, s) => a + s[1], 0);
    updateFileRow(recvFile.refs, recvFile.received, recvFile.size, "Receiving", bps);
}

async function handleFileEnd() {
    if (!recvFile) return;
    const f = recvFile;
    if (f.received !== f.size && f.nackAttempts < 3 && step === "chat") {
        const missing = [];
        for (let i = 0; i < f.totalChunks; i++) {
            if (f.parts[i] === undefined) missing.push(i);
        }
        if (missing.length > 0) {
            f.nackAttempts++;
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

// Sender-side: receiver asked us to re-send specific chunks.
// Reads only the requested slices from the original File object and re-sends them,
// then fires T_FILE_END so the receiver can try assembly again.
async function handleFileNack(pt) {
    if (!lastSentFile || pt.length % 4 !== 0 || pt.length === 0) return;
    const count = pt.length / 4;
    const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    for (let j = 0; j < count; j++) {
        if (step !== "chat") return;
        const idx = dv.getUint32(j * 4, false);
        const offset = idx * CHUNK_SIZE;
        const slice = lastSentFile.slice(offset, Math.min(lastSentFile.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        const payload = new Uint8Array(4 + buf.length);
        new DataView(payload.buffer).setUint32(0, idx, false);
        payload.set(buf, 4);
        if (!sendPayload(T_FILE_CHK, payload)) return;
        if (!useRTC) {
            while (ws && ws.bufferedAmount > MAX_WS_BUFFER) {
                await new Promise(r => setTimeout(r, 10));
            }
        }
    }
    sendPayload(T_FILE_END, new Uint8Array(0));
}

