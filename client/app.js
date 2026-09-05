// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Scar

// 15.4 SRI — placeholders rewritten by scripts/build-sri.sh on release build.
// Until rewritten, runtime check short-circuits with a dev-mode warning.
const CRYPTO_JS_SRI   = "sha384-ZjzAD+YebCuGOe7gHZquNblaaBfiILnBvgvSR/+J5tCP3ZdV1h8dwYbXnG1m10Ga";
const CRYPTO_WASM_SRI = "sha384-BV/Jl8gs64GtFz2v8xd/itc+0yPNvoJrWp5QIO0lhnK4WpVqW+zXKXUl7L/4fhxV";
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

// Self-host branding arrives as DATA — branding.json — and is
// applied here, inside the SRI-pinned app.js. It used to be branding.js, an
// unpinned script that was the first thing the page executed. Empty body or
// any failure means stock branding; nothing else in the page waits on this.
(async () => {
    try {
        const r = await fetch("./branding.json", { cache: "no-store" });
        if (!r.ok) return;
        const text = await r.text();
        if (!text.trim()) return;
        const b = JSON.parse(text);
        if (typeof b.wordmark === "string" && b.wordmark) {
            document.querySelectorAll(".bm-wordmark-text").forEach((el) => { el.textContent = b.wordmark; });
        }
    } catch (_) { /* stock branding */ }
})();

async function verifyAndLoadCrypto() {
    const jsResp = await fetch(`./pkg/iris_crypto.js?v=${sriVersion(CRYPTO_JS_SRI)}`);
    if (!jsResp.ok) throw new Error(`crypto.js fetch ${jsResp.status}`);
    const jsBytes = await jsResp.arrayBuffer();
    const jsHash  = `sha384-${await sha384Base64(jsBytes)}`;

    const wasmResp = await fetch(`./pkg/iris_crypto_bg.wasm?v=${sriVersion(CRYPTO_WASM_SRI)}`);
    if (!wasmResp.ok) throw new Error(`wasm fetch ${wasmResp.status}`);
    const wasmBytes = await wasmResp.arrayBuffer();
    const wasmHash  = `sha384-${await sha384Base64(wasmBytes)}`;

    const devMode = CRYPTO_JS_SRI.startsWith(SRI_PLACEHOLDER_PREFIX)
                 || CRYPTO_WASM_SRI.startsWith(SRI_PLACEHOLDER_PREFIX);
    if (devMode) {
        // Launch polish: dev mode is for the developer's OWN machine only.
        // An unstamped build reaching any real host must fail CLOSED — a served
        // client that silently skips its integrity checks is worse than a dead
        // page. localhost/127.0.0.1/[::1] are the only hostnames allowed through.
        const devHost = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
        if (!devHost) {
            throw new Error("Integrity hashes are not stamped; refusing to run outside localhost.");
        }
        console.warn("[iris] SRI dev mode — hashes not yet injected. Run scripts/build-sri.sh before release.");
        console.warn(`[iris] observed crypto.js  ${jsHash}`);
        console.warn(`[iris] observed wasm       ${wasmHash}`);
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

// In-app browsers (Instagram, Facebook, Messenger, TikTok and friends) open
// links inside a restricted WebView that injects its own scripts and limits
// module/WASM loading, so the crypto verification above fails there. That
// failure is environmental, not an attack — still fail closed, but tell the
// person to open a real browser instead of showing a raw integrity error.
function inAppBrowser() {
    const ua = navigator.userAgent || "";
    return /FBAN|FBAV|FB_IAB|Instagram|Line\/|musical_ly|TikTok|Snapchat/.test(ua)
        || (/Android/.test(ua) && /; wv\)/.test(ua));
}

let cryptoMod;
try {
    cryptoMod = await verifyAndLoadCrypto();
} catch (e) {
    if (inAppBrowser()) {
        showFatalView("Open in your browser",
            "Iriszip can't run inside an app's built-in browser. Tap the ⋯ or share menu and choose “Open in browser”, or copy the link into Safari, Chrome or Firefox.");
    } else {
        showFatalView("Integrity check failed", e && e.message ? e.message : "Cryptographic module verification failed.");
    }
    throw e;
}
const {
    start_pake, finish_pake,
    encrypt, decrypt,
    x25519_keypair, x25519_shared,
    mlkem_keygen, mlkem_encaps, mlkem_decaps,
    hkdf_combine,
    Sha256Stream,
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

// ---------------------------------------------------------------------------
// Phase 28: back-button navigation. Every in-app view change the user
// perceives as "going somewhere" pushes ONE history entry, so Back returns to
// the landing view instead of leaving the site. Locked guards: the URL is
// NEVER changed by a push (a pairing code must never enter it — Phase 24 /
// 23.6b), the state object carries only a view name, and popstate is
// deliberately NOT treated as a consent gesture. Depth stays at most 1: landing is
// the base entry, any other view is one pushed entry, and moves between
// non-landing views retag that entry with replaceState.
function pushView(name) {
    try { history.pushState({ irisView: name }, "", location.pathname + location.search); } catch (_) {}
}
function replaceView(name) {
    try { history.replaceState({ irisView: name }, "", location.pathname + location.search); } catch (_) {}
}
// 28.3: 9 digits must fit the code card on every viewport (TV browsers ship
// wide monospace fallbacks and their own text inflation). Shrink the font
// until the row fits; never wrap, never clip a digit.
function fitCodeCard() {
    const bc = $("big-code");
    if (!bc || bc.childElementCount === 0) return;
    bc.style.fontSize = "";
    let px = parseFloat(getComputedStyle(bc).fontSize) || 52;
    let guard = 24;
    while (bc.scrollWidth > bc.clientWidth && px > 14 && guard-- > 0) {
        px -= 2;
        bc.style.fontSize = px + "px";
    }
}
window.addEventListener("resize", () => { if (!views.sender.hidden) fitCodeCard(); });

window.addEventListener("popstate", (e) => {
    const fatal = $("view-fatal");
    if (fatal && !fatal.hidden) return; // fatal view is a dead end; Back may leave
    if (!views.chat.hidden) {
        // 28.2: a stray Back never kills a live session outright — re-push the
        // entry and treat Back as a press of the End-session button: the first
        // press arms the confirm, a second press inside the arm window ends
        // the session (panicVanish -> landing). Back also expresses the
        // opposite of consent, so held offers are dropped like a vanish tap.
        pushView("chat");
        if (!rtcConsent) heldRtcSignals = [];
        requestVanish();
        return;
    }
    if (!views.landing.hidden) {
        // Forward-press into a dead sender/receiver entry: bounce back to the
        // base entry; that popstate lands here with state null and does nothing.
        if (e.state && e.state.irisView) history.back();
        return;
    }
    // Back out of sender/receiver: the pending session (if any) dies with it.
    // _doVanish closes the WS with the BEEM-LEAVE marker so the room is torn
    // down server-side — the minted code stops working — then shows landing.
    _doVanish();
});

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
    NOT_A_MEMBER: 4008, // refused rather than admitted-and-muted
    RELAY_BUDGET: 4009, // this session used up its relay allowance
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
const T_FILE_DONE = 0x09; // delivery confirmation — receiver→sender after successful assembly: tid(1) || digestHex(64, optional); flips the sender row "Sent" → "Delivered"
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
let currentCode = null; // full pairing code (9 digits) — the SPAKE2 password
let routingCode = null; // Phase 24: the server-minted 6 the relay is allowed to see
// Phase 26.2: a receiver that arrived through a #code deep link never chose its
// peer — a link in a message can pair it with anyone who holds a live code. The
// session still opens (the QR flow stays one-tap), but WebRTC signalling is held
// until the user does something IN the chat, so a tab that is only ever looked
// at emits no ICE candidates (= no public IP) to a peer it never picked. Typed or
// tapped joins chose their peer and are unaffected. The sender always chose.
let rtcConsent = true;
let heldRtcSignals = [];
const HELD_RTC_MAX = 512;       // 4 offers + candidates; stale extras are dropped
const HELD_RTC_MAX_BYTES = 8192; // real signals are ~1 KB; a 200 KiB "candidate" is abuse
function withholdRtcUntilGesture() { rtcConsent = false; heldRtcSignals = []; }
function grantRtcConsent(e) {
    if (rtcConsent) return;
    // "End session" is the one gesture that means the opposite of consent.
    if (e && e.target && e.target.closest && e.target.closest("#btn-vanish")) return;
    rtcConsent = true;
    const held = heldRtcSignals;
    heldRtcSignals = [];
    // Replay in arrival order; each signal is processed by the same FIFO path
    // it would have taken live. Copies were taken when held (see below).
    // Held signals are always ONE generation: nothing re-offers while an offer
    // is unanswered (no timer; rebuildRTC only follows a DC close). If a
    // re-offer timer is ever added, replaying generation-1 answers into a
    // generation-N path would let "duplicate answer" drop the real one.
    (async () => { for (const [t, p] of held) { try { await handleRTCSignal(t, p); } catch (_) {} } })();
}

// Phase 24: the 3 secret digits of the pairing code are drawn HERE, in the
// sender's browser, and never reach the server — they are the part of the
// SPAKE2 password a relay cannot know. Only crypto.getRandomValues is allowed
// for this; Math.random is never acceptable for a secret. Rejection sampling
// (bytes >= 250 are redrawn) keeps each digit uniform over 0–9 — a plain
// `byte % 10` would bias 0–5 by 26/25.
function drawSecretDigits(n) {
    let out = "";
    const buf = new Uint8Array(1);
    while (out.length < n) {
        crypto.getRandomValues(buf);
        if (buf[0] >= 250) continue;
        out += String(buf[0] % 10);
    }
    return out;
}
// server-minted proof-of-membership token, so a reconnect after a
// network switch (new WS, same room) isn't misclassified as a third-party
// observer by the server's headcount heuristic. Memory-only — never
// localStorage, never sessionStorage, never a cookie — it must die with the
// tab, same lifetime as the session key it rides alongside.
let resumeToken = "";
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
let sessionEnded = false; // 23.5: deliberate end-of-chat — suppress the late WS close from resurrecting a view
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
// Post-mobile-freeze the DC rebuild almost always fails (the frozen peer offers
// no fresh relay candidate — coturn-confirmed), and the passive answerer waits
// TRIES*OPEN_MS+2000 before falling back to the working WS relay. Kept short so
// a stalled transfer resumes on relay in ~8 s, not ~17 s; a genuine LAN blip
// still gets two 3 s open windows to rebuild the direct path.
const DC_RECONNECT_TRIES = 2;
const DC_RECONNECT_OPEN_MS = 3000;
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
// **W — the reconnect window.** The single policy number the rest of the timing
// derives from: how long a peer may be gone and still come back successfully.
//
// 30 → 60 s, after real-device runs in which the phone destroyed
// its own session at 30 s while the server had not yet even noticed the peer was
// missing (it reaps at 45 s). The client was giving up before the server started
// caring — the whole liveness mechanism fired at a party that had already left.
//
// Bounded above by when the SURVIVOR is torn down: reap (45 s) + RESUME_GRACE_SECS
// (30 s) = 75 s. Returning after that finds an empty room, so promising more than
// ~75 s would be promising a reconnect that cannot work. 60 s leaves 15 s of slack.
//
// Safe to double only because two things landed first: the client now caps its own
// attempts (the old backoff would have made 7 attempts in 60 s and walked the
// user's own IP into a 30-minute ban), and membership is proven by token since membership tokens landed
// rather than inferred from a headcount, so a longer window no longer widens a
// misclassification window. Nothing cryptographic changes.
const RESUME_GRACE_MS = 60_000;
let resumeUntil = 0;
let resumeAttempt = 0;   // backoff step within the current grace window
let resumeTimer = null;

// Reconnect attempts must never trip the server's own
// per-IP ladder. The server allows 5 connection attempts per rolling 60 s and
// answers the 6th with a 30 s cooldown; three cooldowns in an hour is a 30-minute
// ban on the user's own address — a client can ban itself this way.
//
// This is a client-side mirror of that limiter rather than a hand-picked backoff
// schedule, because the schedule is not the only thing that triggers a connect —
// visibility changes and the `online` event do too, and a flapping interface can
// fire those far faster than any backoff. Counting the attempts we actually make
// enforces the invariant by construction, whatever asked for them.
//
// Budget of 4 against the server's 5 leaves one slot spare for an unrelated join
// landing in the same window.
const RESUME_MAX_ATTEMPTS_PER_WINDOW = 4;
// The server's ACTUAL limit: it cools down the 6th attempt, so a 5th is safe. The
// routine cap above stays at 4 to leave a slot spare, but the last opportunity
// inside a closing reconnect window may spend it — see resumeBudgetAvailable.
const RESUME_HARD_CAP_PER_WINDOW = 5;
const RESUME_WINDOW_MS = 60_000; // must track the server's WS_WINDOW_SECS
// A retry has to land far enough before the window closes to finish connecting.
const RESUME_LAST_CHANCE_MS = 4_000;
// How long to let a freshly-announced network settle before spending an attempt
// on it. Real-device runs had the instant retry fail ~100 ms after
// `online` fired, then had no budget left for a second try.
const ONLINE_SETTLE_MS = 2_500;
let resumeAttemptTimes = [];

// Backoff between scheduled retries: cumulative 0 / 6 / 18 / 40 s. The last entry
// repeats, so a 5th retry would land past the window and the budget above stops
// it anyway. Recovery faster than this comes from the `online` event, not from
// retrying harder.
const RESUME_BACKOFF_MS = [0, 6_000, 12_000, 22_000];

// True if another connection attempt fits inside the budget. Prunes as it goes.
//
// `lastChance` raises the cap from our self-imposed 4 to the server's real 5.
// A real-device run: the phone spent all four attempts by 38.8 s, came back
// onto the network at 38.8 s, its retry there failed because the radio had not
// finished reattaching — and the budget then deferred the next attempt to 107.9 s,
// which is 2 s AFTER the 60 s window closed. The session died with the network up
// and 20 s of window left, because nothing was allowed to try. A window nothing
// may try inside is not a window.
function resumeBudgetAvailable(lastChance) {
    const now = Date.now();
    resumeAttemptTimes = resumeAttemptTimes.filter(t => now - t < RESUME_WINDOW_MS);
    const cap = lastChance ? RESUME_HARD_CAP_PER_WINDOW : RESUME_MAX_ATTEMPTS_PER_WINDOW;
    return resumeAttemptTimes.length < cap;
}
let wsKeepaliveTimer = null;
let wakeLock = null;

// the chip may not claim "Connected" without evidence.
//
// Every setChatChip call site is reached from an explicit event, so with no event
// the chip is structurally frozen on whatever it last said. Confirmed on real
// devices: the receiving PC held "Connected" indefinitely over a session whose
// peer had walked off WiFi — its own WS was healthy and a blackholed idle
// DataChannel fires no onclose, so nothing was ever going to tell it.
//
// The fix is a timeout path that needs no event: stamp the arrival of any frame
// from the peer, and let a timer notice when that stamp goes stale.
//
// Split of responsibility: the client is FAST and SOFT, the
// server is SLOW and AUTHORITATIVE. This warning tears nothing down and clears
// itself the moment a frame arrives, so a false positive costs a few seconds of
// honest doubt — which is why 30 s can sit comfortably inside the server's 45 s
// PEER_SILENCE_TIMEOUT_SECS instead of duplicating it.
//
// Keepalive cadence is what makes 30 s safe: at 10 s the threshold absorbs two
// lost keepalives before it speaks. At the old 20 s a single delayed frame put
// the worst-case gap at 40 s and the chip would have flickered on a healthy link.
const WS_KEEPALIVE_MS = 10_000;
const PEER_SILENCE_MS = 30_000;
const PEER_SILENCE_CHECK_MS = 5_000;
// how often the transport label re-checks reality. Slow enough to be free,
// fast enough that a path change is not displayed as a lie for long.
const PATH_LABEL_MS = 5_000;
let lastPeerFrameAt = 0;
let peerSilenceTimer = null;
let peerSilenceShown = false;

const COUNTER_MAX = (1n << 64n) - 1n;

// Mirror of server MAX_WS_FRAME (200 KiB). The server enforces this on relayed
// traffic, but the relay itself is untrusted — cap incoming frames client-side
// before decrypt so a hostile relay/peer can't force a giant allocation. Largest
// legitimate frame is a 128 KiB chunk + 29 B crypto overhead.
const MAX_FRAME = 200 * 1024;
// A text message travels as ONE frame, and MAX_FRAME is what both the relay and
// the peer accept, so the text itself is bounded here — with generous room for the
// type byte, nonce and tag — and refused before anything is sent. Larger text goes
// as a file, which is chunked.
const MAX_TEXT_BYTES = 128 * 1024;

// Phase 26.1: the frame type is authenticated. The AEAD covers `type ‖ payload`;
// the outer frame[0] is only a wire-visible copy so offsets and sizes stay as
// SPEC §5 had them. A relay that rewrites byte 0 of a genuine frame (empty
// keepalive → "file delivered", anything → BYE) now fails `authenticatedPayload`
// instead of being dispatched. Receivers MUST decrypt first, then dispatch on
// pt[0], never on frame[0].
function withType(type, payload) {
    const out = new Uint8Array(1 + payload.length);
    out[0] = type;
    out.set(payload, 1);
    return out;
}
// Returns the authenticated payload (without its type byte) or null when the
// decrypted type disagrees with the wire byte — or the plaintext is empty,
// which no honest sender produces after 26.1.
function authenticatedPayload(wireType, pt) {
    if (pt.length < 1 || pt[0] !== wireType) return null;
    return pt.subarray(1);
}

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

// Directional key-confirmation tags. Both sides previously sent the identical
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
    pushView("receiver"); // 28.1: Back returns to landing
    $("code-input").focus();
});

$("btn-join").addEventListener("click", joinAsReceiver);
$("code-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") joinAsReceiver();
});
$("code-input").addEventListener("input", () => {
    const el = $("code-input");
    const digits = el.value.replace(/\D/g, "").slice(0, 9); // 28.3: never hold >9 digits
    if (digits !== el.value) el.value = digits; // "123 456 789" pastes survive
    if (digits.length === 9) joinAsReceiver();
});

// 26.2: consent is granted only by a gesture that expresses intent to talk —
// tapping the composer, typing into it, pasting, or dropping a file (capture
// phase, so it fires before any handler below acts on it). Raw keydown or
// pointerdown anywhere in the view must NOT count: Tab/Escape on the way to
// "End session", a modifier key, or a touch to scroll the log would replay
// the held offers and leak ICE to a peer the user never chose.
for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
    $(id).addEventListener("pointerdown", grantRtcConsent, { capture: true, passive: true });
}
$("chat-input").addEventListener("beforeinput", grantRtcConsent, { capture: true, passive: true });
for (const ev of ["paste", "drop"]) {
    $("view-chat").addEventListener(ev, grantRtcConsent, { capture: true, passive: true });
}
// Arming "End session" before any consent gesture means the opposite of
// consent: discard the held offers so nothing can replay them later. The
// session may stay on the relay for its remaining life — the safe direction.
$("btn-vanish").addEventListener("pointerdown", () => {
    if (!rtcConsent) heldRtcSignals = [];
}, { capture: true, passive: true });
$("btn-chat-send").addEventListener("click", sendChat);
$("chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChat();
    }
});

// Copy the full 9-digit pairing code to clipboard. localhost + https are both
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
    if (f) offerFile(f);
    e.target.value = "";
});

$("img-stage-remove").addEventListener("click", clearStagedImage); // 23.8

// Clipboard paste — intercept only when clipboard contains a file (screenshot, copied file).
// Text pastes fall through untouched to the textarea.
document.addEventListener("paste", (e) => {
    if (step !== "chat") return;
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
        if (item.kind === "file") {
            const file = item.getAsFile();
            if (file) { e.preventDefault(); offerFile(file); return; }
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
    if (file) offerFile(file);
});

async function startSender() {
    try {
        const res = await fetch("/new", { method: "POST" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const { code } = await res.json();
        role = "sender";
        // Phase 24: the server's 6 digits route the room; 3 more digits drawn
        // here never leave this browser except via the peer's eyes/QR. All 9
        // are the PAKE password, so the relay can't complete SPAKE2 on its own.
        routingCode = code;
        currentCode = code + drawSecretDigits(3);
        const bc = $("big-code");
        bc.textContent = "";
        for (const digit of currentCode) {
            const sp = document.createElement("span");
            sp.textContent = digit;
            bc.appendChild(sp);
        }
        // 23.6: QR of the join URL, drawn by the vendored local encoder (qr.js).
        // Degrades silently if the script didn't load; the typed code still works.
        const qrEl = $("qr-code");
        qrEl.innerHTML = "";
        if (typeof qrcode === "function") {
            const joinUrl = `${location.origin}/#${currentCode}`;
            const qr = qrcode(0, "M");
            qr.addData(joinUrl);
            qr.make();
            // SVG string comes from our own vendored encoder over our own generated
            // URL, not user input, innerHTML is safe here.
            qrEl.innerHTML = qr.createSvgTag({ scalable: true });
        }
        setWaitMsg("Waiting for peer\u2026", "warn");
        show("sender");
        pushView("sender"); // 28.1: Back returns to landing (and kills the room)
        fitCodeCard(); // 28.3: after show() — a hidden element measures 0
        acquireWakeLock();
        openWs(routingCode, currentCode);
    } catch (e) {
        showFatalView("Could not start session", e && e.message ? e.message : "Failed to generate pairing code.");
    }
}

function joinAsReceiver() {
    // Re-entry guard. CONNECTING alone is not enough: the 9th-digit auto-submit
    // opens the WS in ~ms, so an Enter press right after it finds the socket
    // already OPEN, fires a second join, and the duplicate 65-byte hello lands
    // on the sender's await-ct as a wrong-size frame → "ct size" abort.
    if (ws && (ws.readyState === WebSocket.CONNECTING ||
               (ws.readyState === WebSocket.OPEN && step !== null && step !== "chat"))) return;
    const code = $("code-input").value.trim();
    if (!/^\d{9}$/.test(code)) {
        $("receiver-error").textContent = "Please enter exactly 9 digits.";
        return;
    }
    $("receiver-error").textContent = "";
    role = "receiver";
    currentCode = code;
    routingCode = code.slice(0, 6); // Phase 24: only these 6 go to the server
    rtcConsent = true; heldRtcSignals = []; // 26.2: a typed/tapped join chose its peer
    openWs(routingCode, code);
}

// Phase 24: `routing` is the only thing the server ever sees (?code=); `password`
// is the full 9-digit pairing code and goes only into SPAKE2. On resume the
// handshake state is already in memory, so `password` is unused (pass null).
function openWs(routing, password, resume = false) {
    // Connection accounting: record EVERY connection this client makes, not just the
    // resume retries. The server's per-IP ladder counts them all, and in
    // real-device testing a phone made 6 in one 60 s window — enough to trip a cooldown —
    // while our own counter saw only 4, because the two initial joins were not
    // recorded. (There were two because the first hit a stale code and got 4005.)
    // The single spare slot we reserve for "an unrelated join" was never going to
    // cover that. Initial joins CONSUME budget but are never blocked by it: a user
    // pairing must not be refused by our own bookkeeping.
    resumeAttemptTimes.push(Date.now());
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
    sessionEnded = false; // 23.5: fresh connection — re-arm the close handler

    const proto = location.protocol === "https:" ? "wss" : "ws";
    // present the resume token (if we have one) so a reconnect after a
    // network switch proves membership instead of leaning on the server's
    // headcount heuristic. Same query string `code` already travels in, so
    // this adds no new exposure surface.
    const tokenQs = resumeToken ? `&t=${encodeURIComponent(resumeToken)}` : "";
    ws = new WebSocket(`${proto}://${location.host}/ws?code=${encodeURIComponent(routing)}${tokenQs}`);
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
            // WE were the one that was away, so the silence stamp is stale through
            // no fault of the peer. Restart its clock instead of accusing them.
            notePeerFrame();
            peerSilenceShown = false;
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
        pakeState = start_pake(password, role === "sender" ? "A" : "B");
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
                return;
            }
            // server-minted proof-of-membership token for this connection.
            // Memory-only (see the module-scope declaration) — stash and move on.
            const tok = e.data.match(/^BEEM-TOKEN:([0-9a-f]{32})$/);
            if (tok) {
                resumeToken = tok[1];
                return;
            }
            // 23.7 Peer-presence hints from the relay — chip text only, never state.
            // the relay allowance for this session is running down. Sent to
            // BOTH peers, once per session. Not an error and not a state change —
            // the session is healthy, it just has a ceiling, and being told before
            // it is reached is the whole point.
            const bud = e.data.match(/^BEEM-BUDGET:(\d+)$/);
            if (bud && step === "chat") {
                appendSystemMsg(`(${bud[1]}% of this session's relay allowance used \u2014 a new session starts fresh)`);
                return;
            }
            const g = e.data.match(/^BEEM-GRACE:(\d+)$/);
            if (g && step === "chat") {
                setChatChip("warn", `Peer connection lost — waiting up to ${g[1]} s…`);
            } else if (e.data === "BEEM-BACK" && step === "chat") {
                setChatChip("ok", "Connected");
                // The peer's socket is back but its first frame has not landed yet.
                // Without this the silence watch re-warns in that gap and the chip
                // flickers. Trusting a relay hint here can only make us quieter for
                // one more threshold, never make us claim something we cannot see.
                notePeerFrame();
                peerSilenceShown = false;
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
            if (nonce[3] !== 0) { console.warn("[iris] transport mismatch \u2014 frame rejected"); appendSystemMsg("(a message was ignored for your safety)"); return; }
            const incomingCounter = new DataView(nonce.buffer, nonce.byteOffset, 12).getBigUint64(4, false);
            if (incomingCounter <= recvCounterWS) { console.warn("[iris] replay rejected"); appendSystemMsg("(a message was ignored for your safety)"); return; }
            let pt;
            try {
                pt = decrypt(recvKey, nonce, ct);
            } catch (_) {
                console.warn("[iris] decrypt failed \u2014 frame rejected"); appendSystemMsg("(a message was ignored for your safety)");
                return;
            }
            // 26.1: the wire type byte is outside the tag — only pt[0] is trusted.
            const body = authenticatedPayload(type, pt);
            if (!body) { console.warn("[iris] frame type mismatch \u2014 frame rejected"); appendSystemMsg("(a message was ignored for your safety)"); return; }
            recvCounterWS = incomingCounter;
            handleChatPayload(pt[0], body); // dispatch on the AUTHENTICATED type
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
            catch (_) { console.warn("[iris] ECDH failed"); abort("Pairing failed \u2014 check the code and try again."); return; }

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
            catch (_) { console.warn("[iris] HKDF failed"); abort("Pairing failed \u2014 check the code and try again."); return; }
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
            catch (_) { console.warn("[iris] ECDH failed"); abort("Pairing failed \u2014 check the code and try again."); return; }

            let encapsOut;
            try { encapsOut = mlkem_encaps(peerEk); }
            catch (_) { console.warn("[iris] ML-KEM encaps failed"); abort("Pairing failed \u2014 check the code and try again."); return; }
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
            catch (_) { console.warn("[iris] HKDF failed"); abort("Pairing failed \u2014 check the code and try again."); return; }
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
                abort("Wrong code \u2014 ask the sender for a new code.");
                return;
            }
            step = "chat";
            enterChat();
            await loadTurnConfig(); // must resolve before any RTCPeerConnection is built
            setupWebRTC();
        }
    };

    ws.addEventListener("close", (ev) => {
        if (wsGen !== myGen) return; // stale handler from a replaced WS — ignore
        if (aborted) return;
        if (sessionEnded) return; // 23.5: chat already ended deliberately — ignore the late close
        // 15.10b If the real close frame was stripped (CF Tunnel → 1006), fall back
        // to the text marker the server sent just before closing.
        const rawCode = ev && ev.code;
        const useMarker = rawCode === 1006 && preCloseCode !== 0;
        const code = useMarker ? preCloseCode : rawCode;
        const reason = useMarker ? preCloseReason : ((ev && ev.reason) ? ev.reason : "");

        if (step === "chat") {
            // Known end-of-session codes: actually end the chat.
            // RELAY_BUDGET is terminal on purpose: the ceiling is room-scoped, so a
            // silent resume would be refused again the moment it reconnected — a close
            // loop the user could not see the reason for.
            if (code === CLOSE.SESSION_TIMEOUT || code === CLOSE.PEER_LEFT || code === CLOSE.RELAY_BUDGET) {
                appendSystemMsg(code === CLOSE.SESSION_TIMEOUT ? "(session time limit reached)"
                    : code === CLOSE.RELAY_BUDGET
                        ? "(this session reached its relay limit \u2014 start a new session to keep going)"
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
                $("receiver-error").textContent = "Invalid code format. Please enter exactly 9 digits.";
            } else if (code === CLOSE.CODE_MISSING) {
                $("receiver-error").textContent = "Invalid or expired code. Please try again.";
            } else if (code === CLOSE.NOT_A_MEMBER) {
                // Deliberately not "wrong code" — the code was right. Saying so is
                // the honest answer and it is also the useful one: re-entering the
                // same code will not help, starting a new session will.
                $("receiver-error").textContent = "That session is already in use by two devices. Ask for a new code.";
            } else if (code === CLOSE.RELAY_BUDGET) {
                $("receiver-error").textContent = "That session reached its transfer limit. Ask for a new code.";
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
                txt = "Blocked for 30 minutes after several failed attempts. Try again after that.";
            } else if (code === CLOSE.BAN_24H) {
                txt = "Blocked for 24 hours after repeated failed attempts. Try again after that.";
            } else if (code === CLOSE.CODE_MISSING) {
                txt = "Code expired.";
            } else if (code === CLOSE.NOT_A_MEMBER) {
                txt = "That session is already in use by two devices.";
            } else if (code === CLOSE.RELAY_BUDGET) {
                txt = "That session reached its transfer limit. Start a new one.";
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
    resumeToken = ""; // a stale token must never be presented to a new room
    turnConfig = null; // creds are room-scoped; a new room mints its own
    if (role === "receiver") {
        $("receiver-error").textContent = reason;
        show("receiver");
    } else {
        // the sender's intent is still "send", so a failed
        // pairing mints a fresh code on the spot instead of dead-ending in the
        // fatal view. abort() has already closed the WS and zeroized keys;
        // startSender() opens a clean room (openWs resets `aborted`). If even
        // /new fails, startSender shows the fatal view itself.
        startSender().then(() => {
            setWaitMsg("That code didn't match — share this fresh one.", "warn");
        }).catch(() => {});
    }
}

// Session strip writer. Display-only: it renders the transport state app.js
// already tracks, so the strip never claims a direct path while we are relaying.
function setSessionPath(label) {
    const el = $("session-path");
    if (!el) return;
    const prev = el.textContent;
    el.textContent = label;
    if (prev && prev !== label) {
        // re-trigger the animation even if it's already mid-run from a prior change
        el.classList.remove("bm-session-path--changed");
        void el.offsetWidth;
        el.classList.add("bm-session-path--changed");
    }
}

function enterChat() {
    $("chat-log").innerHTML = "";
    $("session-code").textContent = currentCode || "";
    setSessionPath("server relay"); // until a data channel opens, frames go over WS
    $("chat-input").value = "";
    for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
        const el = $(id);
        if (el) el.disabled = false;
    }
    $("btn-vanish").classList.remove("bm-vanish-btn--killing");
    disarmVanish(); // a new session must never open with the old one's confirm armed
    setChatChip("ok", "Connected");
    show("chat");
    // 28.1: keep history depth at 1. A typed/QR-view join already pushed a
    // sender/receiver entry — retag it as the chat entry; a deep-link join
    // pushed nothing (its hash was scrubbed via replaceState), so push here to
    // give the Back guard an entry to hold.
    if (history.state && history.state.irisView) replaceView("chat");
    else pushView("chat");
    // 26.2: never auto-focus the composer while consent is withheld — a
    // focused textarea turns reflex keystrokes into consent gestures.
    if (rtcConsent) $("chat-input").focus();
    startWsKeepalive();
    startPeerSilenceWatch();
    startPathLabelWatch();
    acquireWakeLock();
}

// Sends a no-op frame over WS every WS_KEEPALIVE_MS when DC is active, preventing
// Cloudflare and other tunnel proxies from treating the idle signaling socket as
// dead. It is also the peer's liveness beacon: it is the only frame a
// session that is merely idle still emits, so the silence threshold is measured
// against it.
function startWsKeepalive() {
    if (wsKeepaliveTimer !== null) clearInterval(wsKeepaliveTimer);
    wsKeepaliveTimer = setInterval(() => {
        if (step === "chat") sendPayload(T_KEEPALIVE, new Uint8Array(0));
    }, WS_KEEPALIVE_MS);
}

function stopWsKeepalive() {
    if (wsKeepaliveTimer !== null) { clearInterval(wsKeepaliveTimer); wsKeepaliveTimer = null; }
}

// Called for every inbound frame that proves the peer is still there. Only
// AEAD-verified frames qualify: a relay hint is evidence about the SERVER, and
// the question here is whether the PEER is alive.
function notePeerFrame() {
    lastPeerFrameAt = Date.now();
}

function startPeerSilenceWatch() {
    notePeerFrame(); // a fresh session starts with a clean slate, not a stale stamp
    peerSilenceShown = false;
    if (peerSilenceTimer !== null) clearInterval(peerSilenceTimer);
    peerSilenceTimer = setInterval(checkPeerSilence, PEER_SILENCE_CHECK_MS);
}

function stopPeerSilenceWatch() {
    if (peerSilenceTimer !== null) { clearInterval(peerSilenceTimer); peerSilenceTimer = null; }
    peerSilenceShown = false;
}

function checkPeerSilence() {
    if (step !== "chat") return;
    // Our own socket being down is a different, truer statement, and attemptResume
    // already owns the chip while it says so. Never overwrite it — we cannot
    // distinguish a silent peer from a silent us.
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const silent = Date.now() - lastPeerFrameAt >= PEER_SILENCE_MS;
    if (silent && !peerSilenceShown) {
        // Deliberately weaker than the server's "Peer connection lost": at this
        // point all we know is that nothing has arrived. Claiming more would be
        // the same overclaiming this step exists to remove.
        setChatChip("warn", "Peer not responding…");
        peerSilenceShown = true;
    } else if (!silent && peerSilenceShown) {
        setChatChip("ok", "Connected");
        peerSilenceShown = false;
    }
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
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        // Foreground return: background retries already climbed the backoff
        // ladder — reconnect now instead of serving a stale 12 s delay.
        resumeAttempt = 0;
        attemptResume();
    }
});

// The browser knows the exact moment connectivity comes
// back and we were not listening — recovery relied entirely on blind backoff
// polling. That is the wrong trade in both directions: it is slow when the
// network returns early, and it is wasteful when it does not.
//
// With the connection budget in place this is safe to wire up: a flapping interface can
// fire `online` as often as it likes, and resumeBudgetAvailable() still refuses
// the 5th attempt in any 60 s window.
//
// Deliberately NOT listening for `offline` to drive the chip. `navigator.onLine`
// is unreliable in exactly the direction that would hurt — it reports true behind
// a captive portal and false on some platforms with a working connection — and a
// chip that lies confidently is the failure this check exists to remove. As a trigger to
// *try harder* a wrong answer costs one refused attempt; as a UI claim it costs
// the user's trust.
window.addEventListener("online", () => {
    if (step !== "chat") return;
    if (ws && ws.readyState === WebSocket.OPEN) return;
    // Fresh ladder: this is real evidence, not another blind tick.
    resumeAttempt = 0;
    // But NOT instantly. `online` means the OS has an interface, not that it can
    // carry a connection — a phone leaving airplane mode is still reattaching to
    // the radio. Measured twice on real devices: the attempt fired the same
    // millisecond as `online` and failed 100 ms later, both times, and that wasted
    // attempt was the last one the budget allowed. Give the radio a moment.
    if (resumeTimer !== null) clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => { resumeTimer = null; attemptResume(); }, ONLINE_SETTLE_MS);
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
    // Each failed connect closes instantly and re-enters here; without spacing
    // that hammers the server and walks our own IP up the cooldown→ban ladder.
    let delay = RESUME_BACKOFF_MS[Math.min(resumeAttempt, RESUME_BACKOFF_MS.length - 1)];
    // Never schedule a retry past the end of the window. The 22 s final step
    // overshot a 60 s window in real-device testing — the last retry was booked for 62 s and
    // the window shut at 60, so the closing 20 seconds contained no attempt at all.
    const latest = resumeUntil - RESUME_LAST_CHANCE_MS;
    if (Date.now() + delay > latest) delay = Math.max(1000, latest - Date.now());
    resumeAttempt += 1;
    if (resumeTimer !== null) clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => {
        resumeTimer = null;
        if (step !== "chat") return;                        // session ended while waiting
        if (ws && ws.readyState === WebSocket.OPEN) return; // already resumed (visibility race)
        // The budget is checked at the moment of connecting, not when the
        // retry was scheduled — anything else (visibility, `online`) may have
        // spent it while this timer was pending.
        if (!resumeBudgetAvailable(false)) {
            // Budget spent. Waiting for a slot is only worth doing if a slot
            // actually frees up while the window is still open.
            const freeIn = Math.max(500, resumeAttemptTimes[0] + RESUME_WINDOW_MS - Date.now());
            const slotArrivesTooLate = Date.now() + freeIn > resumeUntil - RESUME_LAST_CHANCE_MS;
            if (!slotArrivesTooLate) {
                // Come back when the slot frees. Returning outright would STALL the
                // loop: nothing else restarts it, and resumeUntil is only re-checked
                // on entry to attemptResume.
                resumeTimer = setTimeout(attemptResume, freeIn);
                return;
            }
            // Waiting would burn the rest of the window doing nothing — which is
            // exactly how two sessions died in testing, both with the network
            // already back. Spend the reserve slot instead: our routine cap is 4,
            // the server does not cool down until the 6th, so a 5th is within its
            // tolerance. This costs the margin we hold for a same-IP join landing
            // in the same window (the two peers DO share an IP on one WiFi), and
            // that is the right trade against a session that is otherwise dead.
            if (!resumeBudgetAvailable(true)) {
                resumeTimer = setTimeout(attemptResume, Math.max(500, resumeUntil - Date.now()));
                return;
            }
        }
        openWs(routingCode, null, true); // records its own attempt — see openWs
    }, delay);
}

// 15.9 Peer gone / session ended: disable inputs, flip the header chip to err tone.
function endChatSession() {
    step = null;
    sessionEnded = true; // 23.5: mark deliberate end so the late WS close doesn't resurrect a view
    heldRtcSignals = []; rtcConsent = true; // 26.2: held peer SDP (its IP) must not outlive the session
    $("code-input").value = "";
    useRTC = false;
    drainAckWaiters(); // unblock any sendFile/handleFileNack loop waiting on ACK
    settleDcReconnect(); // abandon any in-flight DC rebuild + wake parked loops (16.9.1)
    clearRecvStall(); // 21.4 — no watchdog may outlive the session
    clearPendingDeliveryTimer(); // same rule for the sender-side confirmation watchdog
    forgetTransferState(); // and no transfer state may either
    stopWsKeepalive();
    stopPeerSilenceWatch(); // no watchdog may outlive the session
    stopPathLabelWatch();
    releaseWakeLock();
    closeAllDcPaths();
    zeroizeKeys(); // session over (peer left / timeout) — wipe keys
    resumeToken = ""; // a stale token must never be presented to a new room
    turnConfig = null; // creds are room-scoped; a new room mints its own
    previewUrls.forEach(u => URL.revokeObjectURL(u)); // 23.3
    previewUrls = [];
    clearStagedImage(); // 23.8 — never leave an unsent image behind
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
// Ending a session is instant and irreversible — the log is gone, the room is
// torn down, there is nothing to undo. So the button arms first and only fires on
// a second press, and disarms itself if that press does not come. Cheaper than a
// modal, and it keeps the destructive weight on the control itself.
const VANISH_ARM_MS = 3000;
let vanishArmTimer = null;

let vanishCountdownTimer = null;

function disarmVanish() {
    clearTimeout(vanishArmTimer);
    vanishArmTimer = null;
    clearInterval(vanishCountdownTimer);
    vanishCountdownTimer = null;
    const btn = $("btn-vanish");
    btn.classList.remove("bm-vanish-btn--armed");
    btn.textContent = "End session";
}

function requestVanish() {
    const btn = $("btn-vanish");
    if (vanishArmTimer !== null) { disarmVanish(); panicVanish(); return; }
    btn.classList.add("bm-vanish-btn--armed");
    // B2 (launch polish): the arm window silently expiring was a trap — show
    // the seconds so the second press is an informed one. The button carries
    // aria-live, so the countdown also reaches screen readers.
    let remaining = Math.ceil(VANISH_ARM_MS / 1000);
    btn.textContent = `Press again to end (${remaining})`;
    vanishCountdownTimer = setInterval(() => {
        remaining -= 1;
        if (remaining > 0) btn.textContent = `Press again to end (${remaining})`;
    }, 1000);
    vanishArmTimer = setTimeout(disarmVanish, VANISH_ARM_MS);
}

function panicVanish() {
    sendPayload(T_BYE, new Uint8Array(0)); // must be first — sendPayload checks step === "chat"
    const btn = $("btn-vanish");
    btn.classList.add("bm-vanish-btn--killing");
    setTimeout(_doVanish, 350);
}
function _doVanish() {
    aborted = true;
    sessionEnded = false; // 23.5: back to landing — re-arm for the next session
    step = null;
    useRTC = false;
    drainAckWaiters();
    settleDcReconnect(); // 16.9.1: abandon any DC rebuild + wake parked loops
    clearRecvStall(); // 21.4 — no watchdog may outlive the session
    clearPendingDeliveryTimer(); // same rule for the sender-side confirmation watchdog
    forgetTransferState(); // and no transfer state may either
    stopWsKeepalive();
    stopPeerSilenceWatch(); // no watchdog may outlive the session
    stopPathLabelWatch();
    releaseWakeLock();
    // 23.4: plaintext marker so the server can skip resume-grace and tear the
    // room down immediately — T_BYE above is best-effort (sendPayload silently
    // no-ops when the WS isn't OPEN), this is the server-authoritative backstop.
    if (ws && ws.readyState === WebSocket.OPEN) {
        try { ws.send("BEEM-LEAVE"); } catch (_) {}
    }
    try { ws && ws.close(); } catch (_) {}
    closeAllDcPaths();
    ws = null;
    zeroizeKeys(); // panic vanish — overwrite then drop all key material
    resumeToken = ""; // a stale token must never be presented to a new room
    turnConfig = null; // creds are room-scoped; a new room mints its own
    previewUrls.forEach(u => URL.revokeObjectURL(u)); // 23.3
    previewUrls = [];
    clearStagedImage(); // 23.8 — never leave an unsent image behind
    pakeState = null;
    sendCounterWS = 0n;
    recvCounterWS = -1n;
    sendCountersDC = [0n, 0n, 0n, 0n];
    recvCountersDC = [-1n, -1n, -1n, -1n];
    recvMasksDC = [0n, 0n, 0n, 0n];
    role = currentCode = routingCode = null;
    rtcConsent = true; heldRtcSignals = []; // 26.2: a fresh session starts unheld
    $("qr-code").innerHTML = ""; // 23.6: drop the stale code's QR before the next session
    $("chat-log").innerHTML = "";
    $("chat-input").value = "";
    $("file-status").textContent = "";
    for (const id of ["chat-input", "btn-chat-send", "btn-file-pick"]) {
        const el = $(id);
        if (el) el.disabled = false;
    }
    show("landing");
}

$("btn-vanish").addEventListener("click", requestVanish);

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

// Self-hosted STUN/TURN (16.7.7): /turn.json is deployment-specific
// (gitignored) so the relay address never enters the repo. Shape:
// { "urls": ["stun:host:3478", "turn:host:3478?transport=udp"], "username": "...", "credential": "..." }
// Absent or malformed → fall back to Google STUN (local dev / CI unchanged).
// A tampered turn.json can only redirect the relay path, which is untrusted by
// design — media stays E2E encrypted — so this file needs no SRI pin.
let turnConfig = null;
// /turn.json used to be fetched here, at page load, by anyone
// who opened the page — which is exactly why the relay was minting credentials
// to callers who never paired. It now requires the routing code plus the
// member token, so it can only run once we are an admitted member of a room.
// The token goes in a header rather than the query string so a fronting proxy's
// access log never records it.
//
// no-store: relay config must always be current — a cached copy silently pins
// clients to a retired relay lane (seen when a relay-port change had no effect on cached clients)
async function loadTurnConfig() {
    if (turnConfig) return;                    // one mint per room is enough
    if (!routingCode || !resumeToken) return;  // not a member yet → public STUN
    try {
        const r = await fetch("./turn.json?code=" + encodeURIComponent(routingCode), {
            cache: "no-store",
            headers: { "X-Iris-Member": resumeToken },
        });
        if (!r.ok) return;                     // 403/404 → public STUN, as before
        const j = await r.json();
        if (j && Array.isArray(j.urls) && j.urls.every(u => typeof u === "string")
            && typeof j.username === "string" && typeof j.credential === "string") {
            turnConfig = j;
        }
    } catch (_) { /* unreachable relay config → public STUN fallback */ }
}

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
// of the receiver in real-device testing).
const DC_BUFFER_CAP = 2 * 1024 * 1024;
const DC_STALL_MS = 5000;
function dcPathStalled(p, now) {
    const b = p.dc.bufferedAmount;
    // b === 0 must reset the clock, not just a decrease: an idle path drains to
    // 0 and then nobody calls pickDcPath() again for as long as the session is
    // quiet, so lastDrain goes stale. Without this, the FIRST send after any
    // idle gap > DC_STALL_MS is misread as a stall on the very next pick — the
    // path is closed on sight with that just-written frame still queued and the
    // frame is destroyed. Bit 21.4's NACK retransmit (written, then END picks a
    // path 5 ms later, then close) but it was always latent for any send that
    // follows a quiet stretch. An empty buffer has nothing to drain, so it can
    // never be "stalled" — only sustained b > 0 with no drain means a dead route.
    if (p.lastBuf === undefined || b < p.lastBuf || b === 0) {
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

// the transport label is a standing fact, so it has to keep being true.
//
// This used to run once, on the first path that opened, and never again: the code
// said so itself ("label the connection once"). Real-device runs
// caught the consequence four times — one end saying `direct lan` while
// the other said `server relay` for the same connection, and the PC still claiming
// `direct lan` for a connection that had definitively changed.
//
// The naming half of the disagreement had a second cause, visible in the code
// above: `let label = "Direct"` was the DEFAULT, so an end whose `getStats()`
// returned no nominated pair printed a *different word* than its peer without
// anything having gone wrong. That is now `direct (unverified)` — a strip that
// admits it could not check beats two strips quietly disagreeing.
//
// Re-derivation is cheap and setSessionPath only animates on an actual change, so
// a stable path does not flicker.
async function derivePathLabel() {
    const open = openDcPaths();
    if (!open.length) return "server relay";
    let best = null;
    let live = 0;
    for (const path of open) {
        // A DataChannel stays readyState:"open" while its PeerConnection has
        // already failed — the zombie-channel case, caught on
        // the wire: pc0/pc1 went `failed` at 69.5 s while the strip
        // still counted them and said "direct (unverified)", with 89 MB of that
        // session's traffic going over the WS relay. "I cannot tell" was honest
        // and useless; the true answer was "relay". A path whose transport has
        // failed is not carrying anything, so it does not get a vote.
        const st = path.pc?.connectionState;
        if (st === "failed" || st === "disconnected" || st === "closed") continue;
        live++;
        try {
            const stats = await path.pc.getStats();
            // `nominated` alone is not dependable: Chrome reported it on the first
            // derivation and not on later ones, so re-deriving turned a perfectly
            // good `direct lan` into `direct (unverified)` mid-session
            // while ICE was still host/host on all four paths. Accept a
            // succeeded/selected pair too — that is what the connection is using.
            // ...but "accept a succeeded pair" was implemented as "keep whichever
            // succeeded pair the stats map yields LAST", and a connection routinely has
            // more than one. Observed on a real device: on all four connections ICE
            // reported host/host AND srflx/srflx, both `nominated`, simultaneously — so
            // the printed label depended on map iteration order. The PC walked
            // "server relay" → "p2p (internet)" → "direct lan" on a device that never
            // left the WiFi, and the two ends still disagreed at the end. Rank the pairs
            // instead: a relay pair is the WEAKEST answer, not the strongest, and must
            // never mask a host pair on the same connection. In-use (nominated/selected)
            // outranks specificity, because a nominated relay really is what is carrying
            // the bytes even when a host pair merely succeeded.
            let pair = null;
            let pairRank = -1;
            stats.forEach(s => {
                if (s.type !== "candidate-pair") return;
                const inUse = !!(s.nominated || s.selected);
                if (!inUse && s.state !== "succeeded") return;
                const lt = stats.get(s.localCandidateId)?.candidateType;
                const rt = stats.get(s.remoteCandidateId)?.candidateType;
                let rank;
                if (lt === "relay" || rt === "relay") rank = 0;
                else if (lt === "srflx" || rt === "srflx") rank = 1;
                else if (lt === "host" && rt === "host") rank = 3;
                else rank = 2;                       // prflx, or a mixed non-relayed pair
                if (inUse) rank += 4;
                if (rank > pairRank) { pairRank = rank; pair = s; }
            });
            if (!pair) continue;
            const local  = stats.get(pair.localCandidateId);
            const remote = stats.get(pair.remoteCandidateId);
            if (local?.candidateType === "relay" || remote?.candidateType === "relay")
                // Not "p2p": a TURN allocation forwards every byte through our relay
                // box. Saying "p2p" about a relayed path is a false claim in the one
                // place a user looks to find out where their file is going.
                best = best || "relay (turn)";
            else if (local?.candidateType === "host" && remote?.candidateType === "host")
                return "direct lan";          // most specific answer wins immediately
            else if (local?.candidateType === "srflx" || remote?.candidateType === "srflx")
                best = best || "p2p (internet)";
            // Peer-reflexive: an address learned from an incoming connectivity
            // check. It is a real, non-relayed path — a real-device run
            // had the PC reading host/host while the phone read host/prflx for the
            // SAME connection, and prflx fell through to "(unverified)". It is not
            // unverified, it is direct; we just cannot prove it is a LAN, so this
            // deliberately does not claim "lan".
            else if (local?.candidateType === "prflx" || remote?.candidateType === "prflx")
                best = best || "direct";
        } catch (_) {}
    }
    // Every channel's transport is dead — whatever is still moving is moving over
    // the relay, and that is what the strip must say.
    if (!live) return "server relay";
    // Channels are live but no usable pair could be read. Say that, rather than
    // silently printing a shorter word than the peer is printing.
    return best || "direct (unverified)";
}

let pathLabelTimer = null;
async function refreshPathLabel() {
    if (step !== "chat") return;
    setSessionPath(await derivePathLabel());
}

function startPathLabelWatch() {
    if (pathLabelTimer !== null) clearInterval(pathLabelTimer);
    pathLabelTimer = setInterval(refreshPathLabel, PATH_LABEL_MS);
}

function stopPathLabelWatch() {
    if (pathLabelTimer !== null) { clearInterval(pathLabelTimer); pathLabelTimer = null; }
}

function wireDataChannel(path) {
    const dc = path.dc;
    dc.onopen = async () => {
        useRTC = true;
        if (dcReconnecting) settleDcReconnect(); // unpark chunk loops on the rebuilt path
        // Every open re-evaluates, not just the first: a rebuilt path routinely
        // lands on a different candidate type than the one it replaced.
        // No log line — the strip shows the path continuously, and a standing fact
        // does not belong in a timestamped event log.
        refreshPathLabel();
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
        const body = authenticatedPayload(type, pt); // 26.1: trust pt[0], not buf[0]
        if (!body) return;
        dcReplayMark(pid, dcCounter); // authenticated — only now may it move the window
        // Silent on mismatch (unlike WS): a DC peer already holds the key and could
        // simply send a real T_BYE — announcing it would only add noise.
        handleChatPayload(pt[0], body); // dispatch on the AUTHENTICATED type
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
    // A path dying changes what is true even when others survive — re-derive
    // before the early return, or a degraded session keeps its old label.
    refreshPathLabel();
    if (useRTC) return; // 16.9.2 graceful degrade — surviving paths carry the transfer
    if (step !== "chat" || dcReconnecting) return; // teardown, or already rebuilding
    dcReconnecting = true;
    // transport-path changes are the strip's job now, not the log's — it already
    // shows the path continuously, so an event here would just repeat it.
    setSessionPath("reconnecting…");
    if (role === "sender") {
        rebuildRTC();
    } else {
        // Bounded park covering the sender's full retry budget, plus slack.
        setTimeout(() => {
            if (!dcReconnecting) return;
            settleDcReconnect();
            if (step === "chat") {
                setSessionPath("server relay");
            }
        }, DC_RECONNECT_TRIES * DC_RECONNECT_OPEN_MS + 2000);
    }
}
async function rebuildRTC() {
    for (let i = 0; i < DC_RECONNECT_TRIES && step === "chat"; i++) {
        // Offers travel over WS signalling — a try during a WS outage is a
        // guaranteed no-op (sendSignal drops on closed WS). Wait, bounded, for
        // the resumed socket before spending the attempt.
        const wsDeadline = Date.now() + RESUME_GRACE_MS + 5000;
        while (step === "chat" && (!ws || ws.readyState !== WebSocket.OPEN) && Date.now() < wsDeadline) {
            await new Promise(r => setTimeout(r, 250));
        }
        closeAllDcPaths();
        await loadTurnConfig(); // no-op once minted; covers a resume that never had creds
        setupWebRTC(); // fresh paths + offers over WS signalling
        const deadline = Date.now() + DC_RECONNECT_OPEN_MS;
        while (Date.now() < deadline && step === "chat" && openDcPaths().length === 0) {
            await new Promise(r => setTimeout(r, 100));
        }
        if (openDcPaths().length > 0) { settleDcReconnect(); return; }
    }
    settleDcReconnect();
    if (step === "chat") {
        setSessionPath("server relay");
    }
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
// in RAM" (a real-device run had the receiver ~40 MB behind at "100%" and a
// kill-chat at that moment destroyed the tail). Stalled paths are closed — their queued
// chunks are lost, but the receiver's NACK round at T_FILE_END repairs that.
// Returns on cancel or reconnect too; both leave nothing more to drain here.
// refs may be null (NACK repair round): drain the buffers without touching a row
// that already reads "Sent" — the bytes are the point, not the progress display.
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
        if (refs) updateFileRow(refs, Math.max(0, sentBytes - buffered), totalBytes, "Sending", 0);
        await new Promise(r => setTimeout(r, 100));
    }
}

function sendSignal(type, jsonStr) {
    // Signaling goes over WS relay even when useRTC is true
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const nonce = makeNonce(sendCounterWS, 0);
    if (!nonce) return;
    sendCounterWS += 1n;
    const plaintext = withType(type, textEnc.encode(jsonStr)); // 26.1 type is inside the AEAD
    let ct;
    try { ct = encrypt(sendKey, nonce, plaintext); } catch (_) { return; }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type; // wire copy only — receivers trust pt[0]
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
    // Chunk frames stripe across open DC paths (16.9.2, least-buffered first);
    // signaling + chat always via WS. HDR/END are WS-only too: a zombie DC
    // (carrier reset under a frozen tab) eats them silently and the receiver
    // then has no transfer slot to ACK relayed chunks into — sender deadlocks
    // at the ACK window (seen in real-device testing). earlyChunks replay (16.9.2)
    // covers chunks beating the WS header across a faster path.
    const wantsDC = type === T_FILE_CHK;
    const path = wantsDC && useRTC ? pickDcPath() : null;
    if (!path && (!ws || ws.readyState !== WebSocket.OPEN)) return false;
    const nonce = path ? makeNonce(sendCountersDC[path.id], 1 + path.id)
                       : makeNonce(sendCounterWS, 0);
    if (!nonce) return false;
    if (path) { sendCountersDC[path.id] += 1n; } else { sendCounterWS += 1n; }
    let ct;
    try {
        ct = encrypt(sendKey, nonce, withType(type, plaintext)); // 26.1 type is inside the AEAD
    } catch (_) {
        appendSystemMsg("(encrypt failed)");
        return false;
    }
    const frame = new Uint8Array(1 + 12 + ct.length);
    frame[0] = type; // wire copy only — receivers trust pt[0]
    frame.set(nonce, 1);
    frame.set(ct, 13);
    if (path) {
        path.dc.send(frame);
    } else {
        ws.send(frame);
    }
    return true;
}

// HDR/END delivery: parks on the mobile-resume machinery like the chunk loop —
// a WS blip mid-send reopens within the grace window and the frame goes out then.
async function sendCtrlFrame(type, payload) {
    if (sendPayload(type, payload)) return true;
    const retryUntil = Date.now() + RESUME_GRACE_MS + 5000;
    while (!sendCancelled && step === "chat" && Date.now() < retryUntil) {
        await new Promise(r => setTimeout(r, 250));
        if (sendPayload(type, payload)) return true;
    }
    return false;
}

// 23.8 — images are staged for confirmation instead of being sent on sight: an
// accidental Ctrl+V used to transmit a screenshot with no undo. Non-image files
// keep the send-on-pick behaviour. Display-only; the transfer path is unchanged.
let stagedImage = null;
let stagedImageUrl = null;

function isImageFile(file) {
    if (imageMimeFor(file.name)) return true;
    return !!(file.type && file.type.startsWith("image/"));
}

function stageImage(file) {
    if (step !== "chat") return;
    clearStagedImage(); // a second paste replaces the first, never stacks
    stagedImage = file;
    $("img-stage-name").textContent = file.name || "image";
    $("img-stage-size").textContent = fmtBytes(file.size);
    const thumb = $("img-stage-thumb");
    // Oversized images still stage (so the confirm step is consistent for every
    // image) but show no thumbnail — same 10 MB ceiling as the in-chat preview.
    if (file.size <= MAX_PREVIEW_SIZE) {
        stagedImageUrl = URL.createObjectURL(file);
        thumb.src = stagedImageUrl;
        thumb.hidden = false;
    }
    $("img-stage").hidden = false;
    $("chat-input").focus();
}

function clearStagedImage() {
    stagedImage = null;
    if (stagedImageUrl) {
        URL.revokeObjectURL(stagedImageUrl);
        stagedImageUrl = null;
    }
    const thumb = $("img-stage-thumb");
    thumb.removeAttribute("src");
    thumb.hidden = true;
    $("img-stage").hidden = true;
}

// Routes a picked/pasted/dropped file: images wait for confirmation, everything
// else sends immediately as before.
function offerFile(file) {
    if (isImageFile(file)) stageImage(file);
    else sendFile(file);
}

function sendChat() {
    // A staged image takes priority over the text box; any typed text is left
    // untouched so it can be sent as its own message afterwards.
    if (stagedImage) {
        const file = stagedImage;
        clearStagedImage();
        sendFile(file);
        return;
    }
    const text = $("chat-input").value;
    if (!text) return;
    const bytes = textEnc.encode(text);
    if (bytes.length > MAX_TEXT_BYTES) {
        appendSystemMsg(`(message is ${fmtBytes(bytes.length)} — the limit is ${fmtBytes(MAX_TEXT_BYTES)}; save it as a file and send that)`);
        return;
    }
    if (sendPayload(T_TEXT, bytes)) {
        appendChatMsg("out", text);
        $("chat-input").value = "";
    }
}

function handleChatPayload(type, pt) {
    // the single choke point every inbound AEAD frame passes through, from
    // either lane (WS relay and DataChannel both land here). Stamping it rather
    // than the two call sites is what makes T_KEEPALIVE meaningful: its entire
    // handling below is `return`, so before this it could detect nothing at all.
    notePeerFrame();
    if (type === T_TEXT) {
        appendChatMsg("in", textDec.decode(pt));
        return;
    }
    if (type === T_FILE_HDR) { handleFileHdr(pt); return; }
    if (type === T_FILE_CHK) { handleFileChunk(pt); return; }
    if (type === T_FILE_END) { handleFileEnd(pt); return; }
    if (type === T_RTC_OFFER || type === T_RTC_ANSWER || type === T_RTC_ICE) {
        if (!rtcConsent) {
            // 26.2: hold, don't drop — the peer's offers are replayed on the first
            // gesture. `pt` is a view into the frame buffer; keep our own copy.
            if (pt.length <= HELD_RTC_MAX_BYTES && heldRtcSignals.length < HELD_RTC_MAX) {
                heldRtcSignals.push([type, pt.slice()]);
            }
            return;
        }
        handleRTCSignal(type, pt).catch(() => {}); // a malformed signal must not be an unhandled rejection
        return;
    }
    if (type === T_FILE_NACK) { handleFileNack(pt); return; }
    if (type === T_FILE_ACK)  { ackReceived(); return; }
    if (type === T_FILE_CANCEL) { handleFileCancel(pt); return; }
    if (type === T_FILE_DONE) { handleFileDone(pt); return; }
    if (type === T_KEEPALIVE) return;
    if (type === T_BYE) { endChatSession(); return; }
    console.warn(`[iris] unknown frame type 0x${type.toString(16)}`); appendSystemMsg("(a message was ignored for your safety)");
}

// 23.9 — inline SVGs for the per-message copy button (same clipboard glyph as the
// pairing-code copy button, plus a check for the copied state). Static strings, no
// user data, so innerHTML is safe here.
const COPY_ICON_SVG =
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const CHECK_ICON_SVG =
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="20 6 9 17 4 12"/></svg>';
// Double-check — the two-ends-agree verdict on a file's digest, distinct from the
// single check used for "copied". Two overlapping checkmark polylines, same
// stroke conventions as CHECK_ICON_SVG above.
const DOUBLE_CHECK_ICON_SVG =
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="18 6 7 17 2 12"/><polyline points="22 10 11 21 9 19"/></svg>';

// File-card icons. Static strings, no user data, so innerHTML is safe here.
const FILE_ICON_SVG =
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/>' +
    '<path d="M14 2v5h5"/></svg>';
const DOWNLOAD_ICON_SVG =
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></svg>';
const CANCEL_ICON_SVG =
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';

function appendChatMsg(direction, text) {
    const wrap = document.createElement("div");
    wrap.className = `bm-msg bm-msg--${direction}`;
    const bubble = document.createElement("div");
    bubble.className = "bm-msg-bubble";
    bubble.textContent = text;
    wrap.appendChild(bubble);
    const actions = document.createElement("div");
    actions.className = "bm-msg-actions";
    // Local wall-clock stamp, display-only: never sent on the wire, never stored.
    // The "sent"/"received" word is gone — the side the bubble sits on and its
    // surface colour already carry direction, and the word doubled the meta.
    const timeText =
        new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    // 23.1 — long messages collapse with a fade + toggle, no auto-scroll on toggle
    if (text.length > 600) {
        // A collapsed bubble would hide an in-bubble stamp below the fade, so
        // long messages keep theirs on the actions row beside the toggle.
        const stamp = document.createElement("span");
        stamp.className = "bm-msg-time";
        stamp.textContent = timeText;
        actions.appendChild(stamp);
        bubble.classList.add("bm-msg-bubble--collapsed");
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "bm-msg-toggle";
        toggle.textContent = "See more";
        toggle.addEventListener("click", () => {
            const collapsed = bubble.classList.toggle("bm-msg-bubble--collapsed");
            toggle.textContent = collapsed ? "See more" : "See less";
        });
        actions.appendChild(toggle);
    } else {
        // Messenger placement: the time rides inside the bubble, floated to the
        // trailing edge of the last line, so a message costs one row instead of two.
        // It is CSS generated content off this attribute, never a child node — the
        // bubble's text must stay exactly the message the peer sent, so that a text
        // selection, a copy, and the browser tests all see the message and nothing else.
        bubble.dataset.time = timeText;
    }
    if (actions.childNodes.length) wrap.appendChild(actions);
    // 23.2 — per-message copy button; hidden when Clipboard API is unavailable.
    // 23.9 — icon instead of "Copy" text: quiet clipboard glyph, green check on copy.
    if (navigator.clipboard && navigator.clipboard.writeText) {
        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "bm-msg-copy";
        copyBtn.setAttribute("aria-label", "Copy message");
        copyBtn.title = "Copy";
        copyBtn.innerHTML = COPY_ICON_SVG;
        let copyTimer = null;
        copyBtn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(text);
            } catch (_) {
                return;
            }
            clearTimeout(copyTimer);
            copyBtn.classList.add("bm-msg-copy--copied");
            copyBtn.innerHTML = CHECK_ICON_SVG;
            copyBtn.title = "Copied";
            copyTimer = setTimeout(() => {
                copyBtn.classList.remove("bm-msg-copy--copied");
                copyBtn.innerHTML = COPY_ICON_SVG;
                copyBtn.title = "Copy";
            }, 2000);
        });
        // Sits outside the bubble on its outer edge (CSS), not on a row beneath
        // it — a hover-revealed control must not cost a row of height at rest.
        wrap.appendChild(copyBtn);
    }
    // Consecutive messages from the same side form a group: CSS tightens the gap
    // inside one, so a burst of replies reads as a burst instead of a list.
    const prev = $("chat-log").lastElementChild;
    if (prev && prev.classList.contains(`bm-msg--${direction}`)) {
        wrap.classList.add("bm-msg--stacked");
    }
    $("chat-log").appendChild(wrap);
    wrap.scrollIntoView({ block: "end" });
}

// Returns the element so a caller can close the loop on it later. A repair
// notice is written in the present tense because it is true when printed —
// and the log is permanent and untimestamped, so it stays on screen claiming
// to be in progress long after the round finished. Anything phrased as ongoing
// MUST be rewritten by its owner when it stops. Same honest-signal rule as F-1.
function appendSystemMsg(text) {
    const div = document.createElement("div");
    div.className = "bm-sys-msg";
    div.textContent = text;
    $("chat-log").appendChild(div);
    div.scrollIntoView({ block: "end" });
    return div;
}

// Rewrite a still-running notice into its finished form. No-op if the notice
// was never printed (the overwhelmingly common case: no repair round ran).
function settleSystemMsg(el, text) {
    if (el) el.textContent = text;
}

function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// 23.3 — MIME is never sent on the wire; infer preview eligibility from the
// filename extension alone (display-only, no effect on transfer).
// Phase 25.2: the peer picks the filename, the browser saves under it. The
// name is only ever DISPLAYED via textContent (no markup risk), but
// `a.download` hands it to the OS: a right-to-left override (U+202E) makes
// "photo\u202Egpj.exe" render as "photoexe.jpg", and control/format characters
// or path separators let a hostile peer steer where and as what it lands.
// This keeps the saved name honest; the display keeps the raw name. Legitimate
// multi-dot names ("archive.tar.gz") are untouched — a double extension is a
// user-visible fact, not something we can rewrite without breaking real names.
// Controls, bidi/format overrides, and the invisible "letters" (Hangul fillers,
// braille blank, variation selectors, tag characters) that no browser strips and
// that pad a real extension out of view in a file manager.
const UNSAFE_NAME_CHARS = /[\u0000-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|[\uDB40-\uDB43][\uDC00-\uDFFF]/g;
const WINDOWS_DEVICE    = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i;
const NAME_SEPARATORS   = /[\/\\:*?"<>|]/g;
const MAX_SAVE_NAME     = 200;
function safeDownloadName(raw) {
    let n = String(raw == null ? "" : raw)
        .replace(UNSAFE_NAME_CHARS, "")
        .replace(NAME_SEPARATORS, "_")
        .replace(/^[\s.]+/, "")   // no hidden-file or "..": names, no leading spaces
        .replace(/[\s.]+$/, "");  // Windows drops trailing dots/spaces silently
    if (n.length > MAX_SAVE_NAME) {
        // Keep the real extension (if short) so the OS still opens it right.
        const dot = n.lastIndexOf(".");
        const ext = dot > 0 && n.length - dot <= 16 ? n.slice(dot) : "";
        let head = n.slice(0, MAX_SAVE_NAME - ext.length);
        if (/[\uD800-\uDBFF]$/.test(head)) head = head.slice(0, -1); // never split a pair
        n = (head + ext).replace(/[\s.]+$/, ""); // the cut can re-expose a trailing dot
    }
    if (WINDOWS_DEVICE.test(n)) n = "_" + n; // CON / NUL.jpg / COM1.pdf vanish on Windows
    return n || "download";
}

// The display must not carry the spoof either: an RLO in textContent still
// renders "photo\u202Egpj.exe" as "photoexe.jpg", and that is the string the
// user reads before clicking Download. Replace (don't delete) so the user can
// see something odd was there; keep dots and separators — they are real.
function displayName(raw) {
    return String(raw == null ? "" : raw).replace(UNSAFE_NAME_CHARS, "\uFFFD");
}

function imageMimeFor(name) {
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (ext === "png") return "image/png";
    if (ext === "jpg" || ext === "jpeg") return "image/jpeg";
    if (ext === "gif") return "image/gif";
    if (ext === "webp") return "image/webp";
    return null;
}

function appendFileRow(name, sizeBytes, direction, onCancel) {
    const row = document.createElement("div");
    // B3: --active pins the in-flight card (position: sticky) so heavy texting
    // can never scroll a live transfer out of sight. Dropped at terminal state.
    row.className = `bm-file-row bm-file-row--${direction} bm-file-row--active`;

    const nameEl = document.createElement("div");
    nameEl.className = "bm-file-name";
    // 16.8.1 — direction used to be a ↑/↓ glyph; it now reads from the side the
    // card sits on and its surface colour, exactly as the message bubbles do.
    nameEl.textContent = displayName(name); // 25.2: no bidi/invisible spoof in the UI
    nameEl.title = displayName(name);

    const icon = document.createElement("span");
    icon.className = "bm-file-icon";
    icon.innerHTML = FILE_ICON_SVG;

    // 16.8.2 — one action slot on the trailing edge: ✕ while in flight, swapped for
    // the download arrow once a received file is assembled. Emptied by
    // completeFileRow/failFileRow once the transfer reaches a terminal state.
    let cancelBtn = null;
    const action = document.createElement("div");
    action.className = "bm-file-action";
    if (onCancel) {
        cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "bm-file-btn bm-file-cancel";
        cancelBtn.innerHTML = CANCEL_ICON_SVG;
        cancelBtn.title = "Cancel transfer";
        cancelBtn.setAttribute("aria-label", "Cancel transfer");
        cancelBtn.addEventListener("click", onCancel);
        action.appendChild(cancelBtn);
    }

    const meta = document.createElement("div");
    meta.className = "bm-file-meta";
    // B3: the whole chat log is aria-live=polite; without this, every percent
    // tick is read aloud — a screen reader cannot talk over a transfer. The
    // filename still announces once when the card lands (it sits outside this).
    meta.setAttribute("aria-live", "off");
    meta.textContent = `0% of ${fmtBytes(sizeBytes)}`;

    const info = document.createElement("div");
    info.className = "bm-file-info";
    info.appendChild(nameEl);
    info.appendChild(meta);

    const head = document.createElement("div");
    head.className = "bm-file-head";
    head.appendChild(icon);
    head.appendChild(info);
    head.appendChild(action);

    const progress = document.createElement("div");
    progress.className = "bm-progress";
    const fill = document.createElement("div");
    fill.className = "bm-progress-fill";
    fill.style.width = "0%";
    progress.appendChild(fill);

    row.appendChild(head);
    row.appendChild(progress);

    $("chat-log").appendChild(row);
    row.scrollIntoView({ block: "end" });
    return { row, meta, fill, cancelBtn, action };
}

function removeCancelBtn(refs) {
    if (refs && refs.cancelBtn) {
        refs.cancelBtn.remove();
        refs.cancelBtn = null;
    }
}

// States the card already tells you without words: the side it sits on says who
// is sending, and a moving bar says it is moving. Naming them too pushed the meta
// past the card width, where it wrapped to two lines mid-transfer.
const IMPLIED_FILE_LABELS = new Set(["Sending", "Receiving"]);

// a status message and a progress readout want opposite things from this
// one line. The readout is a fixed shape rewritten every second, so it must stay
// on one line or the progress bar shifts under it (the reasoning behind
// .bm-file-meta's nowrap in style.css). A status message is written once at a
// state change and is the whole point of the card at that moment.
//
// The regression this fixes: RECONNECT_LABEL is 36 characters and does not
// fit a phone-width card on one line even alone, so the ellipsis cut it at
// roughly "Reconnecting — resumes autom…" — losing precisely the words that stop
// someone cancelling a transfer that is seconds from recovering. Widening the
// card is not the fix; letting a one-off status line wrap is.
function setFileMeta(refs, text, wrapping) {
    refs.meta.textContent = text;
    refs.meta.classList.toggle("bm-file-meta--status", !!wrapping);
}

// Used both to write the label and to recognise it — the two must not drift.
const RECONNECT_LABEL = "Reconnecting — resumes automatically";

function updateFileRow(refs, doneBytes, totalBytes, label, speedBps) {
    const pct = totalBytes > 0 ? Math.min(100, (doneBytes / totalBytes) * 100) : 0;
    refs.fill.style.width = `${pct.toFixed(1)}%`;
    // "Sent" is doneBytes === totalBytes by construction (every byte left this
    // machine), so the usual "100% of X" phrasing would read as finished \u2014 and
    // it isn't: T_FILE_DONE, the receiver's assembly confirmation, hasn't
    // landed yet. Say what's actually known instead of a percentage that can
    // only ever say 100.
    if (label === "Sent") {
        // A sentence, not the numeric line: wrapping, or the phone ellipsises it.
        setFileMeta(refs, "Sent \u00b7 waiting for confirmation", true);
        return;
    }
    // Nothing is moving during a reconnect, so the percentage and size are frozen
    // numbers competing for width with the only line that matters. The bar still
    // holds its position \u2014 it is the better carrier for "how far did we get".
    if (label === RECONNECT_LABEL) {
        setFileMeta(refs, label, true);
        return;
    }
    // Any other label means bytes are moving again \u2014 a post-"Sent" NACK repair
    // round lands here. The bar must not stay inert grey while it is working.
    refs.row.classList.remove("bm-file-row--pending");
    const speed = speedBps > 0 ? ` \u00b7 ${fmtBytes(speedBps)}/s` : "";
    const state = IMPLIED_FILE_LABELS.has(label) ? "" : `${label} \u00b7 `;
    // Percentage replaces the raw byte pair: it says the same thing in less width.
    // Total is kept (it's the one number the percentage can't convey).
    setFileMeta(refs, `${state}${pct.toFixed(0)}% of ${fmtBytes(totalBytes)}${speed}`, false);
}

function completeFileRow(refs, totalBytes, finalLabel) {
    removeCancelBtn(refs);
    refs.fill.style.width = "100%";
    refs.fill.classList.add("bm-progress-fill--complete");
    // A full bar pinned to the card's bottom edge just read as a border. On a
    // finished transfer the bar retires and the file icon carries the done state.
    refs.row.classList.add("bm-file-row--done");
    refs.row.classList.remove("bm-file-row--active"); // B3: done cards scroll normally
    // A delivered card must never keep the grey "waiting" bar styling underneath.
    refs.row.classList.remove("bm-file-row--pending");
    setFileMeta(refs, `${finalLabel} \u00b7 ${fmtBytes(totalBytes)}`, false);
}

function failFileRow(refs, message) {
    removeCancelBtn(refs);
    refs.row.classList.remove("bm-file-row--active"); // B3: terminal cards unpin
    // Whatever the terminal state (cancelled, incomplete, aborted), it's no
    // longer "waiting" \u2014 same reasoning as completeFileRow above.
    refs.row.classList.remove("bm-file-row--pending");
    // Terminal messages are sentences and are exactly the text a user must be able
    // to read; the numeric mode would cut them on a phone. Short labels ("Cancelled")
    // are unaffected — the class only changes overflow behaviour.
    setFileMeta(refs, message, true);
}

// The digest belongs to one file, so it lives on that file's card instead of as a
// centred 64-character system line — which was the loudest thing in the log and
// sat detached from the transfer it described. Shown truncated (the two ends are
// what you actually compare across two screens), click to expand, button to copy.
// `verdict` is "match" / "mismatch" once both ends' digests are in (T_FILE_END and
// T_FILE_DONE now carry them, so the app compares instead of leaving it to a human
// eyeball) or null while unknown / when the peer sent no digest at all — null keeps
// today's plain copy-button row.
function attachChecksum(refs, hex, verdict) {
    if (!refs || !refs.row) return;
    const short = `${hex.slice(0, 8)}…${hex.slice(-8)}`;
    // Sender's card gets this widget twice: once at "Sent" (verdict unknown), again
    // when T_FILE_DONE brings the receiver's digest back. One row, one verdict —
    // drop the earlier one instead of stacking a second hash line under it.
    const old = refs.row.querySelector(".bm-file-verify");
    if (old) old.remove();

    const wrap = document.createElement("div");
    wrap.className = "bm-file-verify";

    const value = document.createElement("button");
    value.type = "button";
    value.className = "bm-file-hash";
    value.textContent = `SHA-256 ${short}`;
    value.title = "Show the full digest";
    value.addEventListener("click", () => {
        const full = wrap.classList.toggle("bm-file-verify--full");
        value.textContent = full ? `SHA-256 ${hex}` : `SHA-256 ${short}`;
        value.title = full ? "Shorten" : "Show the full digest";
    });
    wrap.appendChild(value);

    if (verdict === "match" || verdict === "mismatch") {
        // Both ends already hashed and compared automatically, so the copy button's
        // reason to exist (paste it somewhere, compare by eye) is gone — the verdict
        // badge takes its slot instead.
        const badge = document.createElement("span");
        badge.className = "bm-file-verify-badge";
        badge.innerHTML = DOUBLE_CHECK_ICON_SVG;
        const label = document.createElement("span");
        if (verdict === "match") {
            badge.classList.add("bm-file-verify-badge--ok");
            label.textContent = "Digests match";
        } else {
            // The one case an alarming word is earned — but no exclamation marks,
            // same calm register as the rest of the app.
            badge.classList.add("bm-file-verify-badge--err");
            label.textContent = "Digests differ — file may be corrupt";
        }
        badge.appendChild(label);
        wrap.appendChild(badge);
    } else if (navigator.clipboard && navigator.clipboard.writeText) {
        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "bm-file-hash-copy";
        copyBtn.setAttribute("aria-label", "Copy the SHA-256 digest");
        copyBtn.title = "Copy digest";
        copyBtn.innerHTML = COPY_ICON_SVG;
        let copyTimer = null;
        copyBtn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(hex);
            } catch (_) {
                return;
            }
            clearTimeout(copyTimer);
            copyBtn.innerHTML = CHECK_ICON_SVG;
            copyBtn.classList.add("bm-file-hash-copy--copied");
            copyTimer = setTimeout(() => {
                copyBtn.innerHTML = COPY_ICON_SVG;
                copyBtn.classList.remove("bm-file-hash-copy--copied");
            }, 2000);
        });
        wrap.appendChild(copyBtn);
    }
    refs.row.appendChild(wrap);
}

// ---- File transfer ----
const CHUNK_SIZE = 128 * 1024; // 128 KB → encrypted frame ~128 KB + 35 B (26.1: +1 type byte inside), safely under Chrome DC 256 KB max
const MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024; // 1 GB
const MAX_PREVIEW_SIZE = 10 * 1024 * 1024; // 10 MB — 23.3 inline image preview cap
// 23.3 — object URLs backing inline thumbnails (sender + receiver); revoked wholesale on session teardown
let previewUrls = [];

// T_FILE_END payload: tid(1 byte) || digestHex(64 bytes UTF-8), or just tid(1 byte)
// when no digest is available (older peer, or the local hash failed). Built in one
// place because the initial send and handleFileNack's post-repair resend must put
// the identical digest on the wire — a mismatch here would fail verification for a
// transfer that actually arrived intact.
function fileEndPayload(tid, digestHex) {
    if (!digestHex) return new Uint8Array([tid]);
    const b = new Uint8Array(1 + 64);
    b[0] = tid;
    b.set(textEnc.encode(digestHex), 1);
    return b;
}

// Sender-side
async function sendFile(file) {
    if (step !== "chat") return;
    // 16.9.6 single-transfer guard: a second send while one is active destroys
    // the receiver's single recvFile slot and risks cross-transfer corruption.
    if (sendActive) {
        $("file-status").textContent = "One file at a time — wait for the current send to finish.";
        return;
    }
    if (file.size > MAX_FILE_SIZE) {
        $("file-status").textContent =
            "That file is larger than the 1 GB limit.";
        return;
    }
    $("file-status").textContent = "";
    sendActive = true;
    $("btn-file-pick").disabled = true;
    sendTransferId = (sendTransferId + 1) & 0xff;
    const tid = sendTransferId;

    // Header: tid(1) || size(8 BE) || name_len(2 BE) || name_utf8
    const nameBytes = textEnc.encode(file.name);
    const hdr = new Uint8Array(1 + 8 + 2 + nameBytes.length);
    hdr[0] = tid;
    const hv = new DataView(hdr.buffer);
    hv.setBigUint64(1, BigInt(file.size), false);
    hv.setUint16(9, nameBytes.length, false);
    hdr.set(nameBytes, 11);
    sendCancelled = false;
    sendCancelMsg = "";
    if (!await sendCtrlFrame(T_FILE_HDR, hdr)) {
        $("file-status").textContent = "Connection lost — file not sent. Try again.";
        endSendGuard();
        return;
    }
    pendingDelivery = null; // a new transfer supersedes the previous confirmation
    clearPendingDeliveryTimer(); // no watchdog may outlive the confirmation it was watching
    const refs = appendFileRow(file.name, file.size, "out", () => {
        if (sendCancelled) return;
        sendCancelled = true;
        sendCancelMsg = "Cancelled";
        sendPayload(T_FILE_CANCEL, new Uint8Array([0x00])); // tell peer to discard its partial
        drainAckWaiters(); // wake a parked window wait so the loop can observe the flag
        drainDcWaiters();  // likewise a loop parked on a DC reconnect (16.9.1)
    });
    currentSendRefs = refs;
    // 23.3 — inline thumbnail from the picked File; display-only, must never affect the transfer.
    try {
        const mime = imageMimeFor(file.name) || (file.type && file.type.startsWith("image/") ? file.type : null);
        if (mime && file.size <= MAX_PREVIEW_SIZE) {
            const previewUrl = URL.createObjectURL(file);
            previewUrls.push(previewUrl);
            const thumb = document.createElement("img");
            thumb.className = "bm-file-thumb";
            thumb.alt = "";
            thumb.src = previewUrl;
            refs.row.appendChild(thumb);
        }
    } catch (_) {}
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    let sentBytes = 0;
    // Sliding 1-second window: array of [timestamp, bytes] samples
    let speedSamples = [];
    // 21.2 — streaming checksum: each chunk hashed once as it's read, no
    // second full-file buffer/read needed at the end.
    const hasher = new Sha256Stream();

    for (let i = 0; i < totalChunks; i++) {
        if (sendCancelled) break;
        // 16.9.1: DC dropped mid-transfer — park until the rebuild settles
        // (reopened → resume via DC; gave up → chunks route via WS below).
        if (dcReconnecting) {
            // The bar would otherwise sit frozen at the last byte and read as a
            // dead transfer — tell the user it's recovering so they don't cancel.
            updateFileRow(refs, Math.max(0, sentBytes - dcBufferedTotal()), file.size,
                          RECONNECT_LABEL, 0);
            await waitDcSettled();
            if (sendCancelled) break;
        }
        const offset = i * CHUNK_SIZE;
        const slice = file.slice(offset, Math.min(file.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        hasher.update(buf); // 21.2 — hash in-flight, index order, once per chunk
        const payload = new Uint8Array(1 + 4 + buf.length);
        payload[0] = tid;
        new DataView(payload.buffer).setUint32(1, i, false);
        payload.set(buf, 5);
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
                console.warn(`[iris] send aborted at chunk ${i}`); failFileRow(refs, "Send failed \u2014 the connection was lost. Try again.");
                currentSendRefs = null;
                endSendGuard();
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
        endSendGuard();
        return;
    }
    lastSentFile = file; // held so handleFileNack can re-read slices on retransmit request
    lastSentTid = tid;
    resentBytes = 0; // fresh transfer, fresh retransmit budget
    // 21.2's streamed digest is finalized here — before END goes out, not after —
    // so it can ride inside the END frame itself. Every chunk was already hashed in
    // the loop above (this only runs once the loop is done and sendCancelled is
    // false), so finalizing early changes nothing about the result, only when it's
    // read out.
    let cs = "";
    try { cs = hasher.finalize_hex(); } catch (_) {}
    lastSentDigestHex = cs; // read back by handleFileDone's comparison and handleFileNack's END resend
    // Not awaited: a dead WS would park the retry for its full window and hold
    // the row on "Sending" with every chunk already gone. The receiver's 21.4
    // watchdog backstops an END that never lands.
    sendCtrlFrame(T_FILE_END, fileEndPayload(tid, cs)).catch(() => {});
    endSendGuard(); // re-enable on "Sent" — NACK rounds for this transfer stay valid via lastSentTid
    removeCancelBtn(refs);
    updateFileRow(refs, file.size, file.size, "Sent", 0);
    refs.row.classList.add("bm-file-row--pending"); // bar goes inert grey — not done yet
    pendingDelivery = { refs, size: file.size, tid }; // green "Delivered" only on T_FILE_DONE naming this tid
    armPendingDeliveryTimer(); // say so if that confirmation never comes
    // Verdict is unknown until T_FILE_DONE brings the receiver's digest back —
    // handleFileDone re-attaches this same card's widget once it does.
    if (cs) attachChecksum(refs, cs, null);
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
let recvFile = null; // { tid, name, size, totalChunks, nackAttempts, parts: Uint8Array[], received: number, refs }
// Sender-side: held after sendFile completes so handleFileNack can re-read slices
let lastSentFile = null;
let lastSentTid = -1; // transfer-ID of lastSentFile — NACKs for any other ID are stale and ignored
let lastSentDigestHex = ""; // this transfer's SHA-256, set once at "Sent" — compared against T_FILE_DONE's digest
// Cumulative bytes re-sent for lastSentTid across every NACK round. A NACK is a
// peer-controlled request to spend OUR uplink and nothing bounded how many could be
// made: lastSentFile stays live for the rest of the session (only a peer cancel or
// the next send clears it), so a hostile receiver can keep asking long after the card
// reads "Delivered" — and on a direct DC path the server's relay budget, which is what
// caps the WS lane, cannot see a byte of it. Honest repair converges well inside one
// file's worth; 4x leaves room for a genuinely lossy MAX_NACK_ROUNDS repair.
let resentBytes = 0;
const RESEND_BUDGET_FACTOR = 4;
// Everything a transfer leaves behind belongs to the session that ran it. A
// session end (peer gone, vanish) drops it all, so nothing a later peer sends —
// a NACK, a DONE, a stray chunk — can find a file, a confirmation slot or a
// partial assembly to act on. Called from endChatSession and _doVanish.
function forgetTransferState() {
    // A send loop still parked on its last ACK wakes up (drainAckWaiters) and must
    // take its cancel exit, not its "Sent" exit — that exit would hold the file
    // again. sendFile resets the flag when the next transfer starts.
    sendCancelled = true;
    sendCancelMsg = "Session ended";
    lastSentFile = null;
    lastSentTid = -1;
    lastSentDigestHex = "";
    resentBytes = 0;
    pendingDelivery = null;
    recvFile = null;
    earlyChunks = [];
    earlyEndPt = null;
}
// 16.9.6 single-transfer guard + per-transfer ID (1 byte, wraps mod 256).
// The ID stamps HDR/CHK/END/NACK so stray in-flight frames from a finished or
// superseded transfer can never land inside the next file's parts.
let sendActive = false;
let sendTransferId = 0;

function endSendGuard() {
    sendActive = false;
    $("btn-file-pick").disabled = false;
}
// Sender-side: { refs, size } after T_FILE_END — handleFileDone flips it to "Delivered"
let pendingDelivery = null;
// Mirror of the 21.4 receiver watchdog above, for the sender's own blind spot:
// T_FILE_DONE (the receiver's assembly confirmation) can be lost same as END —
// same relay, same paths. Without this the card just sits on "Sent · waiting
// for confirmation" forever, indistinguishable from a UI that stopped updating.
// The receiver's END-grace ceiling. Declared here rather than inline in endGraceMs()
// because the sender's confirmation budget below is derived from it — the whole bug
// this replaces was two constants that governed the same window and had never been
// reconciled (10 s was written before the grace gained its 8 s ceiling).
const END_GRACE_MAX_MS = 8_000;
// What the receiver can legitimately spend after the sender's last byte, before it can
// even begin to answer: up to END_GRACE_MAX_MS waiting for late chunks, then Blob
// assembly + SHA-256 over the whole file, then the trip back. Real-device testing
// measured that window at 14.2 s, 18.3 s and 11.8 s on 124–319 MB files — every one
// past a flat 10 s deadline, so the app accused three healthy transfers of possibly
// not arriving. Derive it instead of guessing.
//
// HASH_FLOOR_BPS is deliberately a FLOOR, not the measured rate: real-device runs hashed
// at ~220–265 MB/s on a laptop, and a budget phone must not be called a liar for being
// four times slower. Ceiling stays at the server's own silence timeout (45 s) — past
// that a genuinely absent peer is reported by the transport, which knows, rather than
// guessed at by this timer, which does not.
// No explicit floor: END_GRACE_MAX_MS + PENDING_DELIVERY_RTT_MS is 13 s by
// construction, already above the 10 s this replaces, so a `Math.max` floor would be
// a constant that can never bind.
const PENDING_DELIVERY_MAX_MS = 45_000;
const PENDING_DELIVERY_RTT_MS = 5_000;    // relayed round trip + Blob assembly
const HASH_FLOOR_BPS = 50 * 1024 * 1024;

function pendingDeliveryMs(size) {
    const hashMs = ((size > 0 ? size : 0) / HASH_FLOOR_BPS) * 1000;
    return Math.min(PENDING_DELIVERY_MAX_MS, Math.ceil(END_GRACE_MAX_MS + hashMs + PENDING_DELIVERY_RTT_MS));
}
let pendingDeliveryTimer = null;
// Timestamp, not a boolean: a repair round exits through five different returns
// (cancel, supersede, dead socket, step change, tid mismatch) and a flag would leak
// on any of them, permanently muting the timer below. A stamp needs no cleanup — it
// simply goes stale, and the accusation returns on its own. Written by
// handleFileNack at every point where it is demonstrably doing work.
let repairActiveAt = 0;
// Covers the gap between the last retransmitted chunk and the round's END, which
// includes dcDrainBuffers() and can legitimately be seconds on a full buffer.
const REPAIR_QUIET_MS = 5_000;

function clearPendingDeliveryTimer() {
    if (pendingDeliveryTimer !== null) { clearTimeout(pendingDeliveryTimer); pendingDeliveryTimer = null; }
}

function armPendingDeliveryTimer() {
    clearPendingDeliveryTimer();
    const p = pendingDelivery;
    if (!p) return;
    pendingDeliveryTimer = setTimeout(() => {
        pendingDeliveryTimer = null;
        if (pendingDelivery !== p) return; // delivered, cancelled or superseded already
        // A repair round in progress is the transfer WORKING, not the peer going
        // silent — and it is the reason this message fired on three healthy
        // transfers in real-device testing (4.2 s, 8.3 s and 1.7 s on screen,
        // every one of them on a run that finished over a relay). Re-arm instead of
        // accusing; if the repair really has died the stamp goes stale and the next
        // expiry says so.
        if (Date.now() - repairActiveAt < REPAIR_QUIET_MS) { armPendingDeliveryTimer(); return; }
        // Calm, not alarmed: nothing here says the transfer failed, because we
        // don't know that — only that the one signal which would say "arrived"
        // hasn't shown up. "It may not have arrived" was dropped from the tooltip:
        // it asserted more than this timer can know, and it lived in
        // a `title` that a phone can never show — no hover on touch — so the only
        // part a mobile user ever saw was the alarming half with none of the
        // context. Say exactly what is true, in the visible line.
        // Was a direct textContent write, which skipped setFileMeta and therefore
        // could never receive the wrapping class — measured CLIPPED on the phone in
        // real-device testing.
        setFileMeta(p.refs, "Sent \u00b7 peer has not confirmed yet", true);
        p.refs.meta.title =
            "Every byte was sent. Your peer has not confirmed assembling the file yet.";
    }, pendingDeliveryMs(p.size));
}
// 16.8.2 cancel state
let sendCancelled = false;   // observed by the sendFile/handleFileNack loops; reset at sendFile start
let sendCancelMsg = "";      // terminal row label ("Cancelled" vs "Cancelled by peer")
let currentSendRefs = null;  // outgoing row refs so a peer-initiated cancel can mark the card
let dropStrayChunks = false; // after an incoming cancel, late in-flight chunks are expected — drop them silently
// 16.9.2: with striped paths, chunks (or even T_FILE_END) on a fast path can
// arrive before the header that went on a slower one — stash and replay on HDR.
let earlyChunks = [];
let earlyEndPt = null; // full payload of an END that beat its header across paths (16.9.2) — kept
                        // whole, not just its tid, so a digest riding inside it survives the replay
const EARLY_CHUNK_CAP = 256; // 32 MB of path skew — far beyond any real race
// 21.4 — END-frame loss watchdog. T_FILE_END rides a DC path like any file
// frame (sendPayload return ignored at the send site), and a stalled path
// closed with END still queued in its buffer (pickDcPath / dcBackpressure /
// dcDrainBuffers all close-on-sight) loses it silently. The NACK repair round
// only ever ran from handleFileEnd, so a lost END left the receiver sitting
// incomplete forever and the sender on "Sent" — the only other END source is
// handleFileNack's tail, which needs a NACK, which needed the END: circular.
// This timer notices "transfer open + no accepted chunk for RECV_STALL_MS"
// and walks into handleFileEnd on its own initiative; the 16.9.5 END grace,
// NACK rounds and the nackAttempts cap then behave exactly as if the END had
// arrived, so a dead sender still terminates at honest "Incomplete".
// The legitimate zero-chunk gaps this must clear are the 1 s END grace, the 5 s
// DC_STALL_MS, the DC rebuild park (DC_RECONNECT_TRIES × DC_RECONNECT_OPEN_MS + 2 s
// ≈ 8 s) and the reconnect window RESUME_GRACE_MS, plus WS chunk-retry slack.
// RESUME_GRACE_MS is 60 s — equal to this timer, not less. That is deliberate and
// accepted: a peer returning right at the edge of its window can race the watchdog
// and trigger one repair round. A round that moves bytes does not spend the
// no-progress budget, so this costs bandwidth, not integrity. Any change to
// RESUME_GRACE_MS has to be re-reasoned against this constant.
const RECV_STALL_MS = 60_000;
let recvStallTimer = null;

function clearRecvStall() {
    if (recvStallTimer !== null) { clearTimeout(recvStallTimer); recvStallTimer = null; }
}

function armRecvStall() {
    clearRecvStall();
    const f = recvFile;
    if (!f) return;
    recvStallTimer = setTimeout(() => {
        recvStallTimer = null;
        if (step !== "chat" || recvFile !== f) return; // torn down or superseded (16.9.6)
        handleFileEnd(new Uint8Array([f.tid])); // body is await-free — recvFile is settled on return
        if (recvFile === f) armRecvStall(); // grace/NACK round still open — keep watching
    }, RECV_STALL_MS);
}

function handleFileHdr(pt) {
    if (pt.length < 11) { appendSystemMsg("(bad file header)"); return; }
    const tid = pt[0];
    const v = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    const size = Number(v.getBigUint64(1, false));
    const nameLen = v.getUint16(9, false);
    if (pt.length !== 11 + nameLen) { appendSystemMsg("(bad file header)"); return; }
    // 21.1: never trust the sender's declared size — a modified client could
    // announce anything and OOM this tab during assembly. Mirror of the
    // sender-side pick check; honest senders can't hit this branch.
    if (size > MAX_FILE_SIZE) {
        appendSystemMsg(`(oversized file rejected · declared ${fmtBytes(size)})`);
        dropStrayChunks = true; // its chunks are already in flight — ignore them
        sendPayload(T_FILE_CANCEL, new Uint8Array([0x01]));
        return;
    }
    const name = textDec.decode(pt.slice(11, 11 + nameLen));
    // 16.9.6: single recvFile slot — a new header supersedes the old transfer
    // EXPLICITLY (it used to be silently destroyed) and the tid checks below
    // keep its still-in-flight chunks out of the new file's parts.
    if (recvFile) {
        const old = recvFile;
        recvFile = null;
        failFileRow(old.refs, `Incomplete · superseded · ${fmtBytes(old.received)} / ${fmtBytes(old.size)}`);
    }
    dropStrayChunks = false; // new transfer — stray-chunk reporting is meaningful again
    const refs = appendFileRow(name, size, "in", () => {
        if (!recvFile || recvFile.refs !== refs) return; // stale button (already terminal)
        const f = recvFile;
        recvFile = null;
        clearRecvStall(); // 21.4
        dropStrayChunks = true; // chunks already in flight will keep landing — expected
        earlyChunks = [];
        earlyEndPt = null;
        sendPayload(T_FILE_CANCEL, new Uint8Array([0x01])); // tell sender to stop
        failFileRow(f.refs, "Cancelled");
    });
    recvFile = { tid, name, size, totalChunks: Math.max(1, Math.ceil(size / CHUNK_SIZE)), nackAttempts: 0, nackRounds: 0, receivedAtLastNack: -1, repairNoticed: false, parts: [], received: 0, refs, speedSamples: [] };
    // Replay anything that beat this header across a faster path (16.9.2);
    // the tid check in handleFileChunk drops stashed frames from other transfers.
    const replay = earlyChunks;
    earlyChunks = [];
    for (const c of replay) handleFileChunk(c);
    const earlyPt = earlyEndPt;
    earlyEndPt = null;
    // Replay the real payload (not a reconstructed bare tid) so a digest that beat
    // the header across a faster path still reaches the comparison below.
    if (earlyPt && earlyPt.length >= 1 && earlyPt[0] === tid) handleFileEnd(earlyPt);
    armRecvStall(); // 21.4 — no-ops if the early END above already finished the transfer
}

function handleFileChunk(pt) {
    if (pt.length < 5) return;
    if (!recvFile) {
        if (!dropStrayChunks && earlyChunks.length < EARLY_CHUNK_CAP) {
            earlyChunks.push(pt); // header still in flight on another path (16.9.2)
        }
        return;
    }
    if (pt[0] !== recvFile.tid) {
        // Stray chunk from a finished/superseded transfer (16.9.6) — before the
        // tid stamp these landed inside the current file's parts (silent
        // corruption, caught only by the SHA-256 lines). Still ACK it so the
        // sender's WS flow-control window can't leak a slot (same rationale as
        // the duplicate branch below).
        sendPayload(T_FILE_ACK, new Uint8Array(0));
        return;
    }
    const idx = new DataView(pt.buffer, pt.byteOffset, pt.byteLength).getUint32(1, false);
    // 21.1: out-of-range index from a hostile sender — sparse parts[] would
    // balloon to idx entries on assembly. No ACK: honest senders never send one.
    if (idx >= recvFile.totalChunks) return;
    // A chunk can never exceed CHUNK_SIZE — the sender slices to exactly that, so
    // an honest peer cannot reach this. Unchecked, the length was the hole in 21.1's
    // ceiling: that check gates the DECLARED size, and parts[] would then hold up to
    // ~1.56x it (MAX_FRAME payload / CHUNK_SIZE) for a size that was accepted as
    // fitting in RAM. It also let `received` — a plain byte sum — reach `size` with
    // parts still missing, which walks straight past every `received !== size` gate
    // in handleFileEnd: the file assembles from a holed parts[], reports "Received",
    // and the digest is silently skipped (the hasher throws into its own catch and
    // leaves cs empty, so no verdict is ever shown on either end).
    if (pt.length - 5 > CHUNK_SIZE) return; // no ACK: same rationale as the index check
    const data = pt.slice(5);
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
    armRecvStall(); // 21.4 — every accepted chunk resets the END-loss watchdog
}

async function handleFileEnd(pt) {
    const tid = pt && pt.length >= 1 ? pt[0] : -1;
    // Sender's digest, when this END carries one: tid(1) || digestHex(64 UTF-8).
    // A bare 1-byte payload (stall watchdog's synthetic re-entry, an older peer, or
    // the sender's own hashing having failed) means "no digest" — fall back to
    // plain display rather than guess or throw.
    const senderDigestHex = pt && pt.length === 1 + 64 ? textDec.decode(pt.slice(1)) : null;
    if (!recvFile) {
        if (!dropStrayChunks) earlyEndPt = pt; // END beat the header across paths (16.9.2)
        return;
    }
    if (tid !== recvFile.tid) return; // stray END from a superseded transfer (16.9.6)
    const f = recvFile;
    // Consecutive NACK rounds that moved zero bytes before the transfer is declared
// dead, and a hard ceiling on total rounds so a pathological trickle still ends.
const MAX_NACK_NO_PROGRESS = 3;
const MAX_NACK_ROUNDS = 32;

// END rides the fast WS lane while bulk chunks are still draining on the DC lane,
// so "missing at END" scales with how much is still in flight — a constant is the
// wrong shape. Real-device case: a 124-chunk repair round re-requested 70 chunks that
// were simply still arriving, because 1 s drains ~8 MB and ~15.5 MB was outstanding.
// Floor 1 s keeps the old behaviour for a small tail (and matches SCTP's own
// rationale for a 1 s RTO floor: never mistake late for lost). Ceiling 8 s stays
// clear of RECV_STALL_MS (60 s) and the DC rebuild park. No recent samples means
// nothing is arriving — repair immediately rather than stalling on a dead path.
function endGraceMs(f) {
    const now = Date.now();
    const bps = f.speedSamples.filter(s => now - s[0] <= 1000).reduce((a, s) => a + s[1], 0);
    if (bps <= 0) return 1000;
    const outstanding = Math.max(0, f.size - f.received);
    return Math.max(1000, Math.min(END_GRACE_MAX_MS, Math.ceil((outstanding / bps) * 1500)));
}

// 16.9.5 unordered DC: a tiny END routinely overtakes large fragmented
    // chunks still in flight on its path (unordered = deliver-on-assembly),
    // so "missing at END" usually means "still arriving". One short grace
    // before each NACK round keeps transfers from always ending in a spurious
    // repair; genuine loss (closed path) just repairs 1 s later. The flag
    // stays set through the grace re-entry (clearing it there would loop the
    // grace forever) and re-arms after each NACK so every round gets one.
    if (f.received !== f.size && step === "chat" && !f.endGraceSpent) {
        f.endGraceSpent = true;
        setTimeout(() => { if (recvFile === f) handleFileEnd(pt); }, endGraceMs(f));
        return;
    }
    if (f.received !== f.size && f.nackAttempts < MAX_NACK_NO_PROGRESS && f.nackRounds < MAX_NACK_ROUNDS && step === "chat") {
        const missing = [];
        for (let i = 0; i < f.totalChunks; i++) {
            if (f.parts[i] === undefined) missing.push(i);
        }
        if (missing.length > 0) {
            // Only a round that achieved nothing counts against the cap. While bytes
            // are still landing the peer is alive and the repair is working, and
            // discarding a live transfer on a raw round count throws away data that
            // is in flight. A zero-progress round still counts, so a dead path
            // terminates at honest "Incomplete"; nackRounds bounds a pathological
            // trickle, and RECV_STALL_MS backstops total silence.
            if (f.received > f.receivedAtLastNack) f.nackAttempts = 0;
            else f.nackAttempts++;
            f.receivedAtLastNack = f.received;
            f.nackRounds++;
            f.endGraceSpent = false; // fresh grace for the retransmit round's END
            // Keep recvFile alive \u2014 retransmitted chunks + new T_FILE_END will arrive
            const nackBuf = new Uint8Array(1 + missing.length * 4);
            nackBuf[0] = f.tid;
            const dv = new DataView(nackBuf.buffer);
            missing.forEach((chunkIdx, i) => dv.setUint32(1 + i * 4, chunkIdx, false));
            sendPayload(T_FILE_NACK, nackBuf);
            // "requesting N missing chunks" is wire jargon and read as data
            // corruption to testers at the exact moment the transfer was being
            // saved. Wording stays literally true: the receiver is verifying it
            // holds every piece before assembly, and re-requesting what it lacks.
            // Deliberately NOT phrased as a dropped connection \u2014 reordered frames
            // and a stalled path closed with chunks queued reach here with the
            // link perfectly healthy \u2014 and NOT as an encryption check, which is
            // not what runs here (the SHA-256 line is the real integrity proof).
            // One line per transfer, not per round: repeated identical lines read
            // as repeated failures rather than one ongoing verification.
            if (!f.repairNoticed) {
                f.repairNoticed = true;
                f.repairMsgEl = appendSystemMsg("(verifying transfer\u2026)");
            }
            updateFileRow(f.refs, f.received, f.size, "Verifying", 0);
            return;
        }
    }
    recvFile = null;
    clearRecvStall(); // 21.4 \u2014 transfer terminal either way below
    if (f.received !== f.size) {
        settleSystemMsg(f.repairMsgEl, "(some pieces never arrived)");
        failFileRow(f.refs, `Incomplete \u00b7 ${fmtBytes(f.received)} / ${fmtBytes(f.size)}`);
        return;
    }
    // Every piece is here: the verification that line announced is finished, so
    // it stops saying it is still running.
    settleSystemMsg(f.repairMsgEl, "(missing pieces recovered)");
    // 23.3 — image previews get a typed Blob so the <img> renders; non-image
    // behavior (untyped Blob, revoke-on-download-click) stays byte-identical.
    const previewMime = imageMimeFor(f.name);
    const isPreviewable = previewMime && f.size <= MAX_PREVIEW_SIZE;
    const blob = isPreviewable ? new Blob(f.parts, { type: previewMime }) : new Blob(f.parts);
    const url = URL.createObjectURL(blob);

    completeFileRow(f.refs, f.size, "Received");

    // 21.2 — streamed digest over the already-assembled parts, in index order,
    // instead of re-reading the assembled blob whole. Computed here, before DONE
    // goes out (it used to run after), so DONE can carry it back to the sender —
    // no extra round trip needed for either side to verify.
    let cs = "";
    try {
        const hasher = new Sha256Stream();
        for (let i = 0; i < f.totalChunks; i++) hasher.update(f.parts[i]);
        cs = hasher.finalize_hex();
    } catch (_) {}
    // DONE payload: tid(1) || digestHex(64 UTF-8), the digest left off when our own
    // hashing failed. The tid names the transfer being confirmed, so the sender
    // credits exactly this file and nothing that came after it.
    const csBytes = cs ? textEnc.encode(cs) : null;
    const done = new Uint8Array(1 + (csBytes && csBytes.length === 64 ? 64 : 0));
    done[0] = f.tid;
    if (done.length === 65) done.set(csBytes, 1);
    sendPayload(T_FILE_DONE, done); // assembly verified — confirm delivery to the sender

    if (isPreviewable) {
        previewUrls.push(url);
        const thumb = document.createElement("img");
        thumb.className = "bm-file-thumb";
        thumb.alt = "";
        thumb.src = url;
        f.refs.row.appendChild(thumb);
    }

    // Download moves into the card's action slot; the meta line keeps showing
    // "Received \u00b7 <size>" that completeFileRow just wrote.
    const link = document.createElement("a");
    link.href = url;
    link.download = safeDownloadName(f.name); // 25.2: peer-chosen, sanitised for the OS
    link.className = "bm-file-btn";
    link.title = `Download ${displayName(f.name)}`;
    link.setAttribute("aria-label", `Download ${displayName(f.name)}`);
    link.innerHTML = DOWNLOAD_ICON_SVG;
    // Non-image only: the same URL feeds the thumbnail above, so it must outlive the click.
    if (!isPreviewable) {
        link.addEventListener("click", () => setTimeout(() => URL.revokeObjectURL(url), 100));
    }
    if (f.refs.action) f.refs.action.appendChild(link);

    // No digest of our own (hashing failed above) — nothing to show or compare;
    // same silent skip as the old try/catch had when finalize_hex() threw.
    if (cs) {
        // No digest from the sender either — older peer, or its finalize_hex()
        // failed — same "peer sent nothing" fallback as the sender side: show the
        // plain hash, no verdict, exactly today's display.
        const verdict = senderDigestHex ? (cs === senderDigestHex ? "match" : "mismatch") : null;
        attachChecksum(f.refs, cs, verdict);
    }
}

// Receiver confirmed assembly (T_FILE_DONE) — the only point where the sender
// may claim more than "Sent". A stray DONE with nothing pending is dropped.
function handleFileDone(pt) {
    if (!pendingDelivery) return;
    // DONE payload: tid(1) || digestHex(64 UTF-8), the digest absent when the
    // receiver has none. A confirmation is credited only to the transfer it names:
    // any other tid, or any other length, is not a confirmation of this one and is
    // dropped. Older peers send the digest alone (64) or nothing (0); both are still
    // read, with no tid to check.
    let peerDigestHex = null;
    if (pt.length === 1 || pt.length === 65) {
        if (pt[0] !== pendingDelivery.tid) return;
        if (pt.length === 65) peerDigestHex = textDec.decode(pt.subarray(1));
    } else if (pt.length === 64) {
        peerDigestHex = textDec.decode(pt);
    } else if (pt.length !== 0) {
        return;
    }
    clearPendingDeliveryTimer(); // confirmation arrived — the watchdog's job is done
    // The receiver confirmed assembly, so any repair round this transfer ran is
    // over. Close its notice out or the log keeps claiming pieces are still in
    // flight for the rest of the session.
    settleSystemMsg(pendingDelivery.repairMsgEl, "(missing pieces re-sent)");
    completeFileRow(pendingDelivery.refs, pendingDelivery.size, "Delivered");
    // lastSentDigestHex belongs to this same transfer: it's set once, right before
    // this transfer's END goes out, and pendingDelivery — gating this whole
    // function — is cleared the instant a new send starts (before that send's own
    // digest overwrites it), so the two can never point at different transfers here.
    if (lastSentDigestHex) {
        const verdict = peerDigestHex ? (peerDigestHex === lastSentDigestHex ? "match" : "mismatch") : null;
        attachChecksum(pendingDelivery.refs, lastSentDigestHex, verdict);
    }
    pendingDelivery = null;
}

// 16.8.2 — peer cancelled a transfer. payload[0]: 0x00 = peer aborted the file
// it was sending to us (discard our partial); 0x01 = peer rejects the file we
// are sending (stop the loop; forget the file so NACK rounds can't resurrect it).
function handleFileCancel(pt) {
    if (pt.length !== 1) return;
    if (pt[0] === 0x00) {
        earlyChunks = [];
        earlyEndPt = null;
        if (!recvFile) { dropStrayChunks = true; return; }
        const f = recvFile;
        recvFile = null;
        clearRecvStall(); // 21.4
        dropStrayChunks = true;
        failFileRow(f.refs, "Cancelled by peer");
        return;
    }
    if (pt[0] === 0x01) {
        sendCancelled = true;
        sendCancelMsg = "Cancelled by peer";
        lastSentFile = null; // a NACK round after this must not resurrect the transfer
        lastSentTid = -1;
        if (currentSendRefs) failFileRow(currentSendRefs, "Cancelled by peer");
        else if (pendingDelivery) failFileRow(pendingDelivery.refs, "Cancelled by peer"); // rejected during a post-"Sent" NACK round
        // The peer stopped the transfer, so a repair round can no longer be
        // running. Left as-is it would sit in the log re-sending forever.
        if (pendingDelivery) settleSystemMsg(pendingDelivery.repairMsgEl, "(re-send stopped)");
        clearPendingDeliveryTimer(); // peer spoke — no need to guess anymore
        pendingDelivery = null;
        drainAckWaiters(); // unpark the send loop so it can observe the flag
        drainDcWaiters();  // likewise a loop parked on a DC reconnect (16.9.1)
    }
}

// Sender-side: receiver asked us to re-send specific chunks.
// Reads only the requested slices from the original File object and re-sends them,
// then fires T_FILE_END so the receiver can try assembly again.
async function handleFileNack(pt) {
    if (!lastSentFile || pt.length < 5 || (pt.length - 1) % 4 !== 0) return;
    const tid = pt[0];
    if (tid !== lastSentTid) return; // NACK for a superseded transfer (16.9.6) — its file is gone, fail clean
    const count = (pt.length - 1) / 4;
    const dv = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
    // A NACK may only ask for chunks this file HAS, and only once each. Neither was
    // checked, and the frame cap is the only thing that bounded `count`: MAX_FRAME
    // leaves room for ~51k indices, so a receiver repeating one valid index made this
    // loop re-read and re-send the same 128 KB slice ~51k times — ~6.4 GB of our
    // uplink bought with a single 200 KB request, repeatable, and concurrent, since
    // handleChatPayload dispatches this without awaiting it. An honest receiver sends
    // each missing index exactly once (see handleFileEnd's builder), so range-checking
    // and de-duplicating costs a real repair round nothing.
    const totalChunks = Math.max(1, Math.ceil(lastSentFile.size / CHUNK_SIZE));
    const wanted = [];
    const seen = new Set();
    for (let j = 0; j < count; j++) {
        const idx = dv.getUint32(1 + j * 4, false);
        if (idx >= totalChunks || seen.has(idx)) continue;
        seen.add(idx);
        wanted.push(idx);
    }
    // Previously this function had no UI call anywhere in it: the receiver
    // printed "(verifying transfer…)" while the sender's row sat frozen on
    // "Sent · waiting for confirmation" for the whole repair, and the sender was
    // then accused by the pending-delivery timer for a transfer it was actively
    // fixing. Both ends must show that the same thing is happening. One line per
    // transfer, not per round — repeated identical lines read as repeated failures
    // rather than one ongoing repair (same reasoning as the receiver's line).
    repairActiveAt = Date.now();
    if (pendingDelivery) {
        if (!pendingDelivery.repairNoticed) {
            pendingDelivery.repairNoticed = true;
            pendingDelivery.repairMsgEl = appendSystemMsg("(re-sending missing pieces\u2026)");
        }
        // wrapping=true: this is a sentence, not the numeric progress line, so it
        // must not be ellipsised away on a phone.
        setFileMeta(pendingDelivery.refs, "Sent \u00b7 re-sending missing pieces", true);
    }
    for (let j = 0; j < wanted.length; j++) {
        if (dcReconnecting) await waitDcSettled(); // 16.9.1: same park as the main loop
        // lastSentFile re-checked each pass: a T_FILE_CANCEL (0x01) arriving
        // mid-round nulls it and sets sendCancelled (16.8.2)
        if (step !== "chat" || sendCancelled || !lastSentFile || tid !== lastSentTid) return;
        const idx = wanted[j];
        const offset = idx * CHUNK_SIZE;
        const slice = lastSentFile.slice(offset, Math.min(lastSentFile.size, offset + CHUNK_SIZE));
        const buf = new Uint8Array(await slice.arrayBuffer());
        // De-duplication bounds ONE round to a file's worth; this bounds the session,
        // where the frames themselves are unlimited. Stop the round rather than
        // announcing it: a system line here would hand a flooding peer the chat log.
        if (resentBytes + buf.length > lastSentFile.size * RESEND_BUDGET_FACTOR) return;
        resentBytes += buf.length;
        const payload = new Uint8Array(1 + 4 + buf.length);
        payload[0] = tid;
        new DataView(payload.buffer).setUint32(1, idx, false);
        payload.set(buf, 5);
        if (!sendPayload(T_FILE_CHK, payload)) return;
        repairActiveAt = Date.now(); // a chunk just left: demonstrable progress
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
    // The main send loop drains before its END; this round must too. dcBackpressure
    // above only caps the queue, so without this the loop finishes with megabytes
    // still buffered and END — which rides the fast WS lane — overtakes them. The
    // receiver then re-requests chunks that were merely in flight, burning a repair
    // round on a healthy transfer (seen in testing: 124-chunk round re-requested 70).
    await dcDrainBuffers(null, 0, 0);
    repairActiveAt = Date.now(); // the drain itself is work, and can take seconds
    if (sendCancelled) return;
    // Same digest as the first END for this transfer (tid still matches lastSentTid,
    // checked above) — the receiver's verification must not depend on which round
    // of chunks actually landed.
    sendCtrlFrame(T_FILE_END, fileEndPayload(tid, lastSentDigestHex)).catch(() => {});
    repairActiveAt = Date.now();
    // The receiver grants itself a fresh grace window for each round's END
    // (`endGraceSpent = false`, 2712), so the sender's wait for T_FILE_DONE must
    // restart with it — otherwise the round's own duration is charged against a
    // budget sized for a single round trip. Row goes back to the honest interim
    // sentence; if the peer really is gone, the timer says so from here.
    if (pendingDelivery) {
        setFileMeta(pendingDelivery.refs, "Sent \u00b7 waiting for confirmation", true);
        armPendingDeliveryTimer();
    }
}


// 23.6b: deep-link join from a scanned QR (#<code>). MUST stay at the very end
// of the module: the join path reads `let` bindings declared throughout the
// file (e.g. wsChunksInFlight), and running it mid-module hits the temporal
// dead zone — the error is then swallowed by the event loop and the join
// silently never happens (seen as an Android bug in real-device testing). Strip the hash via replaceState
// first — fragments never reach the server, but the code shouldn't linger in
// the address bar or browser history either.
const hashMatch = location.hash.match(/^#(\d{9})$/);
if (/^#\d{4,12}$/.test(location.hash)) {
    // Strip any code-shaped fragment, including a stale pre-Phase-24 6-digit
    // link — that one must not linger in the bar, but it must not join either.
    history.replaceState(null, "", location.pathname + location.search);
}
if (hashMatch) {
    $("receiver-error").textContent = "";
    clearRateBanners();
    show("receiver");
    $("code-input").value = hashMatch[1];
    joinAsReceiver();
    // 26.2: AFTER the join (which resets the flag) — this user did not pick the
    // peer, so signalling is held until the first gesture; see grantRtcConsent.
    withholdRtcUntilGesture();
}
