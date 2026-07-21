use axum::{
    extract::{
        connect_info::ConnectInfo,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::{mapref::entry::Entry, DashMap};
use http::{header::{HeaderName, HeaderValue, CONTENT_TYPE}, HeaderMap};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

const CODE_TTL_SECS: u64 = 60;
const MAX_SESSION_SECS: u64 = 60 * 60;
const MAX_WS_FRAME: usize = 200 * 1024; // 128KB chunk + 33B crypto overhead + margin

// 15.2 + 15.11 Per-IP WS connect rate limit.
// Cooldown softened to 30s (was 300s): per-IP is volumetric-abuse defense only.
// Real brute-force defense is now per-code attempt cap (MAX_CODE_ATTEMPTS below).
const WS_MAX_ATTEMPTS_PER_WINDOW: usize = 5;
const WS_WINDOW_SECS: u64 = 60;
const WS_COOLDOWN_SECS: u64 = 30;

// 15.11 Per-code brute-force defense. Once a live code has been connected to
// this many times, it is invalidated regardless of source IP — stops botnet
// enumeration dead. Normal flow uses 2 attempts (sender + receiver); 5 leaves
// room for legit reconnects (page refresh, tab close + retry) without burning
// a code on the first slip-up.
const MAX_CODE_ATTEMPTS: u32 = 5;

// Per-IP hard cap on simultaneously open WS connections. Prevents a botnet from
// accumulating idle sessions up to the 5-min session timeout. Normal flow uses
// 2 connections (sender + receiver, different IPs). 8 is generous for reconnects.
const MAX_CONCURRENT_PER_IP: u32 = 8;

// Mobile browsers freeze/kill the WS when the tab is backgrounded (file picker,
// photo gallery). Instead of evicting the surviving peer the instant one side's
// TCP dies, hold the room for this long so the original peer can reopen the WS
// and resume. Encrypted frames are validated peer-side by the AEAD key — an
// imposter who snipes the slot cannot produce valid ciphertext.
const RESUME_GRACE_SECS: u64 = 30;

// 15.3 Tiered-ban escalation.
const BAN_COOLDOWN_WINDOW_SECS: u64 = 3600; // 1 h — 3 cooldowns here → 30-min ban
const BAN_COOLDOWN_THRESHOLD: usize = 3;
const BAN_MEDIUM_SECS: u64 = 1800; // 30 min
const BAN_MEDIUM_WINDOW_SECS: u64 = 86_400; // 24 h — 3 × 30-min bans here → 24-h ban
const BAN_MEDIUM_THRESHOLD: usize = 3;
const BAN_HARD_SECS: u64 = 86_400; // 24 h

// 15.10 App-defined close codes (RFC 6455 4xxx range). Reason strings can be
// stripped by intermediaries (notably Cloudflare Tunnel), but numeric close
// codes always survive — so the client dispatches UI on these, not the reason.
// The reason is still set when useful (e.g. remaining seconds for cooldown),
// but treated as best-effort by the client.
const CLOSE_RATE_COOLDOWN: u16   = 4001;
const CLOSE_BAN_30M: u16         = 4002;
const CLOSE_BAN_24H: u16         = 4003;
const CLOSE_CODE_FORMAT: u16     = 4004;
const CLOSE_CODE_MISSING: u16    = 4005;
const CLOSE_SESSION_TIMEOUT: u16 = 4006;
const CLOSE_PEER_LEFT: u16       = 4007;

// 15.10b Cloudflare Tunnel drops WS close frames entirely — the client sees code 1006
// ("abnormal closure") instead of our 4001..4007. Workaround: send a plain Text frame
// ("BEEM-CLOSE:<code>:<reason>") the client caches and uses as a fallback when ev.code
// is 1006. cloudflared also drops trailing frames if the server closes the TCP stream
// too fast — so we sleep briefly between send and close, then drain reads until the
// client's close-ack or a short timeout (keeps the socket alive long enough for
// cloudflared to actually flush the text frame).
async fn send_close_signal(socket: &mut WebSocket, code: u16, reason: &str) {
    let _ = socket
        .send(Message::Text(format!("BEEM-CLOSE:{}:{}", code, reason)))
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.to_string().into(),
        })))
        .await;
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(Ok(_)) = socket.recv().await {}
    })
    .await;
}

// 23.4 Client sends this plaintext marker (mirrors 15.10b's BEEM-CLOSE
// workaround — plain Text frames survive Cloudflare Tunnel where native WS
// close semantics are unreliable) just before it closes on panic-vanish, so
// the server can skip the resume-grace and tear the room down immediately
// instead of leaving the peer to wait out RESUME_GRACE_SECS.
fn is_leave_marker(t: &str) -> bool {
    t == "BEEM-LEAVE"
}

#[derive(Clone)]
struct Room {
    tx: broadcast::Sender<(u64, Message)>,
    expires_at: Instant,
    // 15.11 Per-code attempt counter; incremented on every successful room
    // lookup in `pair()`. Once it reaches MAX_CODE_ATTEMPTS the room is removed.
    attempts: u32,
}

type Rooms = Arc<DashMap<String, Room>>;

#[derive(Default)]
struct RateLimitState {
    attempts: VecDeque<Instant>,
    cooldown_until: Option<Instant>,
    // 15.3 Escalation tracking.
    cooldown_history: VecDeque<Instant>, // 15.2 trips, purged to BAN_COOLDOWN_WINDOW
    ban_until: Option<Instant>,
    ban_history: VecDeque<Instant>,      // 30-min-ban trips, purged to BAN_MEDIUM_WINDOW
}

#[derive(Debug, PartialEq)]
enum BlockReason {
    Cooldown { remaining: Duration },
    Ban30m { remaining: Duration, newly_engaged: bool },
    Ban24h { remaining: Duration, newly_engaged: bool },
}

type RateLimits = Arc<DashMap<IpAddr, RateLimitState>>;
type Concurrent = Arc<DashMap<IpAddr, u32>>;

#[derive(Clone)]
struct AppState {
    rooms: Rooms,
    rate_limits: RateLimits,
    concurrent: Concurrent,
    session_secs: u64,
    audit: bool,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct WsParams {
    code: String,
}

#[derive(Serialize)]
struct NewCodeResponse {
    code: String,
}

fn is_valid_code(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())
}

// 17.3 branding: accent color is spliced verbatim into a CSS custom property,
// so it's restricted to characters that can't close the declaration/rule and
// start injecting new ones (no `;`, `{`, `}`).
fn is_safe_css_color(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'#' | b'(' | b')' | b',' | b'.' | b'%' | b' ' | b'-')
        })
}

// 17.3 branding: wordmark text is spliced into a JS string literal in
// branding.js — escape backslash/quote so it can't break out of the literal.
fn escape_js_string(s: &str) -> String {
    s.chars().take(64).flat_map(|c| match c {
        '\\' => vec!['\\', '\\'],
        '"' => vec!['\\', '"'],
        '\n' | '\r' => vec![' '],
        c => vec![c],
    }).collect()
}

#[tokio::main]
async fn main() {
    let host = std::env::var("BEEM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("BEEM_PORT").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(8080);
    let session_secs: u64 = std::env::var("BEEM_SESSION_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(MAX_SESSION_SECS);

    // 17.4 Optional stderr audit log for compliance. Off by default; no content, no
    // codes, no raw IPs — fingerprint only (see ip_fingerprint, reused from 15.3).
    let audit = std::env::var("BEEM_AUDIT").ok().as_deref() == Some("1");

    // 17.3 optional self-host branding: unset by default, no visible change.
    let branding_css = std::env::var("BEEM_ACCENT_COLOR").ok()
        .filter(|c| is_safe_css_color(c))
        .map(|c| format!(":root {{ --accent: {c} !important; --accent-press: {c} !important; }}\n"))
        .unwrap_or_default();
    let branding_js = std::env::var("BEEM_WORDMARK_TEXT").ok()
        .filter(|t| !t.is_empty())
        .map(|t| format!(
            "document.querySelectorAll('.bm-wordmark-text').forEach(function(el){{ el.textContent = \"{}\"; }});\n",
            escape_js_string(&t)
        ))
        .unwrap_or_default();

    let rooms: Rooms = Arc::new(DashMap::new());
    let rate_limits: RateLimits = Arc::new(DashMap::new());
    let concurrent: Concurrent = Arc::new(DashMap::new());
    spawn_sweeper(rooms.clone(), rate_limits.clone(), concurrent.clone());
    let state = AppState { rooms, rate_limits, concurrent, session_secs, audit };

    // 12.1 Rate limit: /new ~ 10/min per IP (burst 10, replenish 1 per 6s).
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(6)
            .burst_size(10)
            .finish()
            .expect("governor config"),
    );

    // 12.6 Security headers.
    let sec_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self' 'wasm-unsafe-eval' blob:; \
                 style-src 'self'; \
                 connect-src 'self' ws: wss:; \
                 img-src 'self' data:; \
                 object-src 'none'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ));

    let app = Router::new()
        .route(
            "/new",
            post(new_code).layer(GovernorLayer { config: governor_conf }),
        )
        .route("/ws", get(ws_handler))
        .route("/branding.css", get(move || {
            let body = branding_css.clone();
            async move { ([(CONTENT_TYPE, "text/css; charset=utf-8")], body) }
        }))
        .route("/branding.js", get(move || {
            let body = branding_js.clone();
            async move { ([(CONTENT_TYPE, "text/javascript; charset=utf-8")], body) }
        }))
        .with_state(state)
        .fallback_service(ServeDir::new("../client"))
        .layer(sec_headers);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .expect("bind");
    let actual_port = listener.local_addr().expect("local_addr").port();
    println!("Iris listening on http://{}:{}", host, actual_port);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}

// One sweep pass over all three maps. Free function so tests can drive it
// with a controlled `now` instead of waiting on the interval.
fn sweep_maps(rooms: &Rooms, rate_limits: &RateLimits, concurrent: &Concurrent, now: Instant) {
    let window = Duration::from_secs(WS_WINDOW_SECS);
    let ban_medium_window = Duration::from_secs(BAN_MEDIUM_WINDOW_SECS);
    rooms.retain(|_, r| r.expires_at > now);
    // 15.2 + 15.3 GC: keep entries with any active state or recent history.
    rate_limits.retain(|_, s| {
        let has_recent = s.attempts.back().map_or(false, |t| now.duration_since(*t) < window);
        let in_cooldown = s.cooldown_until.map_or(false, |u| u > now);
        let in_ban = s.ban_until.map_or(false, |u| u > now);
        let recent_ban_history = s.ban_history.back().map_or(false, |t| now.duration_since(*t) < ban_medium_window);
        has_recent || in_cooldown || in_ban || recent_ban_history
    });
    // Concurrent-connection counters: entries decremented to 0 are dead —
    // without this they accumulate one entry per unique IP forever.
    concurrent.retain(|_, n| *n > 0);
}

fn spawn_sweeper(rooms: Rooms, rate_limits: RateLimits, concurrent: Concurrent) {
    tokio::spawn(async move {
        loop {
            let r = rooms.clone();
            let rl = rate_limits.clone();
            let c = concurrent.clone();
            let result = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                loop {
                    interval.tick().await;
                    sweep_maps(&r, &rl, &c, Instant::now());
                }
            }).await;
            if let Err(e) = result {
                eprintln!("[sweeper] task died: {e} — restarting");
            }
        }
    });
}

fn generate_code<R: Rng>(rng: &mut R) -> String {
    format!("{:06}", rng.gen_range(0..1_000_000))
}

async fn new_code(State(state): State<AppState>) -> Result<Json<NewCodeResponse>, StatusCode> {
    let rooms = &state.rooms;
    let mut rng = rand::thread_rng();
    for _ in 0..1000 {
        let code = generate_code(&mut rng);
        if let Entry::Vacant(v) = rooms.entry(code.clone()) {
            let (tx, _) = broadcast::channel(2048);
            v.insert(Room {
                tx,
                expires_at: Instant::now() + Duration::from_secs(CODE_TTL_SECS),
                attempts: 0,
            });
            return Ok(Json(NewCodeResponse { code }));
        }
    }
    // 100k codes — hitting 1000 retries requires >99% occupancy; return 503 instead of looping forever
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

// 15.2 + 15.3 Check per-IP WS connect; record this attempt; escalate ban tiers if warranted.
// Every /ws connection attempt is counted, valid or invalid code — this is intentional so
// an attacker can't probe the code space faster than the honest-case pair rate allows.
//
// Escalation ladder:
//   - 5 attempts / 60 s    → 5-min cooldown (15.2)
//   - 3 cooldowns / 1 h    → 30-min ban
//   - 3 × 30-min bans / 24 h → 24-h ban (stderr-logged)
// Permanent ban is intentionally manual-only (admin config, not this function) since shared
// NATs mean an automatic permanent ban could lock out thousands of legitimate users.
//
// Pure over (state, now) so it can be unit-tested with synthetic timestamps — see phase 15.6a.
fn check_and_record(state: &mut RateLimitState, now: Instant) -> Result<(), BlockReason> {
    // 1. Active hard/medium ban takes precedence.
    if let Some(until) = state.ban_until {
        if until > now {
            let remaining = until - now;
            // Distinguish 30-min vs 24-h by remaining magnitude (anything > BAN_MEDIUM_SECS is 24-h).
            return Err(if remaining.as_secs() > BAN_MEDIUM_SECS {
                BlockReason::Ban24h { remaining, newly_engaged: false }
            } else {
                BlockReason::Ban30m { remaining, newly_engaged: false }
            });
        }
        state.ban_until = None;
        // After a ban ends, also clear short-window state so the user starts clean.
        state.cooldown_until = None;
        state.attempts.clear();
    }

    // 2. Active short cooldown.
    if let Some(until) = state.cooldown_until {
        if until > now {
            return Err(BlockReason::Cooldown { remaining: until - now });
        }
        state.cooldown_until = None;
        state.attempts.clear();
    }

    // 3. Prune sliding windows.
    prune_older_than(&mut state.attempts, now, Duration::from_secs(WS_WINDOW_SECS));
    prune_older_than(&mut state.cooldown_history, now, Duration::from_secs(BAN_COOLDOWN_WINDOW_SECS));
    prune_older_than(&mut state.ban_history, now, Duration::from_secs(BAN_MEDIUM_WINDOW_SECS));

    // 4. Rate-limit trip?
    if state.attempts.len() >= WS_MAX_ATTEMPTS_PER_WINDOW {
        // Engage 5-min cooldown and record this trip.
        state.cooldown_until = Some(now + Duration::from_secs(WS_COOLDOWN_SECS));
        state.cooldown_history.push_back(now);
        prune_older_than(&mut state.cooldown_history, now, Duration::from_secs(BAN_COOLDOWN_WINDOW_SECS));

        // 3 cooldowns / 1 h → engage 30-min ban.
        if state.cooldown_history.len() >= BAN_COOLDOWN_THRESHOLD {
            state.ban_until = Some(now + Duration::from_secs(BAN_MEDIUM_SECS));
            state.ban_history.push_back(now);
            prune_older_than(&mut state.ban_history, now, Duration::from_secs(BAN_MEDIUM_WINDOW_SECS));

            // 3 × 30-min bans / 24 h → escalate to 24-h ban.
            if state.ban_history.len() >= BAN_MEDIUM_THRESHOLD {
                state.ban_until = Some(now + Duration::from_secs(BAN_HARD_SECS));
                return Err(BlockReason::Ban24h {
                    remaining: Duration::from_secs(BAN_HARD_SECS),
                    newly_engaged: true,
                });
            }
            return Err(BlockReason::Ban30m {
                remaining: Duration::from_secs(BAN_MEDIUM_SECS),
                newly_engaged: true,
            });
        }

        return Err(BlockReason::Cooldown { remaining: Duration::from_secs(WS_COOLDOWN_SECS) });
    }

    // 5. Allowed: record this attempt.
    state.attempts.push_back(now);
    Ok(())
}

fn prune_older_than(buf: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = buf.front().copied() {
        if now.duration_since(front) > window {
            buf.pop_front();
        } else {
            break;
        }
    }
}

// Stable-ish non-PII hash of an IP for log correlation. Not a security boundary — just enough
// to correlate repeat offenders across log lines without persisting the raw IP.
fn ip_fingerprint(ip: IpAddr) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    ip.hash(&mut h);
    h.finish()
}

fn check_ws_rate_limit(rate_limits: &RateLimits, ip: IpAddr, now: Instant) -> Result<(), BlockReason> {
    let mut entry = rate_limits.entry(ip).or_default();
    check_and_record(entry.value_mut(), now)
}

// 15.10 Resolve the real client IP.
//
// Deployment model: the server binds to 127.0.0.1:8080 and is fronted by a local
// process (cloudflared, nginx, Caddy) that terminates TLS and forwards. In that
// setup every TCP peer address is 127.0.0.1 — so using ConnectInfo directly would
// collapse every real user into one shared rate-limit bucket (first person to trip
// cooldown locks out everyone globally).
//
// Fix: when the TCP peer is loopback, trust `CF-Connecting-IP` (Cloudflare) or
// `X-Forwarded-For` (generic reverse proxy) as the real client IP. When the peer
// is NOT loopback, we're exposed directly to the public internet — never trust
// headers from those connections, since a malicious client could spoof them to
// frame a target IP into the rate-limit bucket.
//
// Priority: CF-Connecting-IP > X-Forwarded-For (leftmost) > peer. Any parse error
// falls through to the next source. Only invoked from the loopback branch, so
// spoofing requires local access to 127.0.0.1:8080 (trusted-operator threat model).
fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    if let Some(v) = headers.get("cf-connecting-ip") {
        if let Ok(s) = v.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-forwarded-for") {
        if let Ok(s) = v.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // 15.10 Resolve the real client IP (may be behind a local reverse proxy).
    let ip = client_ip(&headers, addr.ip());

    // 15.2 + 15.3 Per-IP rate/ban check before anything else.
    if let Err(block) = check_ws_rate_limit(&state.rate_limits, ip, Instant::now()) {
        let (code, reason) = match &block {
            BlockReason::Cooldown { remaining } => (
                CLOSE_RATE_COOLDOWN,
                format!("{}", remaining.as_secs().max(1)),
            ),
            BlockReason::Ban30m { remaining, newly_engaged: _ } => (
                CLOSE_BAN_30M,
                format!("{}", remaining.as_secs().max(1)),
            ),
            BlockReason::Ban24h { remaining, newly_engaged } => {
                if *newly_engaged {
                    // 15.3 One-line stderr log on 24-h escalation only. No PII: IP fingerprint
                    // (DefaultHasher-based, not cryptographic) + counters.
                    let fp = ip_fingerprint(ip);
                    let (cd_n, ban_n) = {
                        let e = state.rate_limits.get(&ip);
                        e.map(|s| (s.cooldown_history.len(), s.ban_history.len())).unwrap_or((0, 0))
                    };
                    eprintln!(
                        "[15.3] ip_fp={:x} escalated to 24h ban (cooldowns_1h={}, medium_bans_24h={})",
                        fp, cd_n, ban_n
                    );
                }
                (CLOSE_BAN_24H, format!("{}", remaining.as_secs().max(1)))
            }
        };
        return ws.on_upgrade(move |mut socket| async move {
            send_close_signal(&mut socket, code, &reason).await;
        });
    }

    // 12.4 Strict code format; refuse up front.
    if !is_valid_code(&params.code) {
        return ws.on_upgrade(|mut socket| async move {
            send_close_signal(&mut socket, CLOSE_CODE_FORMAT, "").await;
        });
    }

    // Per-IP concurrent connection cap — hard ceiling regardless of rate limit state.
    {
        let mut count = state.concurrent.entry(ip).or_insert(0);
        if *count >= MAX_CONCURRENT_PER_IP {
            return ws.on_upgrade(move |mut socket| async move {
                send_close_signal(&mut socket, CLOSE_RATE_COOLDOWN, "too many connections").await;
            });
        }
        *count += 1;
    }

    let concurrent = state.concurrent.clone();
    ws.max_message_size(MAX_WS_FRAME)
        .max_frame_size(MAX_WS_FRAME)
        .on_upgrade(move |socket| async move {
            pair(socket, params.code, state.rooms, state.session_secs, ip, state.audit).await;
            // Decrement active connection count for this IP.
            if let Some(mut c) = concurrent.get_mut(&ip) {
                *c = c.saturating_sub(1);
            }
        })
}

// 17.4 msg_payload_len: bytes charged toward the audit log's in/out counters.
// Control frames (Ping/Pong/Close) carry no application payload — 0.
fn msg_payload_len(msg: &Message) -> usize {
    match msg {
        Message::Text(t) => t.len(),
        Message::Binary(b) => b.len(),
        _ => 0,
    }
}

async fn pair(mut socket: WebSocket, code: String, rooms: Rooms, session_secs: u64, ip: IpAddr, audit: bool) {
    // 15.11 Per-code brute-force guard: increment attempts on lookup. If this
    // attempt would put us at or past MAX_CODE_ATTEMPTS, burn the room entirely.
    // Also capture attempt count before increment — only the first 2 connections
    // (the legitimate pair) are allowed to broadcast close signals to each other.
    let (tx, is_pair_member) = {
        let mut entry = match rooms.get_mut(&code) {
            Some(r) if r.expires_at > Instant::now() => r,
            _ => {
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            }
        };
        let attempt_before = entry.attempts;
        entry.attempts += 1;
        if entry.attempts >= MAX_CODE_ATTEMPTS {
            drop(entry); // release the write lock before the DashMap remove.
            rooms.remove(&code);
            send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
            return;
        }
        // attempts 0→1 = sender, 1→2 = receiver: legitimate pair members.
        // attempts 2+ are either observers (attackers) OR reconnects after a mobile
        // background event. Distinguish by channel state: if exactly one subscriber
        // exists when we join, that's the surviving pair member holding the slot
        // open — we're filling it, so we count as a pair member too (for grace
        // purposes on our own exit). An attacker arrives when receiver_count is 0
        // or ≥ 2 and stays marked as observer.
        let tx = entry.tx.clone();
        let is_pair_member = attempt_before < 2 || tx.receiver_count() == 1;
        (tx, is_pair_member)
    };
    let mut rx = tx.subscribe();
    let my_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    // 12.3 Max session duration.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(session_secs);

    // 15.9 If the peer broadcasts a Close through our room channel, forward it to our own
    // socket and mark so the post-loop step doesn't rebroadcast another Close back at them.
    let mut peer_closed_us = false;

    // 23.4 Set when we ourselves sent BEEM-LEAVE (deliberate panic-vanish exit).
    // Skips the post-loop resume-grace entirely — we already evicted the peer
    // and removed the room, there is nothing left to hold open.
    let mut deliberate_leave = false;

    // 17.4 Audit counters (bytes only — no content, no IPs, no codes).
    let started = Instant::now();
    let mut bytes_in: u64 = 0;
    let mut bytes_out: u64 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                send_close_signal(&mut socket, CLOSE_SESSION_TIMEOUT, "").await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(ref t))) if is_leave_marker(t) => {
                        // 23.4 Deliberate vanish: broadcast peer-left immediately (the
                        // peer's own rx arm turns this Close into send_close_signal with
                        // CLOSE_PEER_LEFT), skip resume-grace, drop the room now. Do not
                        // forward this marker to the peer as data.
                        let _ = tx.send((my_id, Message::Close(Some(CloseFrame {
                            code: CLOSE_PEER_LEFT,
                            reason: "".into(),
                        }))));
                        deliberate_leave = true;
                        rooms.remove(&code);
                        break;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(msg)) => {
                        bytes_in += msg_payload_len(&msg) as u64;
                        let _ = tx.send((my_id, msg));
                    }
                    Some(Err(_)) => break,
                }
            }
            broadcast_msg = rx.recv() => {
                match broadcast_msg {
                    Ok((from, msg)) => {
                        if from != my_id {
                            if matches!(msg, Message::Close(_)) {
                                // 15.10b Only CLOSE_PEER_LEFT ever reaches us via broadcast
                                // (see post-loop tx.send below). Send the text marker first.
                                send_close_signal(&mut socket, CLOSE_PEER_LEFT, "").await;
                                peer_closed_us = true;
                                break;
                            }
                            bytes_out += msg_payload_len(&msg) as u64;
                            if socket.send(msg).await.is_err() { break; }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[relay] broadcast lagged {} frames — receiver too slow, closing WS", n);
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // 17.4 One stderr line per session-end when BEEM_AUDIT=1. No content, no
    // codes, no raw IPs — fingerprint only (reuses 15.3's ip_fingerprint).
    if audit {
        eprintln!(
            "[audit] session={:x} bytes_in={} bytes_out={} duration_s={}",
            ip_fingerprint(ip), bytes_in, bytes_out, started.elapsed().as_secs()
        );
    }

    // 15.9 On our exit (tab close, error, deadline), tell the other peer once.
    // Only legitimate pair members (first 2 connections) may evict each other.
    // Third-party observers closing must not terminate the active session.
    //
    // Mobile resume: delay the peer-left broadcast by RESUME_GRACE_SECS so the
    // original peer can reopen the WS (e.g. returning from the photo picker).
    // If someone resubscribes to `tx` in that window, receiver_count climbs
    // above 1 (survivor + reconnect) and we skip the close. Bump room expiry
    // so the sweeper doesn't GC the room mid-grace.
    if !peer_closed_us && !deliberate_leave && is_pair_member {
        if let Some(mut r) = rooms.get_mut(&code) {
            r.expires_at = Instant::now() + Duration::from_secs(RESUME_GRACE_SECS + 10);
        }
        let tx_grace = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(RESUME_GRACE_SECS)).await;
            if tx_grace.receiver_count() <= 1 {
                let _ = tx_grace.send((my_id, Message::Close(Some(CloseFrame {
                    code: CLOSE_PEER_LEFT,
                    reason: "".into(),
                }))));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // TEST-S-001 — Code format validation
    #[test]
    fn test_is_valid_code() {
        assert!(is_valid_code("000000"));
        assert!(is_valid_code("123456"));
        assert!(is_valid_code("999999"));
        assert!(!is_valid_code("12345"));
        assert!(!is_valid_code("1234567"));
        assert!(!is_valid_code("abcdef"));
        assert!(!is_valid_code(""));
        assert!(!is_valid_code("12345a"));
        assert!(!is_valid_code("-12345"));
        assert!(!is_valid_code(" 12345"));
        assert!(!is_valid_code("１２３４５６")); // full-width digits (each is 3 UTF-8 bytes, len != 6)
    }

    // TEST-S-002 — Code generator format + bias check
    #[test]
    fn test_generate_code_format() {
        let mut rng = rand::thread_rng();
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let code = generate_code(&mut rng);
            assert!(is_valid_code(&code), "generate_code produced invalid code: {:?}", code);
            *counts.entry(code).or_insert(0) += 1;
        }
        for (code, count) in &counts {
            assert!(*count <= 100, "code {} appeared {} times (>1% of 10k)", code, count);
        }
    }

    // TEST-S-003 — Rate-limit: cooldown trip
    // The check fires when attempts.len() >= WS_MAX_ATTEMPTS_PER_WINDOW (5),
    // so 5 calls are allowed and the 6th triggers the cooldown.
    #[test]
    fn test_cooldown_trip() {
        let mut state = RateLimitState::default();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(check_and_record(&mut state, now).is_ok());
        }
        match check_and_record(&mut state, now) {
            Err(BlockReason::Cooldown { remaining }) => {
                assert!(
                    remaining.as_secs().abs_diff(WS_COOLDOWN_SECS) <= 1,
                    "remaining={:?}", remaining
                );
            }
            other => panic!("expected Cooldown, got {:?}", other),
        }
    }

    // TEST-S-004 — Rate-limit: 30-min ban escalation
    #[test]
    fn test_ban30m_escalation() {
        let mut state = RateLimitState::default();
        let now = Instant::now();
        // Two prior cooldown trips within the 1-hour window.
        state.cooldown_history.push_back(now - Duration::from_secs(3500));
        state.cooldown_history.push_back(now - Duration::from_secs(1800));
        // Pre-load exactly 5 attempts within the window so the next call trips the 3rd cooldown.
        for _ in 0..5 {
            state.attempts.push_back(now - Duration::from_secs(10));
        }
        match check_and_record(&mut state, now) {
            Err(BlockReason::Ban30m { newly_engaged, .. }) => assert!(newly_engaged),
            other => panic!("expected Ban30m(newly_engaged), got {:?}", other),
        }
    }

    // TEST-S-005 — Rate-limit: 24-h ban escalation
    #[test]
    fn test_ban24h_escalation() {
        let mut state = RateLimitState::default();
        let now = Instant::now();
        // Two prior 30-min ban trips within the 24-hour window.
        state.ban_history.push_back(now - Duration::from_secs(86_000));
        state.ban_history.push_back(now - Duration::from_secs(43_200));
        // Two prior cooldown trips within the 1-hour window.
        state.cooldown_history.push_back(now - Duration::from_secs(3500));
        state.cooldown_history.push_back(now - Duration::from_secs(1800));
        // 5 attempts → next call triggers 3rd cooldown → 3rd medium ban → 24h ban.
        for _ in 0..5 {
            state.attempts.push_back(now - Duration::from_secs(10));
        }
        match check_and_record(&mut state, now) {
            Err(BlockReason::Ban24h { newly_engaged, .. }) => assert!(newly_engaged),
            other => panic!("expected Ban24h(newly_engaged), got {:?}", other),
        }
    }

    // TEST-S-006 — Cooldown expiry clears short-window state
    #[test]
    fn test_cooldown_expiry_clears_state() {
        let mut state = RateLimitState::default();
        let now = Instant::now();
        state.cooldown_until = Some(now - Duration::from_secs(1)); // already expired
        // Stale attempts outside the 60-second window — pruned during check.
        for _ in 0..4 {
            state.attempts.push_back(now - Duration::from_secs(90));
        }
        assert!(
            check_and_record(&mut state, now).is_ok(),
            "expired cooldown should not block"
        );
        assert_eq!(state.attempts.len(), 1, "only the new attempt should remain");
    }

    // TEST-S-007 — client_ip header resolution
    #[test]
    fn test_client_ip_resolution() {
        let public: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let loopback: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Public peer — headers never trusted.
        assert_eq!(client_ip(&HeaderMap::new(), public), public);
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(client_ip(&h, public), public);

        // Loopback peer, no headers → loopback.
        assert_eq!(client_ip(&HeaderMap::new(), loopback), loopback);

        // Loopback + CF header → CF IP.
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(client_ip(&h, loopback), "1.2.3.4".parse::<IpAddr>().unwrap());

        // Loopback + XFF only → leftmost XFF entry.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "5.6.7.8, 9.9.9.9".parse().unwrap());
        assert_eq!(client_ip(&h, loopback), "5.6.7.8".parse::<IpAddr>().unwrap());

        // Loopback + garbage CF + valid XFF → falls through to XFF.
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        h.insert("x-forwarded-for", "5.6.7.8".parse().unwrap());
        assert_eq!(client_ip(&h, loopback), "5.6.7.8".parse::<IpAddr>().unwrap());

        // Loopback + both garbage → loopback.
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        h.insert("x-forwarded-for", "also-garbage".parse().unwrap());
        assert_eq!(client_ip(&h, loopback), loopback);
    }

    // TEST-S-008 — Room lifecycle: per-code attempt burn
    #[test]
    fn test_per_code_attempt_burn() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let code = "55555".to_string();
        let (tx, _) = broadcast::channel(256);
        rooms.insert(
            code.clone(),
            Room { tx, expires_at: Instant::now() + Duration::from_secs(60), attempts: 0 },
        );

        // First MAX_CODE_ATTEMPTS-1 increments — room survives.
        for _ in 1..MAX_CODE_ATTEMPTS {
            rooms.get_mut(&code).unwrap().attempts += 1;
        }
        assert!(rooms.get(&code).is_some(), "room should still exist before 5th attempt");

        // 5th increment triggers burn.
        {
            let mut entry = rooms.get_mut(&code).unwrap();
            entry.attempts += 1;
            if entry.attempts >= MAX_CODE_ATTEMPTS {
                drop(entry);
                rooms.remove(&code);
            }
        }
        assert!(rooms.get(&code).is_none(), "room must be gone after 5th attempt");
    }

    // TEST-S-009 — Room TTL expiry (sweeper retention predicate)
    #[test]
    fn test_room_ttl_expiry() {
        let now = Instant::now();
        let (tx, _) = broadcast::channel::<(u64, Message)>(1);
        let expired = Room { tx: tx.clone(), expires_at: now - Duration::from_secs(1), attempts: 0 };
        let fresh   = Room { tx,             expires_at: now + Duration::from_secs(1), attempts: 0 };

        assert!(!(expired.expires_at > now), "expired room should be pruned");
        assert!(fresh.expires_at > now,      "fresh room should be kept");
    }

    // TEST-S-010 — ip_fingerprint is deterministic and not PII
    #[test]
    fn test_ip_fingerprint() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(ip_fingerprint(ip), ip_fingerprint(ip), "same IP → same fingerprint");

        let fps: std::collections::HashSet<u64> = (1u8..=100)
            .map(|i| ip_fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))))
            .collect();
        assert_eq!(fps.len(), 100, "100 distinct IPs must produce 100 distinct fingerprints");
    }

    // TEST-S-011 — WS routing isolation between codes (broadcast-channel level)
    #[test]
    fn test_broadcast_room_isolation() {
        let (tx_a, _) = broadcast::channel::<(u64, Message)>(256);
        let (tx_b, _) = broadcast::channel::<(u64, Message)>(256);
        let mut rx_a = tx_a.subscribe();
        let mut rx_b = tx_b.subscribe();

        tx_a.send((0, Message::Text("frame-for-a".to_string()))).unwrap();

        assert!(rx_a.try_recv().is_ok(),  "room-A subscriber must receive the frame");
        assert!(rx_b.try_recv().is_err(), "room-B subscriber must NOT receive room-A's frame");
    }

    // TEST-S-012 — Sweeper GCs zeroed concurrent-IP counters (regression test)
    // A counter decremented to 0 is a dead entry and must be removed; an active
    // connection (n ≥ 1) must survive the pass.
    #[test]
    fn test_sweeper_gc_concurrent_map() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let rate_limits: RateLimits = Arc::new(DashMap::new());
        let concurrent: Concurrent = Arc::new(DashMap::new());

        let dead_ip   = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let active_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        concurrent.insert(dead_ip, 0);
        concurrent.insert(active_ip, 2);

        sweep_maps(&rooms, &rate_limits, &concurrent, Instant::now());

        assert!(concurrent.get(&dead_ip).is_none(), "zeroed counter must be GC'd");
        assert_eq!(*concurrent.get(&active_ip).unwrap(), 2, "active counter must survive");
    }

    // TEST-S-013 — 17.4 audit byte-counting: payload length by message variant
    #[test]
    fn test_msg_payload_len() {
        assert_eq!(msg_payload_len(&Message::Text("hello".to_string())), 5);
        assert_eq!(msg_payload_len(&Message::Binary(vec![0u8; 7])), 7);
        assert_eq!(msg_payload_len(&Message::Ping(vec![1, 2, 3])), 0);
        assert_eq!(msg_payload_len(&Message::Pong(vec![1, 2, 3])), 0);
        assert_eq!(msg_payload_len(&Message::Close(None)), 0);
    }

    // TEST-S-014 — 23.4 BEEM-LEAVE marker recognition
    #[test]
    fn test_is_leave_marker() {
        assert!(is_leave_marker("BEEM-LEAVE"));
        assert!(!is_leave_marker("BEEM-CLOSE:4007:"));
        assert!(!is_leave_marker("beem-leave"));
        assert!(!is_leave_marker(""));
        assert!(!is_leave_marker("BEEM-LEAVEX"));
    }
}
