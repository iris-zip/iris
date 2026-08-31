// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Scar

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
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

const CODE_TTL_SECS: u64 = 60;
const MAX_SESSION_SECS: u64 = 60 * 60;

// The relay lane can carry a whole file, so a relayed session needs a ceiling of its
// own: without one the only bound is MAX_SESSION_SECS. The browser's file-size limit
// cannot serve here — it is a client-side check, and a ceiling has to hold for any
// client. Every byte is charged twice, once inbound from the sender and once outbound
// to the receiver, because that is what the relay actually moves.
//
// This is a resource bound, not a confidentiality control: payloads are sealed with an
// AEAD in the browser and this process holds no keys.
//
// 12 GiB per session — six maximum-size files, doubled for the two-way charge. Both
// peers are warned at 80 %.
const MAX_RELAY_BYTES: u64 = 6 * (1024 * 1024 * 1024) * 2;
const RELAY_WARN_PCT: u64 = 80;
// The counter lives in the Room, so a per-frame update would put a map write on the
// relay hot path. Charge in batches instead: one DashMap touch every few seconds at
// realistic relay speeds, and the ceiling is then honoured to within one batch
// (64 MiB of 12 GiB — 0.5 %).
const RELAY_FLUSH_BYTES: u64 = 64 * 1024 * 1024;
// No socket can own this id (NEXT_ID starts at 0 and increments), and the relay arm
// forwards a broadcast only when `from != my_id` — so a frame sent under this id
// reaches BOTH peers instead of everyone-except-the-sender. That is what makes one
// warning visible on both screens without touching either socket directly.
const BUDGET_BROADCAST_FROM: u64 = u64::MAX;

#[derive(PartialEq, Debug)]
enum RelayBudget {
    Ok,
    Warn,
    Exceeded,
}

// Pure, so it is unit-testable without a socket or a room — same shape and reasoning
// as is_pair_member / is_resume_join above. `limit == 0` disables the ceiling, which is
// the escape hatch for a self-hoster who is paying for their own bandwidth.
fn relay_budget_state(total: u64, limit: u64, warned: bool) -> RelayBudget {
    if limit == 0 {
        return RelayBudget::Ok;
    }
    if total >= limit {
        RelayBudget::Exceeded
    } else if !warned && total >= limit / 100 * RELAY_WARN_PCT {
        RelayBudget::Warn
    } else {
        RelayBudget::Ok
    }
}
const MAX_WS_FRAME: usize = 200 * 1024; // 128KB chunk + 33B crypto overhead + margin

// The room's broadcast ring is sized in MESSAGES, not bytes, and each slot can
// hold up to MAX_WS_FRAME. A slow-draining subscriber (one that keeps the socket alive
// with keepalives but stops accepting writes) pins every full slot in memory until it
// either drains or is caught by the Lagged check below — so the ring's capacity times
// MAX_WS_FRAME is the real per-room memory ceiling, not a message count. At the old
// capacity of 2048 that ceiling was ~400 MiB per room, ~1.6 GiB per address across the
// 4 rooms MAX_CONCURRENT_PER_IP allows — attacker-affordable and unbounded by anything
// else in the file. 256 slots caps a room at ~51 MiB (~205 MiB/address): the WS relay
// lane measured 4.3-4.7 MB/s on a real deployment, so this still
// buffers several seconds of a real, fully-drained bulk relay transfer's jitter — the
// legitimate case this must not break — while cutting the attacker's affordable pin by
// roughly 8x. Lagged subscribers are still closed exactly as before; this only tightens
// how much has to accumulate before that happens.
const ROOM_CHANNEL_CAPACITY: usize = 256;

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
// Cap on uncounted mobile-resume rejoins per room (see Room.resumes). 64 covers
// hours of aggressive picker/screen-lock cycling; an attacker spraying resumes
// still needs the live code within a grace window and is IP-rate-limited anyway.
const MAX_RESUME_JOINS: u32 = 64;

// A join is a mobile resume, not a pairing/attack attempt, iff the legitimate
// pair already formed (attempt_before >= 2) and at most one survivor holds the
// room open (receiver_count <= 1: exactly 1 = peer waiting out the grace
// banner, 0 = both sides backgrounded simultaneously — phone↔phone transfer).
// An attacker probing an ACTIVE session meets a full room (2 subscribers) and
// stays on the counted path.
fn is_resume_join(attempt_before: u32, receiver_count: usize) -> bool {
    attempt_before >= 2 && receiver_count <= 1
}

// The count heuristic above is a headcount, not proof: a stale, dead-but-
// not-closed subscriber can hold receiver_count down and let a tokenless
// stranger walk in as the resume. That is only safe while the room has not
// yet minted a token for both legitimate members — once it has, a bare code
// plus a favourable headcount must never be enough to gain membership and
// evict the real peer. Pure and named so the one predicate backs both the
// branch that decides how a join is counted AND the later grant of
// membership itself; those must never be allowed to disagree with each
// other, which is exactly how the original bug shape worked.
fn resume_admitted(both_slots_minted: bool, attempt_before: u32, receiver_count: usize) -> bool {
    !both_slots_minted && is_resume_join(attempt_before, receiver_count)
}

// A connection is a legitimate pair member iff it is one of the first two joins
// (attempt_before < 2 = sender/receiver) OR it is a mobile resume filling a slot with
// at most one survivor (receiver_count <= 1: 1 = peer holding the grace slot, 0 = both
// backgrounded at once, phone<->phone) in a room that has not yet minted a token for
// both members. Any other join (attempt_before >= 2 while both pair members are live,
// receiver_count >= 2, OR both slots already minted) is a third-party observer.
// Observers may READ the relayed (encrypted) frames but must never broadcast INTO the
// room: without this gate an observer that knows the code could send `BEEM-LEAVE` to
// tear the live session down, or relay plaintext UI markers (BEEM-GRACE/BEEM-BACK/
// BEEM-CLOSE) that the peers parse before the AEAD path — or, per the headcount-vs-token gap above, walk in as a
// full member on nothing but a headcount and evict the real peer. Membership is
// exactly `attempt_before < 2 || resume_admitted(..)`, so relay/eviction rights track
// the resume classifier — this is called out inline at the `pair()` call site rather
// than its own function, since a second independent evaluation of the same question
// is exactly how that headcount-vs-token bug happened in the first place.

// Constant-time byte comparison. A 128-bit token crossing a network isn't
// realistically timing-attackable, but this is a membership gate — writing it
// constant-time costs five lines and forecloses the question rather than
// leaving a "was this reviewed" gap for whoever reads it next.
fn ct_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// Does `presented` prove membership, and if so which slot? An absent or
// blank token can never match — a client that never received a token (or lost
// it) must fall through to the count-based rule, not be waved through on an
// empty string. An empty slot list (fresh/never-minted room) also never matches,
// so there is no way to "match" a token that was never issued.
//
// Returns the index rather than a bool because the caller needs to ask a narrower
// question than "is this a member": a departing connection must know whether
// **its own** slot was re-claimed, which a yes/no answer cannot express.
fn slot_index(slots: &[MemberSlot], presented: Option<&str>) -> Option<usize> {
    let p = presented?;
    if p.is_empty() || slots.is_empty() {
        return None;
    }
    slots.iter().position(|s| ct_eq(&s.token, p))
}

// Room lifetime. These two predicates were, until this was fixed, one rule
// written twice in two places that disagreed, and the disagreement was a
// long-standing reliability bug: `pair()` refused any join past `expires_at`,
// while the sweeper deliberately RETAINED such a
// room whenever a live pair was still using it. Retention is not joinability. A
// room was kept alive precisely so a peer could come back to it, and then the
// door was held shut.
//
// `expires_at` is only ever written at room creation (+CODE_TTL_SECS) and at a
// peer's grace exit (+RESUME_GRACE_SECS+10). A healthy session never refreshes
// it — so EVERY reconnect more than 60 s into a session was answered with
// CLOSE_CODE_MISSING. Observed in practice: rejoin at 126 s refused with 4005,
// the same peer accepted at 151 s only because a reap at 134 s happened to
// refresh the clock.
//
// CODE_TTL_SECS was doing two jobs at once. Its real one is bounding how long an
// UNCLAIMED code is guessable; killing live sessions was never the intent.
//
// The fix is deliberately STRICTER than simply making `pair()` match the sweeper.
// Past the TTL a room is **token-only**: the code alone stops being sufficient,
// and only a holder of the 128-bit membership token gets in. So the
// brute-force window narrows rather than widens — a guesser who lands on a live
// code after 60 s can no longer spend that room's MAX_CODE_ATTEMPTS budget.
//
// Relationship between the two (pinned by TEST-S-024): joinable is a strict
// SUBSET of retained. The sweeper cannot check tokens — it has no presented
// credential at sweep time — so it must keep anything a token holder could still
// return to. That asymmetry is why these are two functions and not one.
fn room_retained(within_ttl: bool, attempts: u32, receiver_count: usize) -> bool {
    within_ttl || (attempts >= 2 && receiver_count > 0)
}

fn room_joinable(within_ttl: bool, token_ok: bool, receiver_count: usize) -> bool {
    within_ttl || (token_ok && receiver_count > 0)
}

// Reaching the attempt cap always refuses the connection. Destroying the room is a
// separate, stronger act, and it is only correct when nobody is in it.
//
// Burning a room that two peers are actively using turns brute-force defence into a
// weapon: anyone holding a live code can spend three ordinary connections to evict a
// pair that is mid-transfer, and — because the relay counter lives in the Room — the
// same act removes that session's byte ceiling, since a charge against a missing room
// has nothing to compare. Neither peer ever sees the third connection; it is refused
// exactly as before. Only the eviction is withdrawn.
//
// Against an actual enumeration attempt this loses nothing: a guessed code either
// finds no room at all, or finds one nobody has joined yet, and that room is still
// burned on the cap.
fn burn_room_on_cap(attempts: u32, receiver_count: usize) -> bool {
    attempts >= MAX_CODE_ATTEMPTS && receiver_count == 0
}

// Same reasoning as burn_room_on_cap above, applied to the resume counter
// instead of the attempt counter. `resumes` never resets across a room's life
// (a legitimate long session's 65th mobile resume is not an attack), so
// reaching the cap must always refuse the join but must only ever destroy the
// room when nobody live would be stranded by it.
fn burn_room_on_resume_cap(resumes: u32, receiver_count: usize) -> bool {
    resumes > MAX_RESUME_JOINS && receiver_count == 0
}

// Liveness. Nothing in this server previously noticed a connection that died
// without a FIN. A phone leaving WiFi blackholes its TCP: `socket.recv()` never
// returns, the task parks until MAX_SESSION_SECS (1 h), no peer-left is ever
// broadcast, and the survivor's UI keeps claiming "Connected" over a dead session.
// Confirmed in practice. tungstenite auto-answers an inbound Ping but never
// generates heartbeats of its own, so the server must drive them.
const HEARTBEAT_INTERVAL_SECS: u64 = 15;
// The silence CHECK runs on its own, faster tick. It used to share the ping's
// cadence, which made the reap resolution 15 s: real silence starts at an
// arbitrary phase against the tick, so a 45 s timeout actually fired anywhere in
// 45–60 s. Measured at 58.3 s in practice against a constant that says 45 —
// the same class of measurement bias seen elsewhere in this codebase, and invisible to the prober because it measures
// the aligned case (silence from t≈0, where 45 lands exactly on a tick).
// 5 s narrows the real range to 45–50 s. The ping stays at 15 s on the wire.
const HEARTBEAT_TICK_SECS: u64 = 5;
const PINGS_EVERY_N_TICKS: u64 = HEARTBEAT_INTERVAL_SECS / HEARTBEAT_TICK_SECS;
// Silence past this ends the connection. Deliberately keyed on ANY inbound frame,
// not on Pong alone: cloudflared mangles WS control frames here (see 15.10b), so a
// Pong-only timeout could reap a healthy client behind the tunnel. The client's own
// 10 s T_KEEPALIVE is therefore the primary liveness signal and our Ping is the
// backup — 45 s clears four client keepalives and three of our pings. The client
// also runs its own 30 s soft warning; this one stays slower on purpose,
// because ours is the authoritative timeout that actually ends the connection.
const PEER_SILENCE_TIMEOUT_SECS: u64 = 45;

// A connection may only be judged silent once the room is actually paired. A sender
// waiting alone for its receiver legitimately sends nothing for as long as the owner
// takes to read the code out loud, and an abandoned one is already bounded by
// CODE_TTL_SECS. In the zombie case this still fires on the right task: the dead
// peer's own handler sees receiver_count 2 (survivor + itself) and reaps itself,
// while the live survivor keeps its keepalives flowing and is never reaped.
fn peer_is_silent(receiver_count: usize, silent_for: Duration) -> bool {
    receiver_count >= 2 && silent_for > Duration::from_secs(PEER_SILENCE_TIMEOUT_SECS)
}

// Follow-up to the liveness fix above, confirmed in practice: the heartbeat above is worthless unless
// every write is bounded, and none of them were.
//
// `tokio::select!` polls its branches only while it is choosing one. Once a branch
// is taken, an `.await` inside that branch's BODY runs with select suspended — so
// `socket.send(msg).await` in the relay arm parked the whole loop, heartbeat arm
// included. On a blackholed socket (phone walks off WiFi, no FIN) the kernel send
// buffer fills and that await never completes: the task never exits, never
// broadcasts, and stays subscribed forever, holding `receiver_count` up.
//
// Observed directly: a rejoin logged `rc=3` (survivor + zombie
// + returning peer) and then **no exit line at all** — the zombie was still parked
// when the whole transfer finished. Note this only became reachable once transfers were made to
// survive the switch: a surviving transfer means the survivor keeps
// ACKing, so the zombie always has a frame to relay into a socket nobody drains.
//
// Its own value, NOT an alias of PEER_SILENCE_TIMEOUT_SECS. They happen to be
// equal today and they answer different questions — "will not send us bytes" vs
// "will not accept ours". Aliasing them made it impossible to tell in practice which
// one had ended a connection, and it means tuning either one silently moves the
// other. Same number, independent knob.
//
// 45 s reasoning: a peer that has not accepted a byte in 45 s is exactly as gone
// as one that has not sent one, and a merely slow client gets RESUME_GRACE_SECS
// to come back. What matters most is that the bound EXISTS at all.
const WS_SEND_TIMEOUT_SECS: u64 = 45;

// Returns false if the write failed or could not complete inside the budget —
// either way this socket is finished and the caller must leave the loop.
async fn send_bounded(socket: &mut WebSocket, msg: Message) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(WS_SEND_TIMEOUT_SECS), socket.send(msg)).await,
        Ok(Ok(()))
    )
}

// Per-IP hard cap on simultaneously open WS connections. Prevents a botnet from
// accumulating idle sessions up to the session timeout. Normal flow uses
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
// This connection is not a member of the pair. Previously a non-member
// was ADMITTED and then silently muted — it could read the relay but every frame
// it sent was dropped, so it sat there believing it was connected. That is the
// same lie the whole liveness stage exists to remove, and it was the original
// symptom: a peer that reconnected "came back muted".
//
// Closing instead is strictly better in all three directions: a real member whose
// membership could not be proven now gets a visible failure it can act on rather
// than a session that appears fine and delivers nothing; an observer loses even
// read access to the relay (its frames were AEAD-protected anyway, but there is no
// reason to serve them); and the server stops holding a socket that can do nothing.
//
// It leaks nothing new. Reaching this point already required a valid, live code —
// which the old behaviour confirmed just as clearly by accepting the connection.
const CLOSE_NOT_A_MEMBER: u16    = 4008;

// A budget close must never be a silent death — the client maps this to a
// sentence that says what happened and what to do next, exactly as the not-a-member close did for a
// refused joiner. It is also deliberately NOT resumable on the client: the ceiling is
// room-scoped, so a reconnect would be refused again immediately.
const CLOSE_RELAY_BUDGET: u16    = 4009;
// The socket came from a page on another origin. Distinct from the rate-limit codes
// because nothing was charged — the client is being told "not you", not "not now".
const CLOSE_BAD_ORIGIN: u16      = 4010;

// 15.10b Cloudflare Tunnel drops WS close frames entirely — the client sees code 1006
// ("abnormal closure") instead of our 4001..4007. Workaround: send a plain Text frame
// ("BEEM-CLOSE:<code>:<reason>") the client caches and uses as a fallback when ev.code
// is 1006. cloudflared also drops trailing frames if the server closes the TCP stream
// too fast — so we sleep briefly between send and close, then drain reads until the
// client's close-ack or a short timeout (keeps the socket alive long enough for
// cloudflared to actually flush the text frame).
async fn send_close_signal(socket: &mut WebSocket, code: u16, reason: &str) {
    // Bounded for the same reason as the relay arm: this runs on sockets that are
    // often already dead, and an unbounded write here leaks the task — it would sit
    // parked past its own loop, still subscribed, still inflating receiver_count.
    send_bounded(socket, Message::Text(format!("BEEM-CLOSE:{}:{}", code, reason))).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    send_bounded(
        socket,
        Message::Close(Some(CloseFrame { code, reason: reason.to_string().into() })),
    )
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

// 25.3 An honest client puts exactly two kinds of frame on the wire: AEAD
// binary frames, and the one plaintext `BEEM-LEAVE` marker (consumed by the
// rx arm above the relay arm, never forwarded). Every other Text frame the
// relay sees from a pair member is a modified client trying to speak in the
// server's voice — `BEEM-TOKEN:` to overwrite the peer's resume token,
// `BEEM-CLOSE:` to pre-seed the peer's next drop as a terminal close,
// `BEEM-BUDGET:` to fake an allowance notice — because the client parses
// those markers pre-AEAD from ANY text message. Binary is the only thing a
// member may relay.
fn relayable_from_member(msg: &Message) -> bool {
    matches!(msg, Message::Binary(_))
}

#[derive(Clone)]
struct Room {
    tx: broadcast::Sender<(u64, Message)>,
    expires_at: Instant,
    // 15.11 Per-code attempt counter; incremented on every successful room
    // lookup in `pair()`. Once it reaches MAX_CODE_ATTEMPTS the room is removed.
    attempts: u32,
    // Mobile-resume joins: every Android
    // file-picker / screen-lock cycle reconnects the WS. These must not spend
    // the brute-force budget above or a long session burns its own room
    // mid-transfer — but they get their own generous cap so an uncounted
    // path is never an unlimited one.
    resumes: u32,
    // Proof-of-membership tokens. A returning peer that presents one of
    // these is a pair member regardless of what `tx.receiver_count()` says —
    // fixes the reconnect-after-network-switch misclassification (a dead-but-
    // not-closed connection still counts as a subscriber, so the old count-only
    // rule silently muted a legitimate rejoin). At most 2 tokens ever live here
    // (one per pair slot); minted lazily on first membership grant, never on
    // every join. Dies with the room, so bounded by MAX_SESSION_SECS same as
    // everything else room-scoped.
    member_tokens: Vec<MemberSlot>,
    // Relayed bytes charged against this session, both directions. Room-
    // scoped on purpose — a per-connection counter would hand a fresh budget to every
    // mobile reconnect, and on Android every file-picker cycle is a reconnect.
    relay_bytes: u64,
    // One warning per session, not one per batch.
    budget_warned: bool,
}

// One pair slot — its token, and how many times that token has been
// re-presented since it was minted. The counter is what lets a connection
// discover, at its own exit, that its slot has ALREADY been refilled by the
// same member returning on a new socket.
//
// Observed in practice: a phone that left WiFi rejoined on cellular at
// ~10 s, but the zombie's heartbeat did not reap it until ~45 s. The zombie's
// exit then broadcast BEEM-GRACE room-wide, so the returned phone was told its
// own peer had been lost — while sitting in a working session. Counting is
// deliberately per-slot and not per-room: with a room-wide epoch, B resuming
// once would silence the grace for A's later genuine departure, and the
// survivor would never be told. That is a far worse bug than the banner.
//
// Note this is NOT the receiver_count trick — a count can be inflated by any
// observer subscribing, which is the exact fragility the token-based membership check removed. Only a
// holder of the slot's token can advance this number.
#[derive(Clone)]
struct MemberSlot {
    token: String,
    claims: u32,
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
    relay_limit: u64,
    audit: bool,
    ip_cfg: Arc<ClientIpConfig>,
    allowed_origins: Arc<Vec<String>>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct WsParams {
    code: String,
    // Resume token proving prior membership in this room (see `slot_index`).
    // Travels in the same query string as `code` already does, so this adds no
    // new exposure surface — anything that could see `t` could already see `code`.
    #[serde(default)]
    t: Option<String>,
}

#[derive(Serialize)]
struct NewCodeResponse {
    code: String,
}

// 22.3 Ephemeral TURN credentials (coturn TURN REST API / use-auth-secret).
// The relay secret and URLs live ONLY in the server's environment (deploy-only,
// never in the repo); the static long-term credential is retired. A scraped
// credential expires after TURN_CRED_TTL_SECS, so it can't be reused to steal
// relay bandwidth at public launch.
//
// The TTL used to be 2 h, four times the life of the room it serves. A room
// cannot outlive MAX_SESSION_SECS, so a credential minted at join only has to
// cover that plus resume grace; anything beyond is pure reuse window for a
// scraper. Must stay >= MAX_SESSION_SECS or a long session loses its relay
// mid-transfer.
const TURN_CRED_TTL_SECS: u64 = MAX_SESSION_SECS + 15 * 60;

#[derive(Clone)]
struct TurnCfg {
    secret: Vec<u8>,
    urls: Vec<String>,
}

// Present only when both env vars are set (production). Absent in local dev/CI,
// where /turn.json 404s and the client falls back to public STUN — unchanged.
fn load_turn_cfg() -> Option<TurnCfg> {
    let secret = std::env::var("IRIS_TURN_SECRET").ok().filter(|s| !s.is_empty())?;
    let urls: Vec<String> = std::env::var("IRIS_TURN_URLS")
        .ok()?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if urls.is_empty() {
        return None;
    }
    Some(TurnCfg { secret: secret.into_bytes(), urls })
}

// /turn.json is no longer an open mint. The caller must name a live room
// and prove membership of it with the same token `slot_index` checks on the
// WS path. The token travels in a header, not the query string, so a fronting
// proxy's access log never records it (the WS path has no such option — a
// WebSocket handshake cannot carry a custom header from the browser).
#[derive(Deserialize)]
struct TurnParams {
    #[serde(default)]
    code: Option<String>,
}

const TURN_MEMBER_HEADER: &str = "x-iris-member";

#[derive(Serialize)]
struct TurnJson {
    urls: Vec<String>,
    username: String,
    credential: String,
}

// An opaque, stable per-room tag for the TURN username. Derived from the
// relay secret so it discloses nothing about the code, and stable for the life
// of the room so both peers land in the same coturn quota bucket.
fn turn_room_tag(secret: &[u8], code: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"iris-turn-room:");
    mac.update(code.as_bytes());
    mac.finalize().into_bytes().iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

// (username, credential): username = <unix expiry> or <unix expiry>:<room tag>,
// credential = base64(HMAC-SHA1(secret, username)) — exactly what coturn's
// use-auth-secret recomputes and validates. coturn HMACs the whole username
// string either way, so the tag needs NO coturn-side configuration change.
//
// Tagging per room is what gives coturn's own `user-quota` teeth. Untagged,
// every caller within the same second shared one username, so the quota bucket
// was an arbitrary time slice; one abuser could spend the allowance that honest
// pairs in that second needed. Per room, a single room can never exceed
// user-quota allocations no matter how often its credential is re-fetched.
fn turn_credential(secret: &[u8], now_unix: u64, room_tag: &str) -> (String, String) {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let expiry = now_unix + TURN_CRED_TTL_SECS;
    let username = if room_tag.is_empty() {
        expiry.to_string()
    } else {
        format!("{}:{}", expiry, room_tag)
    };
    let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (username, credential)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

// 17.3 branding: wordmark text is spliced into a JSON string literal in
// branding.json — escape backslash/quote and drop control characters so it
// can't break out of the literal. (This used to be shipped as
// branding.js, an unpinned script the page executed first; it is now data that
// the SRI-pinned app.js applies.)
fn escape_json_string(s: &str) -> String {
    s.chars().take(64).flat_map(|c| match c {
        '\\' => vec!['\\', '\\'],
        '"' => vec!['\\', '"'],
        c if c.is_control() => vec![' '],
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
    // Overridable so a self-hoster can raise it, lower it, or set 0 to disable the
    // ceiling on bandwidth they pay for themselves. Default is the shipped 12 GiB.
    let relay_limit: u64 = std::env::var("BEEM_MAX_RELAY_BYTES").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(MAX_RELAY_BYTES);

    // 17.4 Optional stderr audit log for compliance. Off by default; no content, no
    // codes, no raw IPs — fingerprint only (see ip_fingerprint, reused from 15.3).
    let audit = std::env::var("BEEM_AUDIT").ok().as_deref() == Some("1");

    // 17.3 optional self-host branding: unset by default, no visible change.
    let branding_css = std::env::var("BEEM_ACCENT_COLOR").ok()
        .filter(|c| is_safe_css_color(c))
        .map(|c| format!(":root {{ --accent: {c} !important; --accent-press: {c} !important; }}\n"))
        .unwrap_or_default();
    let branding_json = std::env::var("BEEM_WORDMARK_TEXT").ok()
        .filter(|t| !t.is_empty())
        .map(|t| format!("{{\"wordmark\":\"{}\"}}\n", escape_json_string(&t)))
        .unwrap_or_default();

    // One client-identity resolver, shared by the governor layers and /ws so all
    // three routes derive the same identity. Unset it reads no header at all.
    let (ip_cfg, ip_cfg_warnings) = ClientIpConfig::from_env();
    let ip_cfg = Arc::new(ip_cfg);
    for w in &ip_cfg_warnings {
        eprintln!("[client-ip] {w}");
    }
    if ip_cfg.header.is_none() {
        eprintln!("[client-ip] IRIS_CLIENT_IP_HEADER is unset — no forwarded header is read,");
        eprintln!("[client-ip] so every per-IP control keys on the TCP peer address. Behind a");
        eprintln!("[client-ip] reverse proxy or tunnel the peer is the proxy for every request,");
        eprintln!("[client-ip] which means the /new and /turn.json rate limits, the /ws attempt");
        eprintln!("[client-ip] budget, the 30-min/24-h ban ladder and the {MAX_CONCURRENT_PER_IP}-connection");
        eprintln!("[client-ip] concurrency cap ALL share one bucket for every client. Set");
        eprintln!("[client-ip] IRIS_CLIENT_IP_HEADER (plus IRIS_TRUSTED_PROXIES when the proxy is");
        eprintln!("[client-ip] not on loopback) to key them per client.");
    }

    // Extra origins for a deployment whose page is not served from the same host as
    // the socket. Unset means same-authority only, which is what the shipped layout is.
    let allowed_origins: Arc<Vec<String>> = Arc::new(
        std::env::var("IRIS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    );

    let rooms: Rooms = Arc::new(DashMap::new());
    let rate_limits: RateLimits = Arc::new(DashMap::new());
    let concurrent: Concurrent = Arc::new(DashMap::new());
    spawn_sweeper(rooms.clone(), rate_limits.clone(), concurrent.clone());
    let state = AppState {
        rooms, rate_limits, concurrent, session_secs, relay_limit, audit,
        ip_cfg: ip_cfg.clone(), allowed_origins,
    };

    // 12.1 Rate limit: /new ~ 10/min per IP (burst 10, replenish 1 per 6s).
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(6)
            .burst_size(10)
            .key_extractor(ClientIpKeyExtractor(ip_cfg.clone()))
            .finish()
            .expect("governor config"),
    );

    // 22.3 /turn.json config (deploy-only env; None in dev → route 404s) + its own
    // rate-limit bucket, separate from /new so a code request and a cred fetch
    // don't share a budget.
    let turn_cfg = load_turn_cfg();
    let turn_governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(6)
            .burst_size(10)
            .key_extractor(ClientIpKeyExtractor(ip_cfg.clone()))
            .finish()
            .expect("turn governor config"),
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
                 img-src 'self' data: blob:; \
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
        .route(
            "/turn.json",
            get(
                move |State(st): State<AppState>, headers: HeaderMap, Query(q): Query<TurnParams>| {
                    let cfg = turn_cfg.clone();
                    async move { turn_json(cfg, st, headers, q).await }
                },
            )
            .layer(GovernorLayer { config: turn_governor }),
        )
        .route("/ws", get(ws_handler))
        .route("/branding.css", get(move || {
            let body = branding_css.clone();
            async move { ([(CONTENT_TYPE, "text/css; charset=utf-8")], body) }
        }))
        .route("/branding.json", get(move || {
            let body = branding_json.clone();
            async move { ([(CONTENT_TYPE, "application/json; charset=utf-8")], body) }
        }))
        .with_state(state);

    // Dev-only diagnostic monitor. Mounted before the static fallback so `/` resolves
    // to the injected index.html; absent entirely without IRIS_MONITOR=1.
    let app = if monitor_enabled() {
        eprintln!("[monitor] ENABLED — logging to {}", monitor_log_path());
        eprintln!("[monitor] append ?dev=phone / ?dev=pc to each device's URL");
        app.route("/debug/monitor.js", get(monitor_script))
            .route("/debug/event", post(monitor_event))
            .route("/", get(monitor_index))
            .route("/index.html", get(monitor_index))
    } else {
        app
    };

    let app = app
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

// ---------------------------------------------------------------------------
// DEV MONITOR — development only, mounted ONLY when IRIS_MONITOR=1.
//
// Two-device manual testing was limited by a human watching two screens and
// reporting from memory ("25 or 30 seconds, plus or minus"), which is where wrong
// conclusions come from. This gives both clients somewhere to
// post what actually happened, stamped on ONE clock — the server's — which
// removes the phone-vs-laptop clock skew problem for free.
//
// It lives here rather than as a second local port because the phone can only
// reach the tunnel URL: anything the phone must talk to has to be same-origin.
//
// The client half is `tests/monitor/monitor.js` and is NOT part of `client/`.
// It is injected into the served index.html only in this mode, so the shipped
// tree contains no trace of it. `git revert` of this commit removes all of it.
//
// NOTHING SENSITIVE IS RECORDED — the client sends frame TYPES, never payloads,
// never token values, never the room code. These logs get pasted into chat and
// issue trackers, so they must stay free of anything that matters.
// ---------------------------------------------------------------------------

fn monitor_enabled() -> bool {
    std::env::var("IRIS_MONITOR").ok().as_deref() == Some("1")
}

fn monitor_log_path() -> String {
    std::env::var("IRIS_MONITOR_LOG").unwrap_or_else(|_| "../tests/monitor/session.ndjson".into())
}

// Served at /debug/monitor.js. Read per request so editing the script only needs
// a browser refresh, not a rebuild.
async fn monitor_script() -> Result<([(HeaderName, &'static str); 1], String), StatusCode> {
    let body = tokio::fs::read_to_string("../tests/monitor/monitor.js")
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(([(CONTENT_TYPE, "text/javascript; charset=utf-8")], body))
}

// The real index.html with one extra script tag in front of the app module, so
// the monitor's prototype patches are installed before app.js runs. Same-origin
// and non-inline, so the existing CSP (`script-src 'self'`) covers it with no
// relaxation, and the SRI attributes on app.js/qr.js are untouched.
async fn monitor_index() -> Result<axum::response::Html<String>, StatusCode> {
    let html = tokio::fs::read_to_string("../client/index.html")
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let tag = "<script src=\"/debug/monitor.js\"></script>\n    ";
    Ok(axum::response::Html(match html.find("<script type=\"module\"") {
        Some(i) => format!("{}{}{}", &html[..i], tag, &html[i..]),
        None => html,
    }))
}

// Dev-only diagnostic sink (IRIS_MONITOR=1, off by default) still needs to bound
// disk growth under an unauthenticated, unrate-limited route. 64 MiB comfortably covers
// many monitoring sessions (a real one logged ~8.7k events, a few MB) without letting a
// single forgotten-monitor deployment grow the log file without bound.
const MONITOR_LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;

// Pure — everything that decides what leaves this batch, with no I/O, so it is
// unit-testable without touching the filesystem or an env var. Filters `body`'s lines
// down to well-formed, unforged JSON objects and prepends the server's own receive
// time to each. Returns an empty string when nothing survives.
fn build_monitor_batch(body: &str, t_srv: u128) -> String {
    let mut out = String::with_capacity(body.len() + 64);
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A REAL JSON-object parse, not a starts_with('{')/ends_with('}') sniff. This
        // is what actually keeps a raw control byte off the operator's terminal: RFC
        // 8259 requires every C0/C1 control character inside a JSON string to be
        // escaped and forbids one anywhere else in the document, so a line that parses
        // at all cannot smuggle one through — only its escaped, inert text form (the
        // six-character text sequence for an escaped control code, not the byte
        // itself) can reach the sinks below.
        let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // The server's own receive time is the only thing the downstream timeline
        // analyser treats as ground truth. A line that already carries a `t_srv` key is
        // a forgery attempt — JSON's own last-key-wins semantics would let it shadow the
        // genuine one about to be prepended — so refuse the whole line outright.
        if obj.contains_key("t_srv") {
            continue;
        }
        out.push_str(&format!("{{\"t_srv\":{},{}\n", t_srv, &line[1..]));
    }
    out
}

// Accepts newline-delimited JSON from either client and appends it with one field
// prepended: the server's receive time. Deliberately does not interpret the events
// beyond that — the analyser (`tests/monitor/timeline.mjs`) owns their shape, and a
// dumb collector cannot become a second place where event semantics live.
async fn monitor_event(body: String) -> StatusCode {
    if body.len() > 256 * 1024 {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let t_srv = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out = build_monitor_batch(&body, t_srv);
    if out.is_empty() {
        return StatusCode::NO_CONTENT;
    }
    print!("{}", out); // live view in the terminal running the server
    use tokio::io::AsyncWriteExt;
    let path = monitor_log_path();
    // Refuse once the cap is reached rather than growing past it — same
    // fail-closed spirit as the relay byte ceiling elsewhere in this file.
    if let Ok(meta) = tokio::fs::metadata(&path).await {
        if meta.len() >= MONITOR_LOG_MAX_BYTES {
            return StatusCode::INSUFFICIENT_STORAGE;
        }
    }
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        let _ = f.write_all(out.as_bytes()).await;
    }
    StatusCode::NO_CONTENT
}

// One sweep pass over all three maps. Free function so tests can drive it
// with a controlled `now` instead of waiting on the interval.
fn sweep_maps(rooms: &Rooms, rate_limits: &RateLimits, concurrent: &Concurrent, now: Instant) {
    let window = Duration::from_secs(WS_WINDOW_SECS);
    let ban_cooldown_window = Duration::from_secs(BAN_COOLDOWN_WINDOW_SECS);
    let ban_medium_window = Duration::from_secs(BAN_MEDIUM_WINDOW_SECS);
    rooms.retain(|_, r| room_retained(r.expires_at > now, r.attempts, r.tx.receiver_count()));
    // 15.2 + 15.3 GC: keep entries with any active state or recent history.
    // Ladder memory must outlive the cooldown itself: an entry whose only live
    // state is a cooldown trip inside BAN_COOLDOWN_WINDOW still counts toward
    // the 3-trips→30-min-ban escalation, so it may not be swept.
    rate_limits.retain(|_, s| {
        let has_recent = s.attempts.back().is_some_and(|t| now.duration_since(*t) < window);
        let in_cooldown = s.cooldown_until.is_some_and(|u| u > now);
        let in_ban = s.ban_until.is_some_and(|u| u > now);
        let recent_cooldown_history = s.cooldown_history.back().is_some_and(|t| now.duration_since(*t) < ban_cooldown_window);
        let recent_ban_history = s.ban_history.back().is_some_and(|t| now.duration_since(*t) < ban_medium_window);
        has_recent || in_cooldown || in_ban || recent_cooldown_history || recent_ban_history
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

// 128-bit resume token as lowercase hex (32 chars). Minted once per pair
// member on first acceptance into a room; see `slot_index` for the
// constant-time check on the way back in.
fn generate_member_token() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

async fn new_code(State(state): State<AppState>) -> Result<Json<NewCodeResponse>, StatusCode> {
    let rooms = &state.rooms;
    let mut rng = rand::thread_rng();
    for _ in 0..1000 {
        let code = generate_code(&mut rng);
        if let Entry::Vacant(v) = rooms.entry(code.clone()) {
            let (tx, _) = broadcast::channel(ROOM_CHANNEL_CAPACITY);
            v.insert(Room {
                tx,
                expires_at: Instant::now() + Duration::from_secs(CODE_TTL_SECS),
                attempts: 0,
                resumes: 0,
                member_tokens: Vec::new(),
                relay_bytes: 0,
                budget_warned: false,
            });
            return Ok(Json(NewCodeResponse { code }));
        }
    }
    // 1M codes — hitting 1000 retries requires >99.9% occupancy; return 503 instead of looping forever
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

// 22.3 GET /turn.json — mints a short-lived TURN REST credential. Overrides the
// old static file. Absent config (local dev) → 404, so the client falls back to
// public STUN exactly as before. Rate-limited at the router like /new.
//
// Membership is now required. Note honestly what this does and
// does not buy: an attacker can still script POST /new → /ws → /turn.json to
// reach a credential, so this is not an authentication boundary — the scan
// panel refuted the "bind it to a room" framing on exactly that ground. What it
// buys is that every credential is now bound to a room that has a 5-attempt
// cap, a TTL and a sweeper, and — via the per-room username tag — to one coturn
// quota bucket. Harvesting at scale now costs a room per bucket instead of
// being a single unauthenticated GET.
async fn turn_json(
    cfg: Option<TurnCfg>,
    state: AppState,
    headers: HeaderMap,
    params: TurnParams,
) -> Result<Json<TurnJson>, StatusCode> {
    let cfg = cfg.ok_or(StatusCode::NOT_FOUND)?;
    let code = params.code.unwrap_or_default();
    if !is_valid_code(&code) {
        return Err(StatusCode::FORBIDDEN);
    }
    let presented = headers
        .get(TURN_MEMBER_HEADER)
        .and_then(|v| v.to_str().ok());
    // Same constant-time slot check the WS resume path uses. An absent room and
    // a wrong token are indistinguishable to the caller: both 403.
    let is_member = state
        .rooms
        .get(&code)
        .is_some_and(|r| slot_index(&r.member_tokens, presented).is_some());
    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }
    let tag = turn_room_tag(&cfg.secret, &code);
    let (username, credential) = turn_credential(&cfg.secret, now_unix(), &tag);
    Ok(Json(TurnJson { urls: cfg.urls, username, credential }))
}

// 15.2 + 15.3 Check per-IP WS connect; record this attempt; escalate ban tiers if warranted.
// Every /ws connection attempt is counted, valid or invalid code — this is intentional so
// an attacker can't probe the code space faster than the honest-case pair rate allows.
//
// Escalation ladder:
//   - 5 attempts / 60 s    → 30-second cooldown
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
        // Engage the cooldown (WS_COOLDOWN_SECS) and record this trip.
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
// Salted per process. Without a salt this is not privacy-preserving: the hash is
// deterministic and the IPv4 space is only 2^32, so anyone holding a log line could
// enumerate every address and recover the original in seconds. A random salt minted at
// startup keeps fingerprints comparable within one run — which is all the ban ladder
// needs — while making them useless to anyone reading the log afterwards.
static FP_SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

fn ip_fingerprint(ip: IpAddr) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let salt = *FP_SALT.get_or_init(rand::random::<u64>);
    let mut h = DefaultHasher::new();
    salt.hash(&mut h);
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
// process (cloudflared, nginx, Caddy) that terminates TLS and forwards. In that setup
// every TCP peer address is 127.0.0.1, so the peer address alone collapses every real
// user into one bucket.
//
// A forwarded header is only evidence if something we trust wrote it, and nothing in
// this process can tell an operator's proxy apart from a client that simply sent the
// header itself. A loopback peer does not establish that either: it says the request
// arrived from this host, not that the hop rewrote anything. So the trust is declared:
//
//   IRIS_CLIENT_IP_HEADER   name of the ONE forwarded-IP header to believe, e.g.
//                           `cf-connecting-ip` or `x-forwarded-for`. Unset — the
//                           default — means no header is ever read.
//   IRIS_TRUSTED_PROXIES    comma-separated exact addresses whose header is believed
//                           and which are skipped as hops while walking it. Loopback
//                           is always a trusted hop; unset means loopback only.
//
// Unset, this returns the TCP peer and nothing else. That is the safe answer, not a
// complete one: behind a proxy the peer is the proxy, so every per-IP control keys on
// a single identity until the header is named. `main` says so at startup.
#[derive(Clone, Debug, Default)]
struct ClientIpConfig {
    header: Option<HeaderName>,
    trusted: Vec<IpAddr>,
}

// `1.2.3.4` and `::ffff:1.2.3.4` are the same host but different `IpAddr` values, so
// without folding them together one host holds two of everything keyed on identity —
// two attempt budgets, two ban ladders, two concurrency allowances. It also decides
// trust: `::ffff:127.0.0.1`.is_loopback() is FALSE, so on a dual-stack bind (`BEEM_HOST=::`,
// or the shipped compose file's `0.0.0.0` reached over a v6 mapping) the local proxy
// would not read as a trusted hop and every client would collapse back into one bucket —
// the exact failure this resolver exists to prevent. Fold before comparing or keying.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

impl ClientIpConfig {
    // Returns the config plus any operator-facing complaints, so `main` can print them
    // and the parsing stays testable. A malformed value is never silently equivalent to
    // an absent one: absent is a deliberate default, malformed is a mistake.
    fn from_env() -> (Self, Vec<String>) {
        let mut warnings = Vec::new();

        let raw_header = std::env::var("IRIS_CLIENT_IP_HEADER")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let header = raw_header.as_ref().and_then(|s| {
            let parsed = HeaderName::try_from(s.as_str()).ok();
            if parsed.is_none() {
                warnings.push(
                    "IRIS_CLIENT_IP_HEADER is not a valid header name and was ignored".into(),
                );
            }
            parsed
        });

        let mut trusted = Vec::new();
        for entry in std::env::var("IRIS_TRUSTED_PROXIES").unwrap_or_default().split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<IpAddr>() {
                Ok(ip) => trusted.push(canonical_ip(ip)),
                // Deliberately does not echo the value: this runs on operator input, but
                // an address is an address and none of them belong in a log line.
                Err(_) => warnings.push(
                    "IRIS_TRUSTED_PROXIES contains an entry that is not an IP address; \
                     that hop will NOT be trusted"
                        .into(),
                ),
            }
        }

        (Self { header, trusted }, warnings)
    }

    // A hop whose forwarded header we believe, and which is skipped while walking it.
    // Loopback is always trusted — reaching it at all requires being on this host.
    //
    // Both sides are folded here rather than relying on the stored list already being
    // canonical: a trust check that is only correct when the struct was built by one
    // particular constructor is a decision waiting to be got wrong.
    fn is_trusted_hop(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        ip.is_loopback() || self.trusted.iter().any(|t| canonical_ip(*t) == ip)
    }
}

// A configured header that never gets read is the silent version of the bug this whole
// resolver fixes: the startup notice only fires when the header is UNSET, so an operator
// who names a header but forgets `IRIS_TRUSTED_PROXIES` — the shipped Docker case, where
// the peer is the bridge gateway rather than loopback — would otherwise be told nothing
// while every client shares one bucket. Warn once, on the first request that proves it.
static UNTRUSTED_PEER_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn warn_untrusted_peer_once() {
    if !UNTRUSTED_PEER_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "[client-ip] IRIS_CLIENT_IP_HEADER is set but the request arrived from an \
             address that is not a trusted hop, so the header was ignored and this request \
             was keyed on the TCP peer. If a proxy fronts this server, add its address to \
             IRIS_TRUSTED_PROXIES — otherwise every client shares one rate-limit, ban and \
             concurrency bucket. (Logged once per process; no address is recorded.)"
        );
    }
}

// One element of a forwarded header. Bytes rather than `&str`, because `to_str` fails
// on the whole value: a single non-UTF-8 element on the attacker-controlled left would
// otherwise discard the trustworthy elements on the right.
fn parse_forwarded_element(raw: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(raw).ok()?.trim().trim_matches('"');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // Some proxies append the source port: `1.2.3.4:5678`, `[2001:db8::1]:5678`.
    s.parse::<SocketAddr>().ok().map(|sa| sa.ip())
}

fn resolve_client_ip(cfg: &ClientIpConfig, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    // No declared header, or a peer we have no reason to trust: the TCP peer is the
    // only client identity we actually observed.
    let peer = canonical_ip(peer);
    let Some(name) = cfg.header.as_ref() else {
        return peer;
    };
    if !cfg.is_trusted_hop(peer) {
        warn_untrusted_peer_once();
        return peer;
    }

    // Right to left. Everything right of the first untrusted element was appended by a
    // hop we trust; everything to its left is whatever the client chose to send. So the
    // first element that is not a trusted hop is the furthest point we hold evidence
    // for — take it and stop. A malformed element stops the walk as well, so garbage on
    // the left can never push the walk further out than the evidence reaches.
    //
    // Repeated header lines are one comma list in arrival order (RFC 7230 §3.2.2), so a
    // value the client injected sorts before the one the proxy appended. Walking every
    // line in reverse is what makes an injected duplicate lose to the real hop.
    for value in headers.get_all(name).iter().collect::<Vec<_>>().into_iter().rev() {
        for element in value.as_bytes().rsplit(|b| *b == b',') {
            match parse_forwarded_element(element) {
                Some(ip) if cfg.is_trusted_hop(ip) => continue,
                Some(ip) => return canonical_ip(ip),
                None => return peer,
            }
        }
    }
    peer
}

// The rate-limit key is the same client identity `ws_handler` derives. Without it the
// governor layers use the crate's default peer-IP extractor, which behind a proxy is
// one key shared by the entire internet — one caller can then hold the `/new` bucket
// drained and stop every other visitor from creating a room.
#[derive(Clone)]
struct ClientIpKeyExtractor(Arc<ClientIpConfig>);

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;
        Ok(resolve_client_ip(&self.0, req.headers(), peer))
    }
}

// The per-IP concurrency slot, released by `Drop` rather than by a line at the end
// of the upgrade callback.
//
// This is not styling. `axum-0.7.9/src/extract/ws.rs:314-319` awaits the upgrade inside a
// spawned task and, on error, calls `on_failed_upgrade` and RETURNS — the callback is
// never invoked, so a decrement written inside it never runs. A client that resets the
// connection mid-handshake therefore stranded a count permanently, and `sweep_maps`
// deliberately preserves non-zero counts, so eight of them barred that address (and
// everyone behind the same NAT) from signalling for the life of the process.
//
// A guard captured by the callback closure is dropped when the closure is dropped
// un-called, which is exactly the leaked path — and also covers the callback's future
// being dropped part-way.
struct ConcurrencySlot {
    map: Concurrent,
    ip: IpAddr,
}

impl ConcurrencySlot {
    // Returns None when the address is already at the cap, having changed nothing.
    fn acquire(map: &Concurrent, ip: IpAddr) -> Option<Self> {
        let mut count = map.entry(ip).or_insert(0);
        if *count >= MAX_CONCURRENT_PER_IP {
            return None;
        }
        *count += 1;
        drop(count);
        Some(Self { map: map.clone(), ip })
    }
}

impl Drop for ConcurrencySlot {
    fn drop(&mut self) {
        if let Some(mut c) = self.map.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
        }
    }
}

// Is this socket from our own page?
//
// A browser always sends `Origin` on a WebSocket handshake and a page cannot forge it, so
// comparing it to the `Host` we were addressed as is what separates our own page from any
// other site's. TLS terminates at the front, so the scheme is not ours to check — the
// authority is.
//
// A MISSING Origin is allowed on purpose. Only browsers are bound by this header; a CLI
// client (our own timing prober, curl, a self-hosted integration) sends none and can forge
// any value it likes, so demanding one would break honest tooling while stopping no
// attacker. This addresses browser-based cross-origin access specifically, and this is the browser-shaped control.
//
//   IRIS_ALLOWED_ORIGINS  comma-separated extra origins to accept, for a deployment whose
//                         page is served from a different host than the socket. Unset —
//                         the default — means same-authority only.
// Split an authority into (host, port), lower-cased. Handles the three shapes that turn
// a naive string compare into a false accept or a false reject: userinfo before an `@`
// (`https://iris.example@evil.test` must read as host `evil.test`, not `iris.example`),
// a bracketed IPv6 literal whose colons are not port separators, and a trailing root dot.
fn authority_parts(raw: &str) -> Option<(String, Option<String>)> {
    let s = raw.trim();
    // Everything up to the LAST `@` is userinfo. Last, not first: a password may contain one.
    let s = match s.rfind('@') {
        Some(i) => &s[i + 1..],
        None => s,
    };
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']')?;
        (&s[..=end], s[end + 1..].strip_prefix(':'))
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some((
        host,
        port.filter(|p| !p.is_empty()).map(|p| p.to_ascii_lowercase()),
    ))
}

fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let origin = origin.trim();

    // An explicitly allowed origin is matched whole, scheme included, so an operator
    // cannot accidentally widen this to every scheme on that host.
    if allowed.iter().any(|a| a.eq_ignore_ascii_case(origin)) {
        return true;
    }

    // Otherwise the origin's authority must be the Host we were addressed as.
    let authority = origin.split_once("://").map(|(_, rest)| rest).unwrap_or(origin);
    let Some((origin_host, origin_port)) = authority_parts(authority) else {
        return false;
    };
    // No Host to compare against: refuse rather than guess. HTTP/1.1 requires one and
    // axum synthesises it from the :authority pseudo-header on HTTP/2.
    let Some(host_hdr) = headers.get(http::header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Some((host_host, host_port)) = authority_parts(host_hdr) else {
        return false;
    };

    if origin_host != host_host {
        return false;
    }

    // Ports are compared ONLY when both sides actually carry one.
    //
    // This is not laxness, it is the deployment talking: `SELFHOST.md` ships nginx with
    // `proxy_set_header Host $host`, and nginx's `$host` drops the port. A browser, by
    // contrast, puts the port in `Origin` whenever it is not the scheme's default. So on
    // a self-host at a non-default port the two sides disagree by construction, and
    // requiring equality would refuse every legitimate connection rather than any attack.
    // A portless side is missing information, not contradicting evidence.
    //
    // The residual: a page on the SAME host at a different port is accepted when the
    // proxy strips the port. Serving that page already requires control of another port
    // on our own hostname, which is a larger foothold than this control was ever meant
    // to address. An operator who needs the strict form lists the exact origins in
    // IRIS_ALLOWED_ORIGINS.
    match (host_port, origin_port) {
        (Some(h), Some(o)) => h == o,
        _ => true,
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // 15.10 Resolve the real client IP (may be behind a local reverse proxy).
    let ip = resolve_client_ip(&state.ip_cfg, &headers, addr.ip());

    // Origin check FIRST — before the rate-limit charge below. That order is the whole
    // point: a foreign page's socket must not debit the visitor's attempt budget, or the
    // page can walk them up the ban ladder just by keeping them on it.
    if !origin_allowed(&headers, &state.allowed_origins) {
        return ws.on_upgrade(move |mut socket| async move {
            send_close_signal(&mut socket, CLOSE_BAD_ORIGIN, "").await;
        });
    }

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
    let Some(slot) = ConcurrencySlot::acquire(&state.concurrent, ip) else {
        return ws.on_upgrade(move |mut socket| async move {
            send_close_signal(&mut socket, CLOSE_RATE_COOLDOWN, "too many connections").await;
        });
    };

    ws.max_message_size(MAX_WS_FRAME)
        .max_frame_size(MAX_WS_FRAME)
        .on_upgrade(move |socket| async move {
            // `slot` is owned by this future; it releases on every exit, including the
            // upgrade failing before this body ever runs.
            let _slot = slot;
            pair(socket, params.code, params.t, state.rooms, state.session_secs, state.relay_limit, ip, state.audit).await;
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

async fn pair(mut socket: WebSocket, code: String, resume_token: Option<String>, rooms: Rooms, session_secs: u64, relay_limit: u64, ip: IpAddr, audit: bool) {
    // 15.11 Per-code brute-force guard: increment attempts on lookup. If this
    // attempt would put us at or past MAX_CODE_ATTEMPTS, burn the room entirely.
    // Also capture attempt count before increment — only the first 2 connections
    // (the legitimate pair) are allowed to broadcast close signals to each other.
    let (tx, is_pair_member, was_resume, minted_token, my_slot, claims_at_join) = {
        // Decide joinability and release the map lock BEFORE the await in
        // send_close_signal — holding a DashMap guard across an await is how you
        // deadlock every other joiner on this code.
        let joinable = match rooms.get(&code) {
            None => false,
            Some(r) => room_joinable(
                r.expires_at > Instant::now(),
                slot_index(&r.member_tokens, resume_token.as_deref()).is_some(),
                r.tx.receiver_count(),
            ),
        };
        if !joinable {
            send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
            return;
        }
        // Re-acquire: the room can still vanish between the two lookups (sweeper,
        // or another joiner burning the attempt budget), so this is not redundant.
        let mut entry = match rooms.get_mut(&code) {
            Some(r) => r,
            None => {
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            }
        };
        let attempt_before = entry.attempts;
        // Once a room has minted both member slots, the tokenless count
        // heuristic below must stop granting membership. Read BEFORE any minting
        // this call might do (minting only ever happens later, at the bottom of
        // this block) so it reflects the room's true state at join time, not a
        // slot this very connection is about to claim.
        let both_slots_minted = entry.member_tokens.len() >= 2;

        // A presented token matching one on file is proof of membership,
        // full stop — it does not depend on `tx.receiver_count()` at all. This
        // is the fix for the reconnect-after-network-switch bug: a dead-but-
        // not-closed old connection keeps the broadcast channel's subscriber
        // count up, so the count-based heuristic below misreads a legitimate
        // rejoin as a third-party observer and silently mutes it. Observed in
        // practice: `join attempts_before=2 receiver_count=2
        // is_pair_member=false` on a real rejoin. A token sidesteps the
        // arithmetic instead of trying to patch it further.
        // This needs the slot itself, not just a yes/no — a departing connection
        // has to be able to ask "was MY slot refilled?" and nothing else.
        let mut my_slot = slot_index(&entry.member_tokens, resume_token.as_deref());
        let token_valid = my_slot.is_some();
        // Claim the slot before anyone else can: the count read here is the
        // baseline this connection compares against when it eventually exits.
        let mut claims_at_join = 0;
        if let Some(i) = my_slot {
            entry.member_tokens[i].claims += 1;
            claims_at_join = entry.member_tokens[i].claims;
        }

        if token_valid {
            // Proven member: counts toward the resume cap exactly like a
            // count-based resume does (an uncounted path must never become an
            // unlimited one) but does NOT spend a MAX_CODE_ATTEMPTS attempt —
            // mirrors how is_resume_join is wired into the bookkeeping just
            // below, gated on the token instead of the count heuristic.
            entry.resumes += 1;
            // Destroying the room is only correct when nobody else is left in it —
            // same emptiness predicate burn_room_on_cap already uses for the attempt
            // cap. A still-live partner must keep its room; only this join is refused.
            if burn_room_on_resume_cap(entry.resumes, entry.tx.receiver_count()) {
                drop(entry); // release the write lock before the DashMap remove.
                rooms.remove(&code);
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            } else if entry.resumes > MAX_RESUME_JOINS {
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            }
        } else if resume_admitted(both_slots_minted, attempt_before, entry.tx.receiver_count()) {
            // No token presented (or an invalid one — a stranger's guess must
            // not get the resume bypass either): fall back to the EXISTING
            // count-based rule, unchanged. Mobile-resume joins bypass the
            // brute-force counter (observed in practice: picker/screen-
            // lock cycles burned the room mid-transfer after ~3 resumes) but
            // are bounded by their own generous cap. This fallback is
            // deliberate belt-and-braces: a client that somehow lost its token
            // still behaves exactly as it does today. Remove it once the
            // token path is proven in practice.
            //
            // Gated on `!both_slots_minted` — once a room has minted a token
            // for both pair members, a bare code plus a favourable headcount (e.g.
            // one peer's dead-but-not-closed socket still holding receiver_count
            // up) must never be enough to walk in as a member and evict the real
            // peer. Before both slots exist there is no token to demand yet, so
            // the count heuristic is still the only membership signal available.
            entry.resumes += 1;
            if burn_room_on_resume_cap(entry.resumes, entry.tx.receiver_count()) { // same as above.
                drop(entry); // release the write lock before the DashMap remove.
                rooms.remove(&code);
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            } else if entry.resumes > MAX_RESUME_JOINS {
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            }
        } else {
            // saturating: the room is no longer removed at the cap when it is live, so
            // this counter can now keep climbing for the life of the session.
            entry.attempts = entry.attempts.saturating_add(1);
            if entry.attempts >= MAX_CODE_ATTEMPTS {
                let burn = burn_room_on_cap(entry.attempts, entry.tx.receiver_count());
                drop(entry); // release the write lock before the DashMap remove.
                if burn {
                    rooms.remove(&code);
                }
                send_close_signal(&mut socket, CLOSE_CODE_MISSING, "").await;
                return;
            }
        }
        // attempts 0→1 = sender, 1→2 = receiver: legitimate pair members.
        // attempts 2+ are either observers (attackers) OR reconnects after a mobile
        // background event. Distinguish by channel state: if exactly one subscriber
        // exists when we join, that's the surviving pair member holding the slot
        // open — we're filling it, so we count as a pair member too (for grace
        // purposes on our own exit). An attacker arrives when receiver_count is 0
        // or ≥ 2 and stays marked as observer.
        let tx = entry.tx.clone();
        let rc = tx.receiver_count();
        // A valid token overrides the count heuristic outright — no number
        // of stale, dead-but-not-closed subscribers can out-vote a proof of
        // membership. This is what makes this gate strictly stronger than the
        // count-only version it backs up: an observer without a token can no
        // longer be misclassified as a member no matter what the headcount says.
        // Reuses the exact same `resume_admitted` predicate the branch gate
        // above used, rather than re-deriving "is this a resume" a second time —
        // two independent evaluations of the same question are how the original
        // bug shape worked (branch selection and membership grant could disagree).
        let is_pair_member =
            token_valid || attempt_before < 2 || resume_admitted(both_slots_minted, attempt_before, rc);
        // 23.7 Likewise, a token-proven rejoin is always a resume (the survivor
        // may be showing the grace banner and needs the "peer is back" signal)
        // regardless of the count-based was_resume heuristic below it.
        let was_resume = token_valid || (attempt_before >= 2 && rc == 1);

        // Mint a token only for a join accepted as a pair member that did NOT
        // already present a valid one (never double-mint) and only while a
        // slot remains (at most 2 tokens per room, one per pair member). The
        // token is per-room, dies with the room (so bounded by
        // MAX_SESSION_SECS same as everything else room-scoped), and grants
        // relay membership ONLY — it carries no key material and grants no
        // decryption ability, content stays protected by the AEAD regardless
        // of who holds a token.
        let minted_token = if is_pair_member && !token_valid && entry.member_tokens.len() < 2 {
            let tok = generate_member_token();
            entry.member_tokens.push(MemberSlot { token: tok.clone(), claims: 0 });
            my_slot = Some(entry.member_tokens.len() - 1); // this connection now owns it
            Some(tok)
        } else {
            None
        };
        (tx, is_pair_member, was_resume, minted_token, my_slot, claims_at_join)
    };

    // Tell a rejected joiner instead of muting it. Everything below this
    // point assumes membership, so there is nothing for a non-member to do here.
    if !is_pair_member {
        send_close_signal(&mut socket, CLOSE_NOT_A_MEMBER, "").await;
        return;
    }
    let mut rx = tx.subscribe();
    let my_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);


    // hand the freshly minted token to THIS socket only. Never
    // `tx.send` — that broadcasts into the room and would hand the token to
    // the peer (and any observer) too, defeating its purpose as proof of
    // this specific connection's membership.
    if let Some(tok) = minted_token {
        let _ = socket.send(Message::Text(format!("BEEM-TOKEN:{}", tok))).await;
    }

    if was_resume {
        // 23.7 Clears the survivor's "waiting up to 30 s" banner.
        let _ = tx.send((my_id, Message::Text("BEEM-BACK".into())));
    }

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

    // Relay ceiling. `unflushed` is this socket's uncharged tail; it is folded into
    // the room's counter once it reaches RELAY_FLUSH_BYTES so the per-frame path stays
    // free of map writes. Returns the room's verdict, and sets the room's warned bit
    // itself so two sockets crossing 80 % in the same instant still produce one warning.
    let mut unflushed: u64 = 0;
    let mut budget_hit = false;
    let relay_charge = |unflushed: &mut u64, add: u64| -> RelayBudget {
        *unflushed = unflushed.saturating_add(add);
        if *unflushed < RELAY_FLUSH_BYTES {
            return RelayBudget::Ok;
        }
        let batch = std::mem::take(unflushed);
        match rooms.get_mut(&code) {
            Some(mut r) => {
                r.relay_bytes = r.relay_bytes.saturating_add(batch);
                let st = relay_budget_state(r.relay_bytes, relay_limit, r.budget_warned);
                if st == RelayBudget::Warn {
                    r.budget_warned = true;
                }
                st
            }
            // Fail CLOSED. A relay in flight means at least the sender is still
            // subscribed, so room_retained keeps the room alive and this arm should be
            // unreachable. If it is reached anyway, the ceiling has lost the only
            // counter it can measure against — and answering Ok there is what made the
            // budget strippable by deleting the room. An anomaly ends the session
            // instead of granting it unlimited relay.
            None => RelayBudget::Exceeded,
        }
    };

    // Heartbeat state. `last_seen` tracks the last frame of ANY kind from this
    // socket — data, Pong, control — because that is the only signal that survives
    // the tunnel intact.
    // ORDER IS LOAD-BEARING — `last_seen` must be stamped BEFORE the interval is
    // created, and a refactor that "tidies" these two lines together will silently
    // regress it. The silence check is only evaluated on a tick, so its resolution
    // is HEARTBEAT_INTERVAL_SECS, and PEER_SILENCE_TIMEOUT_SECS (45) is exactly
    // three of them — the threshold lands on a tick boundary. Stamp `last_seen`
    // after the interval and elapsed at the T+45 tick is `45 − δ`, which loses to
    // a strict `>` every single time and slips the reap to T+60.
    //
    // Measured by the timing prober before this fix: 60.004 s, deterministically,
    // against a constant that says 45.
    //
    // No unit test can catch this — it is initialisation order, not arithmetic.
    // `node tests/timing/probe.mjs` (M2a) is the regression gate.
    let mut last_seen = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_TICK_SECS));
    let mut ticks: u64 = 0;
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await; // interval fires immediately on creation; spend that tick here

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                send_close_signal(&mut socket, CLOSE_SESSION_TIMEOUT, "").await;
                break;
            }
            _ = heartbeat.tick() => {
                ticks += 1;
                if peer_is_silent(tx.receiver_count(), last_seen.elapsed()) {
                    // Break rather than send a close frame: this socket is already
                    // gone, so writing to it would only park. Breaking is the whole
                    // fix — it runs the post-loop resume-grace path below, which is
                    // what finally tells the survivor its peer went quiet.
                    break;
                }
                // Ping on the wire keeps its 15 s cadence; only the silence CHECK
                // above runs on the faster tick.
                if !ticks.is_multiple_of(PINGS_EVERY_N_TICKS) { continue; }
                // Bounded: an unbounded Ping write parks this arm on a dead socket
                // and the next tick — the one that would reap it — never arrives.
                if !send_bounded(&mut socket, Message::Ping(Vec::new())).await { break; }
            }
            incoming = socket.recv() => {
                // Any inbound frame proves the far end is still there.
                last_seen = tokio::time::Instant::now();
                match incoming {
                    // 23.4: only a pair member may deliberately vanish. An
                    // observer's BEEM-LEAVE must NOT evict the pair — gated like the
                    // post-loop peer-left broadcast. A non-member marker falls through
                    // to the relay arm below, where it is dropped (not a member).
                    Some(Ok(Message::Text(ref t))) if is_pair_member && is_leave_marker(t) => {
                        // Deliberate vanish: broadcast peer-left immediately (the peer's
                        // own rx arm turns this Close into send_close_signal with
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
                    // Control frames are liveness, not data — bumping last_seen
                    // above is their entire job. They must never reach the relay arm
                    // below: broadcasting a Pong into the room would hand the peer a
                    // frame its pre-AEAD dispatch never expects.
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(msg)) => {
                        // Only pair members may broadcast into the room. Dropping an
                        // observer's frames here closes both the plaintext-marker spoof
                        // (BEEM-GRACE/BEEM-BACK/BEEM-CLOSE parsed client-side pre-AEAD)
                        // and junk-injection. Encrypted frames from an observer would
                        // fail the peer's AEAD anyway; this just stops them at the relay.
                        if is_pair_member && relayable_from_member(&msg) {
                            // Length read before the move into the broadcast.
                            let n = msg_payload_len(&msg) as u64;
                            bytes_in += n;
                            let _ = tx.send((my_id, msg));
                            match relay_charge(&mut unflushed, n) {
                                RelayBudget::Warn => {
                                    let _ = tx.send((
                                        BUDGET_BROADCAST_FROM,
                                        Message::Text(format!("BEEM-BUDGET:{}", RELAY_WARN_PCT)),
                                    ));
                                }
                                RelayBudget::Exceeded => { budget_hit = true; }
                                RelayBudget::Ok => {}
                            }
                        }
                        if budget_hit { break; }
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
                            let n = msg_payload_len(&msg) as u64;
                            bytes_out += n;
                            // THE parking point (confirmed in practice). select! is
                            // suspended for the whole of this await, so an unbounded
                            // write here disables the heartbeat arm completely.
                            if !send_bounded(&mut socket, msg).await { break; }
                            // Charged after the write, so bytes we failed to deliver are
                            // not billed to the session. An observer's outbound traffic
                            // is charged too (it is real bandwidth) but only a pair
                            // member's crossing may raise the warning, per the pair-member check above.
                            match relay_charge(&mut unflushed, n) {
                                RelayBudget::Warn if is_pair_member => {
                                    let _ = tx.send((
                                        BUDGET_BROADCAST_FROM,
                                        Message::Text(format!("BEEM-BUDGET:{}", RELAY_WARN_PCT)),
                                    ));
                                }
                                RelayBudget::Exceeded => { budget_hit = true; }
                                _ => {}
                            }
                            if budget_hit { break; }
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

    // F10: every exit from the loop above is a bare `break` — none of them flush
    // `unflushed` into the room's counter, only relay_charge's own 64 MiB threshold
    // does that. A connection that closes with bytes still sitting under that
    // threshold left them uncharged forever, understating the room's true relay
    // usage by up to RELAY_FLUSH_BYTES per connection — across the 64-resume cap,
    // enough to falsify the ceiling's own documented accounting bound. Fold the tail
    // in once, here, regardless of which exit path was taken. Best-effort: if the
    // room is already gone there is nothing left to charge and no ceiling left to
    // protect, same as every other post-loop room lookup in this function.
    if unflushed > 0 {
        if let Some(mut r) = rooms.get_mut(&code) {
            r.relay_bytes = r.relay_bytes.saturating_add(unflushed);
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

    // Say why. A socket that vanishes on a limit with no explanation is the same
    // class of bug as the sender that claimed a delivered file might not have arrived.
    if budget_hit {
        send_close_signal(&mut socket, CLOSE_RELAY_BUDGET, "").await;
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
    // If this connection's own slot has already been re-claimed, the member
    // it represents is not gone — it is sitting in the room on a newer socket.
    // Announcing a grace window now tells the survivor something false and tells
    // the returned peer that IT has lost its peer, which is the doubled banner
    // seen in practice. There is nobody left to inform.
    let slot_reclaimed = match my_slot {
        Some(i) => rooms.get(&code).is_some_and(|r| {
            r.member_tokens.get(i).is_some_and(|s| s.claims > claims_at_join)
        }),
        None => false, // no slot of our own (count-path member) — behave as before
    };

    if !peer_closed_us && !deliberate_leave && is_pair_member && !slot_reclaimed {
        if let Some(mut r) = rooms.get_mut(&code) {
            r.expires_at = Instant::now() + Duration::from_secs(RESUME_GRACE_SECS + 10);
        }
        // 23.7 Honest wait: tell the survivor the peer went silent and the grace
        // clock is running (cosmetic banner — old clients ignore unknown Text
        // markers, and it never changes session state on either side).
        let _ = tx.send((my_id, Message::Text(format!("BEEM-GRACE:{}", RESUME_GRACE_SECS))));
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
// Several tests here exist precisely to pin a constant — that a ceiling is the number
// that was decided, that a timeout still clears the keepalives it has to clear. Clippy
// reads an assertion over constants as pointless; here it is the entire point, and it
// is what fails the build if someone edits a constant without re-reasoning it.
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // TEST-S-017 — TURN REST credential matches coturn's use-auth-secret format.
    // Reference vector computed independently (Python hmac): base64(HMAC-SHA1(
    // "testsecret", "1700000000")). now_unix chosen so expiry = now + TTL = 1700000000.
    #[test]
    fn test_turn_credential_vector() {
        let now = 1700000000 - TURN_CRED_TTL_SECS;
        let (username, credential) = turn_credential(b"testsecret", now, "");
        assert_eq!(username, "1700000000", "username must be the unix expiry");
        assert_eq!(credential, "n4KuwizbZtngI4DON7Ws71orzs4=", "coturn REST HMAC format");
    }

    // TEST-S-018 — expiry is in the future and username parses as its timestamp.
    #[test]
    fn test_turn_credential_expiry_future() {
        let now = now_unix();
        let (username, _) = turn_credential(b"anything", now, "");
        let expiry: u64 = username.parse().expect("username is a unix timestamp");
        assert!(expiry > now, "expiry must be ahead of now");
        assert_eq!(expiry - now, TURN_CRED_TTL_SECS, "TTL exactly applied");
    }

    // The per-room tag must be stable for a code, different across codes,
    // and must not disclose the code itself.
    #[test]
    fn test_turn_room_tag_stable_and_distinct() {
        let a = turn_room_tag(b"s3cret", "123456");
        let b = turn_room_tag(b"s3cret", "123456");
        let c = turn_room_tag(b"s3cret", "123457");
        assert_eq!(a, b, "same secret + code -> same tag");
        assert_ne!(a, c, "different code -> different tag");
        assert_eq!(a.len(), 12, "6 bytes rendered as hex");
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(!a.contains("123456"), "tag must not leak the code");
        assert_ne!(a, turn_room_tag(b"other", "123456"), "tag is secret-bound");
    }

    // A tagged credential is "<expiry>:<tag>" and the HMAC covers the whole
    // username, which is exactly what coturn recomputes. Untagged stays byte-for
    // -byte what it was, so the pinned vector above still holds.
    #[test]
    fn test_turn_credential_tagged_username_shape() {
        let now = 1700000000 - TURN_CRED_TTL_SECS;
        let tag = turn_room_tag(b"testsecret", "424242");
        let (username, credential) = turn_credential(b"testsecret", now, &tag);
        assert_eq!(username, format!("1700000000:{}", tag));

        use base64::Engine;
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(b"testsecret").unwrap();
        mac.update(username.as_bytes());
        let want = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(credential, want, "HMAC covers the full tagged username");

        let (plain, _) = turn_credential(b"testsecret", now, "");
        assert_eq!(plain, "1700000000", "untagged form unchanged");
        assert_ne!(plain, username);
    }

    // The credential must outlive the longest possible room, or a session
    // loses its relay mid-transfer.
    #[test]
    fn test_turn_ttl_covers_a_full_session() {
        assert!(
            TURN_CRED_TTL_SECS >= MAX_SESSION_SECS,
            "TTL {} must cover a full {}s session",
            TURN_CRED_TTL_SECS,
            MAX_SESSION_SECS
        );
        assert!(TURN_CRED_TTL_SECS < 2 * 60 * 60, "no longer the old 2 h window");
    }

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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg(header: Option<&str>, trusted: &[&str]) -> ClientIpConfig {
        ClientIpConfig {
            header: header.map(|h| HeaderName::try_from(h).unwrap()),
            trusted: trusted.iter().map(|s| ip(s)).collect(),
        }
    }

    // TEST-S-007 — unconfigured, no header is read from any peer.
    #[test]
    fn test_client_ip_unconfigured_ignores_headers() {
        let c = cfg(None, &[]);
        let loopback = ip("127.0.0.1");
        let public = ip("203.0.113.1");

        assert_eq!(resolve_client_ip(&c, &HeaderMap::new(), loopback), loopback);
        assert_eq!(resolve_client_ip(&c, &HeaderMap::new(), public), public);

        // A header is present and declares another address; unset, it is not evidence.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), loopback);
        assert_eq!(resolve_client_ip(&c, &h, public), public);
    }

    // TEST-S-007b — a configured header is believed only from a trusted hop.
    #[test]
    fn test_client_ip_trusted_hop_gate() {
        let c = cfg(Some("cf-connecting-ip"), &[]);
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());

        // Loopback is always a trusted hop.
        assert_eq!(resolve_client_ip(&c, &h, ip("127.0.0.1")), ip("1.2.3.4"));
        // A public peer is not — direct exposure must not accept a spoofed header.
        assert_eq!(resolve_client_ip(&c, &h, ip("203.0.113.1")), ip("203.0.113.1"));

        // Declaring that proxy makes the same header count.
        let c = cfg(Some("cf-connecting-ip"), &["203.0.113.1"]);
        assert_eq!(resolve_client_ip(&c, &h, ip("203.0.113.1")), ip("1.2.3.4"));
        // …and only that one. A different public peer is still untrusted.
        assert_eq!(resolve_client_ip(&c, &h, ip("203.0.113.9")), ip("203.0.113.9"));

        // A header the operator did not name is never consulted.
        let c = cfg(Some("cf-connecting-ip"), &[]);
        let mut other = HeaderMap::new();
        other.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &other, ip("127.0.0.1")), ip("127.0.0.1"));
    }

    // TEST-S-007c — the walk runs right to left, past trusted hops only.
    #[test]
    fn test_client_ip_walks_right_to_left() {
        let c = cfg(Some("x-forwarded-for"), &["198.51.100.7"]);
        let loopback = ip("127.0.0.1");

        // Rightmost element is the trusted proxy; the client is the one before it.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.5, 198.51.100.7".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), ip("203.0.113.5"));

        // The attacker prepends addresses; the walk stops at the first untrusted hop,
        // so the leftmost value it chose can never win.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "9.9.9.9, 8.8.8.8, 203.0.113.5, 198.51.100.7".parse().unwrap(),
        );
        assert_eq!(resolve_client_ip(&c, &h, loopback), ip("203.0.113.5"));

        // Garbage to the left of the evidence stops the walk instead of forcing it on.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4, not-an-ip, 198.51.100.7".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), loopback);

        // Every element trusted → no client evidence at all → the peer.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "127.0.0.1, 198.51.100.7".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), loopback);

        // An appended source port is tolerated on either family.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.5:41234, 198.51.100.7".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), ip("203.0.113.5"));
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "[2001:db8::1]:443, 198.51.100.7".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), ip("2001:db8::1"));
    }

    // TEST-S-020 — a foreign page's socket is refused; our own and non-browsers pass.
    #[test]
    fn test_origin_allowed() {
        let none: Vec<String> = Vec::new();
        let host = |o: Option<&str>| {
            let mut h = HeaderMap::new();
            h.insert(http::header::HOST, "iris.example".parse().unwrap());
            if let Some(o) = o {
                h.insert("origin", o.parse().unwrap());
            }
            h
        };

        // Our own page.
        assert!(origin_allowed(&host(Some("https://iris.example")), &none));
        // Scheme is not ours to judge — TLS terminates at the front.
        assert!(origin_allowed(&host(Some("http://iris.example")), &none));
        // Case is not significant in an authority.
        assert!(origin_allowed(&host(Some("https://IRIS.EXAMPLE")), &none));

        // Any other site — the finding itself.
        assert!(!origin_allowed(&host(Some("https://evil.example")), &none));
        // A subdomain is a different origin, and a suffix match would have passed it.
        assert!(!origin_allowed(&host(Some("https://iris.example.evil.test")), &none));
        // `null` (sandboxed iframe, file://) is not our page.
        assert!(!origin_allowed(&host(Some("null")), &none));

        // A ported Origin against a portless Host is the SHIPPED nginx config on a
        // non-default port: `proxy_set_header Host $host` drops the port while the
        // browser keeps it. Refusing here would reject every real connection to that
        // deployment, so a portless side is treated as missing information.
        assert!(origin_allowed(&host(Some("https://iris.example:8443")), &none));

        // When both sides carry a port they must agree.
        let ported = |o: &str, h: &str| {
            let mut m = HeaderMap::new();
            m.insert(http::header::HOST, h.parse().unwrap());
            m.insert("origin", o.parse().unwrap());
            m
        };
        assert!(origin_allowed(&ported("https://iris.example:8443", "iris.example:8443"), &none));
        assert!(!origin_allowed(&ported("https://iris.example:9999", "iris.example:8443"), &none));

        // Userinfo must not be mistaken for the host — this one reads as `evil.test`.
        assert!(!origin_allowed(&host(Some("https://iris.example@evil.test")), &none));
        // …and the reverse still resolves to our host, so it stays allowed.
        assert!(origin_allowed(&host(Some("https://evil.test@iris.example")), &none));
        // A trailing root dot is the same name.
        assert!(origin_allowed(&host(Some("https://iris.example.")), &none));

        // A bracketed IPv6 literal: the colons inside are not a port separator.
        let v6 = |o: &str, h: &str| {
            let mut m = HeaderMap::new();
            m.insert(http::header::HOST, h.parse().unwrap());
            m.insert("origin", o.parse().unwrap());
            m
        };
        assert!(origin_allowed(&v6("http://[2001:db8::1]:8080", "[2001:db8::1]:8080"), &none));
        assert!(origin_allowed(&v6("http://[2001:db8::1]:8080", "[2001:db8::1]"), &none));
        assert!(!origin_allowed(&v6("http://[2001:db8::2]:8080", "[2001:db8::1]:8080"), &none));

        // No Origin at all: a non-browser client. Allowed deliberately — it could forge
        // any value anyway, so refusing only breaks honest tooling.
        assert!(origin_allowed(&host(None), &none));

        // Operator-declared extra origin, matched whole including scheme.
        let extra = vec!["https://app.example".to_string()];
        assert!(origin_allowed(&host(Some("https://app.example")), &extra));
        assert!(!origin_allowed(&host(Some("http://app.example")), &extra));

        // No Host to compare against → refuse rather than guess.
        let mut h = HeaderMap::new();
        h.insert("origin", "https://iris.example".parse().unwrap());
        assert!(!origin_allowed(&h, &none));
    }

    // TEST-S-021 — the slot is released by Drop, including when the upgrade callback
    // never runs and the closure holding it is simply dropped.
    #[test]
    fn test_concurrency_slot_releases_on_drop() {
        let map: Concurrent = Arc::new(DashMap::new());
        let addr = ip("203.0.113.5");

        let a = ConcurrencySlot::acquire(&map, addr).unwrap();
        let b = ConcurrencySlot::acquire(&map, addr).unwrap();
        assert_eq!(*map.get(&addr).unwrap(), 2);
        drop(a);
        assert_eq!(*map.get(&addr).unwrap(), 1);
        drop(b);
        assert_eq!(*map.get(&addr).unwrap(), 0);

        // The leak path: a closure captures the slot and is dropped without being called,
        // exactly as axum does when the upgrade fails.
        let slot = ConcurrencySlot::acquire(&map, addr).unwrap();
        assert_eq!(*map.get(&addr).unwrap(), 1);
        let never_called = move || {
            let _slot = slot;
        };
        drop(never_called);
        assert_eq!(*map.get(&addr).unwrap(), 0);

        // The cap still binds, and a refused acquire changes nothing.
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_PER_IP {
            held.push(ConcurrencySlot::acquire(&map, addr).expect("under cap"));
        }
        assert_eq!(*map.get(&addr).unwrap(), MAX_CONCURRENT_PER_IP);
        assert!(ConcurrencySlot::acquire(&map, addr).is_none());
        assert_eq!(*map.get(&addr).unwrap(), MAX_CONCURRENT_PER_IP);

        // Releasing one frees exactly one slot, so the cap is not a one-way ratchet.
        held.pop();
        assert_eq!(*map.get(&addr).unwrap(), MAX_CONCURRENT_PER_IP - 1);
        assert!(ConcurrencySlot::acquire(&map, addr).is_some());
    }

    // TEST-S-007f — v4-mapped v6 folds to v4, so one host cannot hold two identities
    // and a dual-stack loopback still reads as a trusted hop.
    #[test]
    fn test_client_ip_v4_mapped_folding() {
        assert_eq!(canonical_ip(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical_ip(ip("1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical_ip(ip("2001:db8::1")), ip("2001:db8::1"));

        // A mapped loopback peer must still be a trusted hop; `is_loopback()` alone
        // says false, which would silently collapse a dual-stack deployment.
        let c = cfg(Some("cf-connecting-ip"), &[]);
        assert!(c.is_trusted_hop(ip("::ffff:127.0.0.1")));
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, ip("::ffff:127.0.0.1")), ip("1.2.3.4"));

        // The same client in either representation resolves to one key.
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "::ffff:1.2.3.4".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, ip("127.0.0.1")), ip("1.2.3.4"));

        // A declared proxy is matched in either representation too.
        let c = cfg(Some("cf-connecting-ip"), &["::ffff:198.51.100.7"]);
        assert!(c.is_trusted_hop(ip("198.51.100.7")));
        assert_eq!(resolve_client_ip(&c, &h, ip("198.51.100.7")), ip("1.2.3.4"));

        // And an untrusted peer is still untrusted in either representation.
        assert_eq!(
            resolve_client_ip(&c, &h, ip("::ffff:203.0.113.1")),
            ip("203.0.113.1")
        );
    }

    // TEST-S-007d — an injected duplicate header line loses to the real hop's line.
    #[test]
    fn test_client_ip_duplicate_header_lines() {
        let c = cfg(Some("x-forwarded-for"), &[]);
        let loopback = ip("127.0.0.1");

        // Repeated lines are one list in arrival order, so the client's line sorts
        // first and the proxy's appended line is what the right-to-left walk reaches.
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "9.9.9.9".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.5".parse().unwrap());
        assert_eq!(resolve_client_ip(&c, &h, loopback), ip("203.0.113.5"));
    }

    // TEST-S-007e — both rate limiters key on that same identity, not the TCP peer.
    #[test]
    fn test_key_extractor_matches_resolver() {
        let c = Arc::new(cfg(Some("cf-connecting-ip"), &[]));
        let ex = ClientIpKeyExtractor(c.clone());

        let build = |peer: &str, hdr: Option<&str>| {
            let mut req = http::Request::builder().uri("/new");
            if let Some(v) = hdr {
                req = req.header("cf-connecting-ip", v);
            }
            let mut req = req.body(()).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip(peer), 12345)));
            req
        };

        // Two clients behind the same loopback proxy must land on separate keys —
        // that is the whole point of this check.
        let a = ex.extract(&build("127.0.0.1", Some("1.2.3.4"))).unwrap();
        let b = ex.extract(&build("127.0.0.1", Some("5.6.7.8"))).unwrap();
        assert_eq!(a, ip("1.2.3.4"));
        assert_eq!(b, ip("5.6.7.8"));
        assert_ne!(a, b);

        // No header from the proxy → the peer, same as the resolver.
        assert_eq!(ex.extract(&build("127.0.0.1", None)).unwrap(), ip("127.0.0.1"));

        // A request with no ConnectInfo cannot be keyed; it must error, never collapse
        // into a shared key.
        let bare = http::Request::builder().uri("/new").body(()).unwrap();
        assert!(ex.extract(&bare).is_err());
    }

    // TEST-S-008 — Room lifecycle: per-code attempt burn
    #[test]
    fn test_per_code_attempt_burn() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let code = "55555".to_string();
        let (tx, _) = broadcast::channel(256);
        rooms.insert(
            code.clone(),
            Room { tx, expires_at: Instant::now() + Duration::from_secs(60), attempts: 0, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false },
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
        let expired = Room { tx: tx.clone(), expires_at: now - Duration::from_secs(1), attempts: 0, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false };
        let fresh   = Room { tx,             expires_at: now + Duration::from_secs(1), attempts: 0, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false };

        assert!((expired.expires_at <= now), "expired room should be pruned");
        assert!(fresh.expires_at > now,      "fresh room should be kept");
    }

    // TEST-S-009b — sweeper must not GC a paired room with live WS subscribers
    // past its TTL, but must still hard-expire unpaired rooms so join codes
    // don't outlive their 60s window.
    #[test]
    fn test_sweeper_keeps_paired_expired_room_with_subscribers() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let rate_limits: RateLimits = Arc::new(DashMap::new());
        let concurrent: Concurrent = Arc::new(DashMap::new());
        let now = Instant::now();

        // 1. Expired, paired (attempts >= 2), receiver still alive → KEPT.
        let (tx_paired, rx_paired) = broadcast::channel::<(u64, Message)>(1);
        rooms.insert(
            "paired-live".to_string(),
            Room { tx: tx_paired, expires_at: now - Duration::from_secs(1), attempts: 2, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false },
        );

        // 2. Expired, paired, zero receivers (dropped immediately) → PRUNED.
        let (tx_paired_dead, rx_paired_dead) = broadcast::channel::<(u64, Message)>(1);
        drop(rx_paired_dead);
        rooms.insert(
            "paired-dead".to_string(),
            Room { tx: tx_paired_dead, expires_at: now - Duration::from_secs(1), attempts: 2, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false },
        );

        // 3. Expired, unpaired (attempts < 2), even with a live receiver → PRUNED.
        let (tx_unpaired, rx_unpaired) = broadcast::channel::<(u64, Message)>(1);
        rooms.insert(
            "unpaired-live".to_string(),
            Room { tx: tx_unpaired, expires_at: now - Duration::from_secs(1), attempts: 1, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false },
        );

        // 4. Fresh (unexpired) room → KEPT regardless of attempts/receivers.
        let (tx_fresh, _) = broadcast::channel::<(u64, Message)>(1);
        rooms.insert(
            "fresh".to_string(),
            Room { tx: tx_fresh, expires_at: now + Duration::from_secs(60), attempts: 0, resumes: 0, member_tokens: Vec::new(), relay_bytes: 0, budget_warned: false },
        );

        sweep_maps(&rooms, &rate_limits, &concurrent, now);

        assert!(rooms.get("paired-live").is_some(),   "paired room with live subscriber must survive expiry");
        assert!(rooms.get("paired-dead").is_none(),   "paired room with zero subscribers must be pruned");
        assert!(rooms.get("unpaired-live").is_none(), "unpaired room must hard-expire even with a live subscriber");
        assert!(rooms.get("fresh").is_some(),         "unexpired room must always survive");

        // Keep receivers alive through the assertions above so receiver_count() > 0 held.
        drop(rx_paired);
        drop(rx_unpaired);
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

    // TEST-S-012b — Sweeper must not erase ban-ladder memory (S3-02 regression).
    // An entry whose ONLY live state is cooldown trips inside BAN_COOLDOWN_WINDOW
    // (attempts stale, cooldown expired, no ban) still counts toward the
    // 3-trips→30-min-ban escalation and must survive the sweep; once the last
    // trip ages past the window the entry is dead and must be GC'd.
    #[test]
    fn test_sweeper_keeps_cooldown_history() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let rate_limits: RateLimits = Arc::new(DashMap::new());
        let concurrent: Concurrent = Arc::new(DashMap::new());
        let now = Instant::now() + Duration::from_secs(BAN_COOLDOWN_WINDOW_SECS * 2);

        let ladder_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mut ladder = RateLimitState::default();
        // Two trips well inside the 1 h escalation window; nothing else live.
        ladder.cooldown_history.push_back(now - Duration::from_secs(300));
        ladder.cooldown_history.push_back(now - Duration::from_secs(120));
        rate_limits.insert(ladder_ip, ladder);

        let stale_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let mut stale = RateLimitState::default();
        // Last trip older than the window: no escalation can use it any more.
        stale.cooldown_history.push_back(now - Duration::from_secs(BAN_COOLDOWN_WINDOW_SECS + 60));
        rate_limits.insert(stale_ip, stale);

        sweep_maps(&rooms, &rate_limits, &concurrent, now);

        assert!(rate_limits.get(&ladder_ip).is_some(), "in-window cooldown history must survive the sweep");
        assert_eq!(rate_limits.get(&ladder_ip).unwrap().cooldown_history.len(), 2, "ladder memory must be intact");
        assert!(rate_limits.get(&stale_ip).is_none(), "out-of-window history is dead state and must be GC'd");
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

    // TEST-S-035 — 25.3 a pair member may relay binary only: any Text frame that
    // is not the (separately consumed) BEEM-LEAVE marker is dropped, so a modified
    // peer cannot inject BEEM-TOKEN / BEEM-CLOSE / BEEM-BUDGET into its partner.
    #[test]
    fn test_member_relays_binary_only() {
        assert!(relayable_from_member(&Message::Binary(vec![0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
        assert!(relayable_from_member(&Message::Binary(Vec::new())));
        assert!(!relayable_from_member(&Message::Text("BEEM-TOKEN:00000000000000000000000000000000".into())));
        assert!(!relayable_from_member(&Message::Text("BEEM-CLOSE:4006:".into())));
        assert!(!relayable_from_member(&Message::Text("BEEM-BUDGET:90".into())));
        assert!(!relayable_from_member(&Message::Text("BEEM-GRACE:30".into())));
        assert!(!relayable_from_member(&Message::Text("BEEM-BACK".into())));
        assert!(!relayable_from_member(&Message::Text(String::new())));
        // BEEM-LEAVE is handled by the rx arm before the relay arm; if it ever
        // reached the relay arm it must still not be forwarded as data.
        assert!(!relayable_from_member(&Message::Text("BEEM-LEAVE".into())));
        // Control frames never reach the relay arm either, but the predicate
        // must not accidentally admit them.
        assert!(!relayable_from_member(&Message::Ping(Vec::new())));
        assert!(!relayable_from_member(&Message::Pong(Vec::new())));
        assert!(!relayable_from_member(&Message::Close(None)));
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

    // TEST-S-015 — mobile-resume joins must not spend the brute-force budget
    // (observed in practice: ~3 picker cycles burned the room mid-transfer).
    #[test]
    fn test_is_resume_join() {
        // Pairing itself is never a resume.
        assert!(!is_resume_join(0, 0)); // sender joins fresh room
        assert!(!is_resume_join(1, 1)); // receiver joins, sender waiting
        // Post-pairing rejoin with one survivor = the classic picker resume.
        assert!(is_resume_join(2, 1));
        assert!(is_resume_join(4, 1)); // later resumes in a long session
        // Both sides backgrounded at once (phone↔phone) — still a resume.
        assert!(is_resume_join(2, 0));
        // Attacker probing an ACTIVE session: room is full → counted path.
        assert!(!is_resume_join(2, 2));
        assert!(!is_resume_join(3, 2));
    }

    // TEST-S-016 — a long session's resume cycles never reach the burn line,
    // while attacker-style joins still do. Simulates the counting logic of
    // pair() against the realistic scenario (pair + many picker cycles).
    #[test]
    fn test_resume_cycles_do_not_burn_room() {
        let mut attempts: u32 = 0;
        let mut resumes: u32 = 0;
        // Legitimate pairing: sender then receiver — counted.
        for receiver_count in [0usize, 1] {
            assert!(!is_resume_join(attempts, receiver_count));
            attempts += 1;
        }
        // 20 file-picker / screen-lock cycles: survivor holds the slot open.
        for _ in 0..20 {
            assert!(is_resume_join(attempts, 1), "resume misclassified");
            resumes += 1;
            assert!(resumes <= MAX_RESUME_JOINS, "resume cap hit too early");
        }
        // attempts never moved past the pair — room alive.
        assert!(attempts < MAX_CODE_ATTEMPTS);
        // Attacker joins during an ACTIVE session (2 subscribers): counted,
        // and the 5th total attempt burns the room as before.
        for _ in 0..3 {
            assert!(!is_resume_join(attempts, 2));
            attempts += 1;
        }
        assert!(attempts >= MAX_CODE_ATTEMPTS, "brute-force cap lost its teeth");
    }

    // TEST-S-020 — silence detection. A phone that leaves WiFi blackholes its
    // TCP, so nothing ever closes the socket; without this the task parked for the
    // full session hour and the survivor's UI claimed "Connected" the whole time.
    #[test]
    fn test_peer_is_silent() {
        let over = Duration::from_secs(PEER_SILENCE_TIMEOUT_SECS + 1);
        let under = Duration::from_secs(PEER_SILENCE_TIMEOUT_SECS - 1);

        // The case this exists for: paired room, peer stopped answering.
        assert!(peer_is_silent(2, over), "paired + silent past the timeout → reap");

        // A live peer keeps its 10 s T_KEEPALIVE flowing, so it is never silent long.
        assert!(!peer_is_silent(2, under), "paired but recently heard from → keep");

        // A sender waiting alone for its receiver sends nothing while the owner reads
        // the code out loud. Reaping that would break normal pairing; CODE_TTL_SECS
        // already bounds an abandoned room.
        assert!(!peer_is_silent(1, over), "unpaired sender waiting → never reaped");
        assert!(!peer_is_silent(0, over), "empty room → never reaped");

        // Exactly at the boundary is not yet silent — the comparison is strict.
        assert!(
            !peer_is_silent(2, Duration::from_secs(PEER_SILENCE_TIMEOUT_SECS)),
            "boundary is inclusive of 'still alive'"
        );

        // The timeout must clear several client keepalives (10 s each), or a
        // healthy but quiet client behind a tunnel that strips Pong would be reaped.
        // The client's own 30 s soft warning must also fit inside it — this timeout
        // ends the connection, and the authoritative signal must never be the fast one.
        assert!(
            PEER_SILENCE_TIMEOUT_SECS > 40,
            "must survive several missed 10 s client keepalives and outlast the client's 30 s warning"
        );
        // …and must fire well inside the session cap, or it changes nothing.
        assert!(PEER_SILENCE_TIMEOUT_SECS < MAX_SESSION_SECS);
    }

    // TEST-S-019 — only pair members may broadcast into a room (BEEM-LEAVE
    // teardown + relay injection). An observer joining a live, full session is not a
    // pair member, so its frames — including BEEM-LEAVE — are dropped by the gate.
    // Mirrors the exact membership expression used at the `pair()` call site:
    // `attempt_before < 2 || resume_admitted(both_slots_minted, attempt_before, rc)`.
    #[test]
    fn test_is_pair_member_gates_observer() {
        let member = |slots_minted: bool, a: u32, rc: usize| a < 2 || resume_admitted(slots_minted, a, rc);

        // The two legitimate joins are always pair members, before or after both
        // slots are minted — attempt_before < 2 can, in practice, never coincide
        // with both_slots_minted (minting requires two prior successful joins,
        // each of which already advanced attempts past 2), but the gate must not
        // depend on that invariant to do the right thing either way.
        assert!(member(false, 0, 0), "sender joins fresh room");
        assert!(member(false, 1, 1), "receiver joins, sender waiting");
        assert!(member(true, 0, 0), "first join is always a member regardless");
        // Mobile resume before both slots exist: at most one survivor holds the
        // slot open — the pre-token-system fallback path.
        assert!(member(false, 2, 1), "resume — survivor holding the grace slot");
        assert!(member(false, 4, 0), "both-backgrounded (phone<->phone) resume");
        // Third-party observer probing a live session (both peers subscribed) is NOT
        // a pair member — its BEEM-LEAVE and relayed markers must be dropped.
        assert!(!member(false, 2, 2), "observer, full room");
        assert!(!member(false, 3, 2), "second observer, full room");
        assert!(!member(false, 2, 3), "observer while a third already present");
        // Consistency with the resume classifier: a counted (non-resume) join into a
        // full room is exactly the observer case the relay gate must reject.
        assert!(!is_resume_join(2, 2) && !member(false, 2, 2));
    }

    // TEST-S-029 — the count-based resume fallback must stop granting membership
    // once a room has minted a token for both legitimate members. Before that point,
    // a stale dead-but-not-closed subscriber can hold receiver_count down and let a
    // tokenless stranger read as "the survivor's resume" — the exact headcount that
    // used to admit a real resume must now be refused once both tokens exist, closing
    // the eviction path a code-holder had into a live, fully-established session.
    #[test]
    fn test_resume_admitted_requires_open_slot() {
        // Before both slots are minted, the plain count heuristic still applies —
        // unchanged behaviour for a room still forming or one that lost a token.
        assert!(resume_admitted(false, 2, 1), "pre-token resume — survivor holding the slot");
        assert!(resume_admitted(false, 2, 0), "pre-token resume — both backgrounded at once");
        assert!(!resume_admitted(false, 2, 2), "still not a resume with both peers live");

        // Once both slots are minted, the SAME favourable headcount that used to
        // grant membership must no longer be enough — a token is now required.
        assert!(!resume_admitted(true, 2, 1), "full room, no token — must not admit");
        assert!(!resume_admitted(true, 2, 0), "full room, no token — must not admit");
        assert!(!resume_admitted(true, 4, 1), "still refused arbitrarily later in the session");

        // Not a resume at all (attempt_before < 2) is out of scope for this predicate;
        // the call site ORs it in separately and unconditionally.
        assert!(!resume_admitted(true, 0, 0));
        assert!(!resume_admitted(false, 0, 0));
    }

    // TEST-S-030 — reaching the resume cap must always refuse the join, but must
    // only ever destroy the room when nobody live is left in it. Regression for the
    // audit finding where a room's own 65th legitimate resume — resumes never reset —
    // deleted the room out from under its still-connected partner, and a tokenless
    // attacker could reach the same destructive path deliberately.
    #[test]
    fn test_burn_room_on_resume_cap_does_not_evict_a_live_pair() {
        // At and below the cap: never burned, whatever the headcount.
        assert!(!burn_room_on_resume_cap(MAX_RESUME_JOINS, 0));
        assert!(!burn_room_on_resume_cap(MAX_RESUME_JOINS, 2));

        // Past the cap with a live subscriber — refused, but the room survives so the
        // still-connected partner is never stranded.
        assert!(!burn_room_on_resume_cap(MAX_RESUME_JOINS + 1, 2), "a live pair must never be evicted");
        assert!(!burn_room_on_resume_cap(MAX_RESUME_JOINS + 1, 1), "a survivor holding the slot must not be evicted");

        // Past the cap with nobody left in the room — safe to reclaim.
        assert!(burn_room_on_resume_cap(MAX_RESUME_JOINS + 1, 0), "an empty room is still reclaimed on the cap");
    }

    // TEST-S-021 — slot_index, the membership proof gate. A peer that
    // reconnects after a network switch (new WS, old one dead but not yet
    // closed) presents this to prove it's still the same pair member, without
    // relying on `receiver_count` arithmetic that a stale connection can throw
    // off. An absent, blank, or simply wrong token must never pass — and a
    // room that never minted a token (empty list) must never accidentally
    // "match" a plausible-looking guess.
    #[test]
    fn test_slot_index() {
        let tokens = vec![
            MemberSlot { token: "a".repeat(32), claims: 0 },
            MemberSlot { token: "b".repeat(32), claims: 0 },
        ];
        assert_eq!(slot_index(&tokens, Some(&"a".repeat(32))), Some(0), "known token must match");
        assert_eq!(slot_index(&tokens, Some(&"b".repeat(32))), Some(1), "…and resolve to ITS slot");
        assert!(slot_index(&tokens, Some(&"c".repeat(32))).is_none(), "wrong token must not match");
        assert!(slot_index(&tokens, None).is_none(), "no token presented must never match");
        assert!(slot_index(&tokens, Some("")).is_none(), "blank token must never match");
        // Empty token list (room never minted one yet) — even a token that looks
        // exactly like a real one must not match; there is nothing to match against.
        assert!(slot_index(&[], Some(&"a".repeat(32))).is_none(), "empty token list must never match");
    }

    // TEST-S-024 — room retention and room joinability, and the relationship
    // between them. The bug this pins is not a wrong value, it is two copies of
    // one rule that drifted: `pair()` refused rooms the sweeper was deliberately
    // keeping alive for a resume, so every reconnect past CODE_TTL_SECS got
    // CLOSE_CODE_MISSING on a session that was working fine.
    #[test]
    fn test_room_lifetime() {
        // Inside the TTL nothing changed — no token needed, exactly as before.
        assert!(room_joinable(true, false, 0), "fresh room, no token, must still join");
        assert!(room_retained(true, 0, 0), "fresh room is kept regardless");

        // Past the TTL with a live pair: THE regression. Retained AND joinable by
        // a token holder — these two must agree or the room is kept for nobody.
        assert!(room_retained(false, 2, 1), "paired + live must survive the sweeper");
        assert!(room_joinable(false, true, 1), "…and a token holder must get back IN");

        // Past the TTL WITHOUT a token: refused. This is stricter than the old
        // behaviour inside the TTL — after 60 s the code alone buys nothing, so a
        // guesser can no longer spend a live room's MAX_CODE_ATTEMPTS budget.
        assert!(!room_joinable(false, false, 1), "right code, no token, past TTL → refused");

        // Nobody left to resume with: a token cannot resurrect an empty room.
        assert!(!room_joinable(false, true, 0), "token but no live member → refused");
        assert!(!room_retained(false, 2, 0), "…and the sweeper reclaims it");

        // Unpaired rooms still hard-expire at CODE_TTL_SECS. That is the actual
        // brute-force control and it must not be weakened by any of the above.
        assert!(!room_retained(false, 1, 1), "never-paired room still expires");

        // The invariant that was violated: anything retained FOR a resume must be
        // reachable by the credential a resume presents. Retained-but-unjoinable
        // is a room held open for nobody.
        for &rc in &[1usize, 2] {
            assert!(
                !room_retained(false, 2, rc) || room_joinable(false, true, rc),
                "retained for resume ⇒ a token holder can join (rc={})", rc
            );
        }
    }

    // TEST-S-023 — a departing connection must be able to tell "my peer is
    // gone" from "my peer is already back on a new socket". The zombie case is
    // the whole reason: the phone rejoined at ~10 s and the dead connection was
    // not reaped until ~45 s, so its exit broadcast a grace window into a room
    // that was working — and the returned phone was told it had lost its peer.
    //
    // The discriminator is per-slot on purpose. The second half of this test is
    // the case a room-wide epoch would get wrong: B resumes, then A genuinely
    // dies. A's slot was never re-claimed, so A must still announce.
    #[test]
    fn test_slot_reclaim() {
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        let mut slots = vec![
            MemberSlot { token: a.clone(), claims: 0 },
            MemberSlot { token: b.clone(), claims: 0 },
        ];

        let a_idx = slot_index(&slots, Some(&a)).expect("minted token must resolve to its slot");
        assert_eq!(a_idx, 0, "slot_index must return the matching slot, not just a bool");
        let a_claims_at_join = slots[a_idx].claims;

        // Nothing has happened yet: A's exit still has something to announce.
        assert!(slots[a_idx].claims <= a_claims_at_join, "untouched slot is not reclaimed");

        // A returns on a new socket, presenting the same token.
        let returning = slot_index(&slots, Some(&a)).expect("a returning peer resolves its slot");
        slots[returning].claims += 1;
        assert!(slots[a_idx].claims > a_claims_at_join,
                "the old connection must see its own slot was refilled and stay quiet");

        // The returning connection itself now holds the newer baseline, so when
        // IT eventually leaves for real it announces normally.
        let a2_claims_at_join = slots[returning].claims;
        assert!(slots[returning].claims <= a2_claims_at_join,
                "the live connection must not silence its own genuine departure");

        // B never resumed. A's traffic must not have touched B's slot — this is
        // what a room-wide counter would have broken.
        let b_idx = slot_index(&slots, Some(&b)).expect("b's slot is independent");
        assert_eq!(slots[b_idx].claims, 0, "one member resuming must not silence the other");
    }

    // TEST-S-022 — ct_eq, the constant-time byte comparison slot_index is
    // built on. Real-world case it defends: a membership gate is exactly the
    // kind of check that should never be written as a short-circuiting `==`
    // even when (as here) the practical timing signal is negligible over a
    // network — the point is to foreclose the question, not to prove exploitability.
    #[test]
    fn test_ct_eq() {
        assert!(ct_eq("abcdef0123456789", "abcdef0123456789"), "equal strings must match");
        assert!(!ct_eq("abcdef0123456789", "abcdef012345678x"), "same length, different content must not match");
        assert!(!ct_eq("short", "longerstring"), "different length must not match");
        assert!(!ct_eq("", "a"), "empty vs non-empty must not match");
        assert!(ct_eq("", ""), "two empty strings must match");
    }

    // TEST-S-025 — the relay ceiling's decision function.
    // Real-world case it defends: a real deployment's lane test measured whole files
    // crossing the WS relay while the byte counters were compared to nothing. The
    // ordering that matters here is that the warning fires strictly BEFORE the close
    // and exactly once, so a user is told before a session is ended under them.
    #[test]
    fn test_relay_budget_state() {
        let limit = 1000u64;
        assert_eq!(relay_budget_state(0, limit, false), RelayBudget::Ok);
        assert_eq!(relay_budget_state(799, limit, false), RelayBudget::Ok, "below 80% is silent");
        assert_eq!(relay_budget_state(800, limit, false), RelayBudget::Warn, "80% warns");
        assert_eq!(relay_budget_state(999, limit, false), RelayBudget::Warn, "still only a warning");
        assert_eq!(relay_budget_state(950, limit, true), RelayBudget::Ok, "one warning per session, not per batch");
        assert_eq!(relay_budget_state(1000, limit, true), RelayBudget::Exceeded, "the ceiling closes");
        assert_eq!(relay_budget_state(1000, limit, false), RelayBudget::Exceeded, "exceeded outranks a pending warning");
        assert_eq!(relay_budget_state(u64::MAX, limit, true), RelayBudget::Exceeded);
        // 0 disables the ceiling — the self-hoster escape hatch, and it must not be
        // reachable by accident: a normal limit can never behave like this.
        assert_eq!(relay_budget_state(u64::MAX, 0, false), RelayBudget::Ok, "limit 0 disables");
    }

    // TEST-S-026 — the shipped ceiling is the number that was decided, and it
    // cannot silently drift into breaking normal use. Six max-size files, doubled
    // because the relay is charged for every byte twice, in and out.
    #[test]
    fn test_relay_budget_constants() {
        assert_eq!(MAX_RELAY_BYTES, 12 * 1024 * 1024 * 1024, "12 GiB counted per session");
        assert!(RELAY_WARN_PCT > 0 && RELAY_WARN_PCT < 100, "a warning must precede the close");
        assert!(MAX_RELAY_BYTES / 100 * RELAY_WARN_PCT < MAX_RELAY_BYTES);
        // A 1 GiB transfer costs ~2 GiB of budget. If this ever fails, the ceiling has
        // been lowered to where an ordinary pair of large transfers would be cut off.
        assert!(MAX_RELAY_BYTES >= 6 * 2 * 1024 * 1024 * 1024, "must clear six 1 GiB relayed files");
        // The batch must be small enough that the ceiling is honoured closely, and it is
        // pointless if it exceeds the budget itself.
        assert!(RELAY_FLUSH_BYTES < MAX_RELAY_BYTES / 100, "batching must stay under 1% of the ceiling");
    }

    // TEST-S-031 — a slow-draining subscriber can pin at most ROOM_CHANNEL_CAPACITY
    // full-size frames in memory, regardless of how long the room lives. Pins the actual
    // byte ceiling so a future capacity bump cannot silently regress back toward the
    // ~400 MiB/room the finding reported without this assertion moving too.
    #[test]
    fn test_room_channel_capacity_bounds_pinned_memory() {
        let per_room_ceiling = ROOM_CHANNEL_CAPACITY as u64 * MAX_WS_FRAME as u64;
        assert!(per_room_ceiling <= 64 * 1024 * 1024, "a slow subscriber must not pin more than ~64 MiB/room");
        // Across every room MAX_CONCURRENT_PER_IP allows one address to hold open at once
        // (2 sockets/room, so /2 rooms), the total pin must stay a small fraction of the
        // 12 GiB session ceiling — affordable to the operator, not a second exhaustion path.
        let per_address_ceiling = per_room_ceiling * (MAX_CONCURRENT_PER_IP as u64 / 2);
        assert!(per_address_ceiling < MAX_RELAY_BYTES / 20, "must stay well under the relay ceiling itself");
    }

    // TEST-S-032 — the monitor collector must reject a forged `t_srv` and must
    // never let a raw control byte survive into the batch it prints/logs. Both a
    // real JSON parse and a hand-crafted "valid JSON but not the shape we want"
    // attempt are covered so a future edit can't quietly weaken either half.
    #[test]
    fn test_build_monitor_batch_rejects_forgery_and_garbage() {
        // A well-formed, honest line survives and gets the server's t_srv prepended
        // as the first key.
        let out = build_monitor_batch(r#"{"kind":"ping"}"#, 42);
        assert_eq!(out, "{\"t_srv\":42,\"kind\":\"ping\"}\n");

        // A line that already carries t_srv is a forgery attempt — refused outright,
        // not "fixed up" by overwriting it, so nothing this attacker wrote reaches
        // either sink.
        let out = build_monitor_batch(r#"{"t_srv":999,"kind":"ping"}"#, 42);
        assert_eq!(out, "", "a forged t_srv must drop the whole line");

        // Not a JSON object at all (array, bare string, bare number) — dropped.
        assert_eq!(build_monitor_batch(r#"["x"]"#, 42), "");
        assert_eq!(build_monitor_batch(r#""just a string""#, 42), "");
        assert_eq!(build_monitor_batch("42", 42), "");

        // A raw C0 control byte breaks JSON string syntax (RFC 8259 requires it be
        // escaped), so a line trying to smuggle one in verbatim fails to parse and
        // is dropped whole — it can never reach the terminal or the log file.
        let hostile = "{\"kind\":\"\x1b[2Jpwned\"}".to_string();
        assert_eq!(build_monitor_batch(&hostile, 42), "", "a raw control byte must not parse");

        // The escaped, inert TEXT form of the same code point (the six ASCII
        // characters backslash, u, 0, 0, 1, b — built via char codes below so this
        // source file itself never contains a raw control byte) is ordinary JSON
        // and is let through: the defence is against the literal byte reaching a
        // sink, not against the character it represents appearing escaped.
        let esc_seq: String = [92u8 as char, 'u', '0', '0', '1', 'b'].iter().collect();
        let escaped = format!("{{\"kind\":\"{}[2Jpwned\"}}", esc_seq);
        let out = build_monitor_batch(&escaped, 42);
        assert!(out.contains(&esc_seq), "escaped control sequences remain ordinary JSON text");
        assert!(!out.chars().any(|c| c == (0x1bu32 as u8 as char)), "the literal byte must never appear in the output");

        // Garbage that merely starts with { and ends with } (what the old sniff
        // accepted) but isn't valid JSON — dropped.
        assert_eq!(build_monitor_batch("{not json}", 42), "");

        // Multiple lines: only the well-formed, non-forged ones survive, each on its
        // own line with the same t_srv.
        let body = "{\"a\":1}\n{\"t_srv\":1,\"a\":2}\nnot json\n{\"a\":3}";
        let out = build_monitor_batch(body, 7);
        assert_eq!(out, "{\"t_srv\":7,\"a\":1}\n{\"t_srv\":7,\"a\":3}\n");

        // Empty input produces empty output — the caller treats that as "nothing to do".
        assert_eq!(build_monitor_batch("", 42), "");
        assert_eq!(build_monitor_batch("   \n  \n", 42), "");
    }

    // TEST-S-027 — a third party who knows a live code must not be able to evict the
    // pair. Reaching the attempt cap refuses the connection either way; only an EMPTY
    // room is destroyed. Regression for the audit finding where three ordinary
    // connections burned a live room, which both locked the pair out of resuming and
    // stripped the session's relay ceiling (a charge against a missing room used to
    // answer Ok).
    #[test]
    fn test_attempt_cap_does_not_evict_a_live_pair() {
        // Below the cap: never burned, whatever the headcount.
        assert!(!burn_room_on_cap(MAX_CODE_ATTEMPTS - 1, 0));
        assert!(!burn_room_on_cap(MAX_CODE_ATTEMPTS - 1, 2));

        // At and past the cap with the pair live — refused, but the room survives.
        assert!(!burn_room_on_cap(MAX_CODE_ATTEMPTS, 2), "a live pair must never be evicted");
        assert!(!burn_room_on_cap(MAX_CODE_ATTEMPTS, 1), "a survivor holding the slot must not be evicted");
        assert!(!burn_room_on_cap(MAX_CODE_ATTEMPTS + 10, 2), "still no eviction however long it goes on");

        // At the cap with nobody in it — brute-force defence still burns it.
        assert!(burn_room_on_cap(MAX_CODE_ATTEMPTS, 0), "an empty room is still burned on the cap");

        // The room really does survive the sweeper afterwards, so the pair can resume:
        // room_retained keeps a paired room with live subscribers past its TTL.
        assert!(room_retained(false, MAX_CODE_ATTEMPTS, 2), "burned-at attempts, still retained while live");
    }

    // TEST-S-028 — the relay ceiling must fail closed. Losing the room must never be
    // read as "no limit"; that was the second half of the same finding.
    #[test]
    fn test_relay_budget_fails_closed_without_a_room() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let code = "424242".to_string();
        assert!(rooms.get_mut(&code).is_none(), "precondition: no room for this code");

        // Mirrors the None arm of relay_charge's lookup.
        let verdict = match rooms.get_mut(&code) {
            Some(mut r) => {
                r.relay_bytes = r.relay_bytes.saturating_add(RELAY_FLUSH_BYTES);
                relay_budget_state(r.relay_bytes, MAX_RELAY_BYTES, r.budget_warned)
            }
            None => RelayBudget::Exceeded,
        };
        assert_eq!(verdict, RelayBudget::Exceeded, "a missing room must end the session, not uncap it");
    }

    // TEST-S-033 — F10: a connection's uncharged tail (bytes relayed since the last
    // RELAY_FLUSH_BYTES flush) must still be billed to the room when the connection
    // exits, however it exits. Mirrors the post-loop fold in `pair()` directly, the
    // same style TEST-S-028 above uses for relay_charge's lookup.
    #[test]
    fn test_relay_tail_is_folded_on_exit() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let code = "424242".to_string();
        let (tx, _) = broadcast::channel::<(u64, Message)>(1);
        rooms.insert(
            code.clone(),
            Room {
                tx,
                expires_at: Instant::now() + Duration::from_secs(60),
                attempts: 2,
                resumes: 0,
                member_tokens: Vec::new(),
                relay_bytes: 10 * 1024 * 1024, // some already flushed, from earlier batches
                budget_warned: false,
            },
        );

        // A connection relayed 30 MiB since its last flush, then hit a bare `break`
        // (deadline, silence reap, peer close — the exit path does not matter) with
        // that amount still under RELAY_FLUSH_BYTES and therefore never flushed.
        let unflushed: u64 = 30 * 1024 * 1024;

        // Mirrors the post-loop fold exactly.
        if unflushed > 0 {
            if let Some(mut r) = rooms.get_mut(&code) {
                r.relay_bytes = r.relay_bytes.saturating_add(unflushed);
            }
        }

        assert_eq!(
            rooms.get(&code).unwrap().relay_bytes,
            40 * 1024 * 1024,
            "the tail must land in the room's counter exactly once, on top of what was already flushed"
        );
    }

    // TEST-S-034 — F10, the other half: an already-gone room must not panic or
    // silently invent state. Best-effort exactly like every other post-loop room
    // lookup in `pair()` (the resume-grace bump a few lines below it, for example).
    #[test]
    fn test_relay_tail_fold_is_best_effort_without_a_room() {
        let rooms: Rooms = Arc::new(DashMap::new());
        let code = "424242".to_string();
        let unflushed: u64 = 30 * 1024 * 1024;

        // Must not panic, and must leave no trace of a room that was never there.
        if unflushed > 0 {
            if let Some(mut r) = rooms.get_mut(&code) {
                r.relay_bytes = r.relay_bytes.saturating_add(unflushed);
            }
        }
        assert!(rooms.get(&code).is_none(), "folding into a missing room must not create one");
    }
}
