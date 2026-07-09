# Iris — self-host image (Phase 17.1)
#
# Three stages, mirroring the exact order Makefile's `deploy` target encodes
# (wasm -> sri -> server), because the SRI hashes stamped into app.js /
# index.html are computed FROM the freshly built wasm — building them out of
# order produces a client that fails its own integrity check.

# ---- Stage 1: build the WASM crypto module ----------------------------------
FROM rust:1.92-slim AS wasm-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# Pinned, checksum-verified wasm-pack install (same version + hash as
# .github/workflows/test.yml — avoids curl|sh per 16.5.1).
RUN WP_VERSION=v0.14.0 && \
    WP_SHA256=278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d && \
    WP_DIR=wasm-pack-${WP_VERSION}-x86_64-unknown-linux-musl && \
    curl -sSfL -o /tmp/wasm-pack.tar.gz \
        "https://github.com/rustwasm/wasm-pack/releases/download/${WP_VERSION}/${WP_DIR}.tar.gz" && \
    echo "${WP_SHA256}  /tmp/wasm-pack.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/wasm-pack.tar.gz -C /tmp && \
    install -m 755 "/tmp/${WP_DIR}/wasm-pack" /usr/local/cargo/bin/wasm-pack

WORKDIR /src
COPY . .
RUN cd crypto && wasm-pack build --target web --out-dir ../client/pkg

# ---- Stage 2: build the server binary + stamp SRI ----------------------------
FROM rust:1.92-slim AS server-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
COPY --from=wasm-builder /src/client/pkg client/pkg

# Rewrites client/app.js + client/index.html + HASHES.md in place so the
# binary below ships a client whose integrity hashes actually match.
RUN bash scripts/build-sri.sh

RUN cd server && cargo build --locked --release

# ---- Stage 3: minimal runtime -------------------------------------------------
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin iris

# Binary and client/ are siblings under /app so the server's hardcoded
# `ServeDir::new("../client")` (server/src/main.rs) resolves correctly.
WORKDIR /app/server
COPY --from=server-builder /src/server/target/release/iris-server ./iris-server
COPY --from=server-builder /src/client ../client

USER iris
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ || exit 1

ENTRYPOINT ["./iris-server"]
