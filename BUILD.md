# Building Iris

## Requirements

- Rust `1.92.0` — pinned via `rust-toolchain.toml`, installed automatically by rustup
- `wasm-pack` — install once: `cargo install wasm-pack`
- `openssl` CLI — for SRI hash generation (`openssl dgst -sha384`)

## Steps

**1. Build the WASM crypto module**

```sh
cd crypto
wasm-pack build --target web --mode no-install
cd ..
```

Output: `client/pkg/` — `iris_crypto.js` + `iris_crypto_bg.wasm`

**2. Inject SRI hashes**

```sh
bash scripts/build-sri.sh
```

This reads `client/app.js`, `client/pkg/iris_crypto.js`, and `client/pkg/iris_crypto_bg.wasm`, computes SHA-384 for each, writes hashes into `client/index.html` and `client/app.js`, and regenerates `HASHES.md`.

**3. Build the server**

```sh
cd server
cargo build --locked --release
cd ..
```

Output: `server/target/release/iris-server`

**4. Run**

```sh
./server/target/release/iris-server
```

Server listens on `127.0.0.1:8080` by default.

## Verifying reproducibility

Two clean checkouts on the same OS and Rust version should produce byte-identical WASM. To verify:

```sh
sha384sum client/pkg/iris_crypto_bg.wasm
```

Compare against the `wasm` row in `HASHES.md`. They must match exactly.

The server binary is not guaranteed byte-identical across different OS/linker versions — only the WASM is pinned in `HASHES.md` because that is what the browser executes.

## Running tests

```sh
# Server unit tests
cd server && cargo test && cd ..

# WASM crypto tests
cd crypto && wasm-pack test --headless --firefox && cd ..

# Browser integration tests
cd tests/browser && npm install && npx playwright install chromium && npx playwright test && cd ../..
```
