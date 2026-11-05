# Building Iriszip

## Requirements

- Rust `1.92.0` — pinned via `rust-toolchain.toml`, installed automatically by rustup
- `wasm-pack` — install once: `cargo install wasm-pack`
- `openssl` CLI — for SRI hash generation (`openssl dgst -sha384`)

## Steps

**1. Build the WASM crypto module**

```sh
cd crypto
wasm-pack build --target web --mode no-install --out-dir ../client/pkg
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

## Verifying what the site serves

`HASHES.md` lists the SHA-384 of every script the browser runs. To check the live site against it:

```sh
for f in app.js qr.js pkg/iris_crypto.js pkg/iris_crypto_bg.wasm; do
  curl -s "https://iriszip.com/$f" | sha384sum
done
```

Each value must match its row in `HASHES.md` exactly.

**The WASM build is not yet bit-for-bit reproducible.** A clean rebuild from this
repository produces a matching `iris_crypto.js`, but its `iris_crypto_bg.wasm` can
differ from the published one. Making it reproducible is open work. The server binary is not
reproducible either; it never sees plaintext, so the browser files are what matter.

## Running tests

```sh
# Server unit tests
cd server && cargo test && cd ..

# WASM crypto tests
cd crypto && wasm-pack test --headless --firefox && cd ..
```
