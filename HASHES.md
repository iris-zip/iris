# Iris — Published Build Hashes

Every file the browser runs ships with a SHA-384 Subresource Integrity tag
and is also listed here. Cross-check these against what your browser
actually loaded (Chrome DevTools → Network tab → click file → Headers /
Response tab shows the integrity value) to confirm you're running the
exact code in this git commit.

**Commit:** `5c5a3690fb6adacd826cb6dbe70248a497bc556d` (`5c5a369`)
**Generated:** 2026-09-05T10:44:16Z (UTC) — by `scripts/build-sri.sh`

## Client files (run in your browser)

| File | sha384 (hex) | sha384 (SRI / base64) |
|---|---|---|
| `client/app.js` | `7a3754f2d1a2fdb1106f0b6a27c95a8530f08fda803cb51499d0a8a482010289b714e0ad73e77c05b0a0b736cbff81b8` | `sha384-ejdU8tGi/bEQbwtqJ8lahTDwj9qAPLUUmdCopIIBAom3FOCtc+d8BbCgtzbL/4G4` |
| `client/qr.js` | `d881dfe0a3ecd1d6dd4bb3fdb739689862d3bfba738cbeecc67d7c1919be0694515acc8e6119d61d447f2d7330f13633` | `sha384-2IHf4KPs0dbdS7P9tzlomGLTv7pzjL7sxn18GRm+BpRRWsyOYRnWHUR/LXMw8TYz` |
| `client/pkg/iris_crypto.js` | `663cc00fe61e6c2b8639eee01d9aae35b95a6817e220b9c1be0bd247ff89e6d08fdd9755d61f1dc186d79c6d66d7419a` | `sha384-ZjzAD+YebCuGOe7gHZquNblaaBfiILnBvgvSR/+J5tCP3ZdV1h8dwYbXnG1m10Ga` |
| `client/pkg/iris_crypto_bg.wasm` | `055fc997c82ceb81ad173daff3177f8ad73ed323cdbe826b5a9e5020ed258672b85a956a5becd7297525ecbff87e1c55` | `sha384-BV/Jl8gs64GtFz2v8xd/itc+0yPNvoJrWp5QIO0lhnK4WpVqW+zXKXUl7L/4fhxV` |

## How to verify manually

From the repo root, after a clean checkout:

```
sha384sum client/app.js client/qr.js client/pkg/iris_crypto.js client/pkg/iris_crypto_bg.wasm
```

The hex values must match the table above. If they don't, either the
repo was tampered with or you're on a different commit.

## Not yet covered

- Signed git tags (`git tag -s`): deferred until the first public
  release; a GPG key will be bound to the maintainer identity at that
  time and the tag fingerprint will be added here.
- Server binary hash: ephemeral per build; users running the hosted
  service do not execute it, so not published. Self-hosters should
  rebuild from this exact commit and check `cargo build --locked --release`
  output.
