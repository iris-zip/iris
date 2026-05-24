#!/usr/bin/env bash
# Phase 15.4 — inject SHA-384 Subresource Integrity hashes into the client.
# Phase 15.5 — also rewrite HASHES.md so the published hashes stay in sync
#              with what the browser actually loads.
#
# Order matters:
#   1. Hash pkg/beem_crypto.js and pkg/beem_crypto_bg.wasm.
#   2. Rewrite the two constants in client/app.js with those hashes.
#   3. Hash the now-updated app.js.
#   4. Rewrite the <script> tag in client/index.html with that hash.
#   5. Rewrite HASHES.md with all three hashes and the current git SHA.
#
# Idempotent: each sed pattern tolerates either the placeholder or a prior hash.

set -euo pipefail

cd "$(dirname "$0")/.."

CLIENT=client
APP_JS="$CLIENT/app.js"
INDEX="$CLIENT/index.html"
CRYPTO_JS="$CLIENT/pkg/beem_crypto.js"
CRYPTO_WASM="$CLIENT/pkg/beem_crypto_bg.wasm"

for f in "$APP_JS" "$INDEX" "$CRYPTO_JS" "$CRYPTO_WASM"; do
    [[ -f "$f" ]] || { echo "missing: $f" >&2; exit 1; }
done

sha384_b64() {
    openssl dgst -sha384 -binary "$1" | openssl base64 -A
}

CRYPTO_JS_SRI="sha384-$(sha384_b64 "$CRYPTO_JS")"
CRYPTO_WASM_SRI="sha384-$(sha384_b64 "$CRYPTO_WASM")"

echo "crypto.js   $CRYPTO_JS_SRI"
echo "crypto.wasm $CRYPTO_WASM_SRI"

sed -i -E \
    -e "s|^const CRYPTO_JS_SRI   = \"[^\"]*\";|const CRYPTO_JS_SRI   = \"$CRYPTO_JS_SRI\";|" \
    -e "s|^const CRYPTO_WASM_SRI = \"[^\"]*\";|const CRYPTO_WASM_SRI = \"$CRYPTO_WASM_SRI\";|" \
    "$APP_JS"

grep -q "^const CRYPTO_JS_SRI   = \"$CRYPTO_JS_SRI\";"   "$APP_JS" || { echo "failed to inject crypto.js hash" >&2; exit 1; }
grep -q "^const CRYPTO_WASM_SRI = \"$CRYPTO_WASM_SRI\";" "$APP_JS" || { echo "failed to inject wasm hash"      >&2; exit 1; }

APP_JS_SRI="sha384-$(sha384_b64 "$APP_JS")"
echo "app.js       $APP_JS_SRI"

sed -i -E \
    "s|<script type=\"module\" src=\"app\.js\"( integrity=\"[^\"]*\")?></script>|<script type=\"module\" src=\"app.js\" integrity=\"$APP_JS_SRI\"></script>|g" \
    "$INDEX"

grep -q "integrity=\"$APP_JS_SRI\"" "$INDEX" || { echo "failed to inject app.js integrity" >&2; exit 1; }

echo "SRI hashes injected."

# 15.5 — rewrite HASHES.md. Hashes are written as plain hex so a user can
# reproduce with `sha384sum` without needing to base64-decode. SRI (base64)
# values are also shown, because those are what Chrome DevTools displays.
HASHES_MD="HASHES.md"
sha384_hex() {
    openssl dgst -sha384 "$1" | awk '{print $NF}'
}
APP_JS_HEX=$(sha384_hex "$APP_JS")
CRYPTO_JS_HEX=$(sha384_hex "$CRYPTO_JS")
CRYPTO_WASM_HEX=$(sha384_hex "$CRYPTO_WASM")
GIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "(no git)")
GIT_FULL=$(git rev-parse HEAD 2>/dev/null || echo "(no git)")
STAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "$HASHES_MD" <<EOF
# Beem — Published Build Hashes

Every file the browser runs ships with a SHA-384 Subresource Integrity tag
and is also listed here. Cross-check these against what your browser
actually loaded (Chrome DevTools → Network tab → click file → Headers /
Response tab shows the integrity value) to confirm you're running the
exact code in this git commit.

**Commit:** \`$GIT_FULL\` (\`$GIT_SHORT\`)
**Generated:** $STAMP (UTC) — by \`scripts/build-sri.sh\`

## Client files (run in your browser)

| File | sha384 (hex) | sha384 (SRI / base64) |
|---|---|---|
| \`client/app.js\` | \`$APP_JS_HEX\` | \`$APP_JS_SRI\` |
| \`client/pkg/beem_crypto.js\` | \`$CRYPTO_JS_HEX\` | \`$CRYPTO_JS_SRI\` |
| \`client/pkg/beem_crypto_bg.wasm\` | \`$CRYPTO_WASM_HEX\` | \`$CRYPTO_WASM_SRI\` |

## How to verify manually

From the repo root, after a clean checkout:

\`\`\`
sha384sum client/app.js client/pkg/beem_crypto.js client/pkg/beem_crypto_bg.wasm
\`\`\`

The hex values must match the table above. If they don't, either the
repo was tampered with or you're on a different commit.

## Not yet covered

- Signed git tags (\`git tag -s\`): deferred until the first public
  release; a GPG key will be bound to the maintainer identity at that
  time and the tag fingerprint will be added here.
- Server binary hash: ephemeral per build; users running the hosted
  service do not execute it, so not published. Self-hosters should
  rebuild from this exact commit and check \`cargo build --locked --release\`
  output.
EOF

echo "wrote $HASHES_MD (commit $GIT_SHORT)"
