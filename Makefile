# Iris — build orchestration (16.5.5)
# `make deploy` encodes the release order so it can never be run backwards:
# SRI hashes are computed from the freshly built wasm, so wasm MUST come first.

.PHONY: deploy wasm sri server test test-browser

deploy: wasm sri server

wasm:
	cd crypto && wasm-pack build --target web --out-dir ../client/pkg

sri:
	bash scripts/build-sri.sh

server:
	cd server && cargo build --locked --release

test:
	cd server && cargo test
	cd crypto && wasm-pack test --headless --firefox

test-browser:
	cd tests/browser && npx playwright test
