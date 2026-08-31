# Contributing to Iriszip

Thanks for wanting to help. A few ground rules keep this easy for everyone.

## Security issues

Never open a public issue for a vulnerability. Email security@iriszip.com and
read [`SECURITY.md`](./SECURITY.md) for the policy and timeline. Everything
else in this file is about non-security contributions.

## Bugs and ideas

Open an issue. Say what you did, what happened, and what you expected. Browser
name and version help a lot, since most of Iriszip lives in the browser.

## Pull requests

- Small, focused changes are much easier to review than big ones.
- The protocol and key schedule are the reviewed core. Changes there need a
  very good reason and will be treated conservatively; a PR that touches
  `crypto/` or the wire format should start life as an issue first.
- Run the tests before opening a PR: `cargo test` in `server/`, and
  `wasm-pack test --headless --firefox` in `crypto/`.
- Match the style of the code around you.

## Contributor license agreement

Iriszip is licensed per directory (MIT client, Apache-2.0 crypto, AGPL-3.0
server) and the server is also offered under a commercial license. To keep
that model workable, contributions need a signed CLA before they can merge.
Signing happens once, in the PR itself, when the CLA bot asks; it takes a
minute. No paperwork beyond that.

## Build

See [`BUILD.md`](./BUILD.md) for the full local build, and the README's quick
start for the two-command version.
