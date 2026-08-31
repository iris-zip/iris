# Iris for Organizations — Self-Host Tiers (draft)

Iris is an end-to-end encrypted, ephemeral transfer service your company can
run entirely inside its own network. No accounts, no logs, no stored data —
which also means: no per-seat licensing, because there are no seats to
count. Pricing attaches to the *instance*, sized by concurrent sessions (the
only capacity metric an account-less relay actually has).

Every tier below runs the exact same code — Iris is open source (client MIT,
crypto Apache-2.0, server AGPL-3.0), so nothing here is a feature gate and
the cryptography is never paywalled. What the paid tiers buy is
accountability (support, SLAs) and a licence exemption that the copyleft
terms don't grant, scoped to what you're actually doing with it.

## Tiers

| | Community | Team | Enterprise (Internal) |
|---|---|---|---|
| Price | **Free** | **$490 / year** per instance | **$4,900 / year** per instance |
| License | AGPL-3.0 | same as Community | **Commercial License** — internal use only |
| Internal company use | ✔ unlimited | ✔ unlimited | ✔ unlimited |
| Modify without publishing your changes | ✘ AGPL requires publishing | ✘ | ✔ granted, for internal use |
| Embed or redistribute Iris to your own external customers | ✘ only if you publish your modified source | ✘ | ✘ — this tier is internal-use only; see [OEM, reseller, and strategic rights](#beyond-internal-use-oem-reseller-and-strategic-rights) below |
| Support | community (GitHub issues) | priority email, 2-business-day response | direct channel, SLA'd response |
| Security advisories | public disclosure timeline | advance direct notification | advance direct notification |
| Security-fix SLA | none | none | critical fixes: response within 2 business days |
| Deployment assistance | docs (`SELFHOST.md`) | email guidance | hands-on session + review of your reverse-proxy/TLS setup |
| Branding (`BEEM_WORDMARK_TEXT` / `BEEM_ACCENT_COLOR`) | ✔ (in the code, documented) | ✔ | ✔ + assistance |
| Compliance audit log (`BEEM_AUDIT`) | ✔ (in the code, documented) | ✔ | ✔ + assistance |
| Purchasing | — | card / crypto | invoice / PO, custom terms, indemnification available |
| Recommended for | any size | small/medium deployments | larger or business-critical deployments |

**Enterprise (Internal) covers running Iris for your own organization only.** It does not
include the right to embed Iris in a product you sell, or to redistribute it to your own
customers — that is a different kind of arrangement, described next.

## Beyond internal use: OEM, reseller, and strategic rights

The tiers above cover organizations running Iris *for themselves*. A different
arrangement is needed for organizations that want to put Iris *in front of their own
customers* — as a component in a product they sell, as a white-labeled offering they
resell, or as part of a larger strategic partnership. These are not flat "pay once, use
forever" purchases, because what's changing hands scales with how many of *your*
customers you're distributing Iris to.

| | OEM / Embedded | Reseller / White-label | Strategic |
|---|---|---|---|
| What it's for | Iris becomes a component inside a product you build and ship | You commercially distribute an Iris-based offering to your own customers | Large or unusual arrangements that don't fit either of the above |
| Price | **[PRICE TBD]** — scoped to an agreed deployment/customer cap | **[PRICE TBD]** — scoped, or a negotiated revenue share | Custom, negotiated individually |
| Typical scope | e.g. "up to N downstream customer deployments per year" | e.g. "up to N downstream customer deployments," or reporting-based revenue share | Unlimited redistribution — only this tier ever grants that, and only by explicit agreement |
| Includes | Everything in Enterprise (Internal), plus redistribution rights for the agreed scope | same | same |

**How scope is honored without telemetry.** Iris still logs nothing about your end users
or their transfers — that doesn't change under any tier. A deployment or customer-count
cap is enforced contractually, not technically: you self-report aggregate counts
periodically (e.g. "340 active deployments this quarter") as a term of the agreement, the
same way most enterprise software licenses work. That is a business reporting obligation
between us, not the product surveilling anyone.

**Why there's no fixed price here yet.** A flat fee for unlimited redistribution would
mean a customer could pay once and put Iris in front of an unlimited number of their own
customers with nothing further owed — that was an accidental gap in an earlier version of
this document, not the intent. The actual commercial-license contract text (not just this
pricing page) is still being drafted. If you want one of these arrangements now, contact admin@iriszip.com and terms
will be negotiated directly.

## Why it's structured this way

**Community is genuinely free, forever, at any scale.** The AGPL permits
internal production use with no strings and no seat count. We won't pretend
otherwise or claw it back — a 10,000 person company can run Iris internally
without paying us anything. If that's you, take it; we ask only that you
consider a Team subscription so the project has a maintainer when you need
one.

**Team is a support contract, not a license.** You're paying so that when
something breaks, a specific person is obligated to answer within two
business days, and so you hear about security issues before the public
disclosure timeline runs. For an org relying on Iris for daily cross-device
transfer, $490/yr is the cost of having someone accountable.

**Enterprise (Internal) is the license tier — for your own internal use.** The AGPL
requires that a modified version users interact with remotely over a network must offer
those users access to its corresponding source. For most organisations that is a
non-issue — but not for one whose policy forbids AGPL code outright. Enterprise licenses
your internal deployment under a separate Commercial License instead of AGPL-3.0, which
doesn't carry that condition, plus an SLA on critical security fixes, hands-on deployment
help, and the paperwork larger orgs need (invoicing, PO, custom terms, indemnification).
It deliberately does **not** include the right to embed Iris in a product you sell or
redistribute it to your own customers — a flat internal-use fee isn't the right shape for
rights that scale with how many of *your* customers you're putting Iris in front of.
That's what OEM, reseller, and strategic arrangements are for, above.

**Why no per-user or per-GB pricing:** every competitor prices per seat
(WeTransfer $120–276/user/yr, Mattermost $120/user/yr, GitLab $348+/user/yr)
or per gigabyte (MASV $0.25/GB, Aspera from ~$11k/yr for committed volume).
Both models require the vendor to *count* something — users or traffic.
Iris is built not to know either: no accounts exist, and metering transfer
volume would mean logging what the product promises not to log. Flat
per-instance pricing is the simplest model consistent with Iris's
no-telemetry architecture. Concurrency tiers are a good-faith sizing
guideline, not something the software enforces or phones home about — it
never phones home at all.

## Market context (2026)

**Needs re-verification before public launch.** Researched 2026-07-09; competitor pricing
pages change over time and these figures have not been re-checked since.

For a 25-person team, a year of the mainstream options costs roughly:

| Option | Model | ~Cost for 25 people | Sees your files? |
|---|---|---|---|
| WeTransfer Premium | per seat | ~$5,700/yr | yes (cloud, stored) |
| MASV | per GB | $0.25/GB — 2 TB/mo ≈ $6,000/yr | yes (cloud, stored) |
| IBM Aspera | volume commit | from ~$11,088/yr | infrastructure, complex |
| Enterprise MFT (MOVEit, GoAnywhere) | quote-only | typically five figures | stores + logs by design |
| **Iris Team** | per instance | **$490/yr** | **no — E2EE, relay-blind, nothing stored** |

Iris is drastically cheaper because the economics are different, not because
it does less of what matters here: you supply the hardware (a container on
any box), there's no cloud storage to fund, no per-user accounting to
administer, and the security property — end-to-end encrypted, post-quantum
hybrid, zero retention — is one none of the above offer at any price.

## Status of this document

Draft — tiers and prices are subject to a sanity-check with early customers
before publication. The Community/Team/Enterprise (Internal) prices reflect actual market
research (see Market context above); the OEM/Reseller/Strategic figures are explicitly
**not** researched yet and are marked `[PRICE TBD]` rather than invented.
Contact: admin@iriszip.com.
