# Security policy

Iriszip exists to move a file between two devices without anyone in the middle being
able to read it. If you have found a way to break that, we want to hear from you
before anyone else does.

## Reporting a vulnerability

Email **admin@iriszip.com**. That is the only address; there is no separate
security alias and no web form.

Please include:

- What the flaw is, in one or two sentences.
- The steps to reproduce it. A short script, a curl command, or two browser tabs
  and a description all work fine.
- What an attacker gets out of it. "The relay can read plaintext" and "the page
  renders a broken image" need very different responses, and we would rather you
  tell us which one it is than have us guess.
- The version or commit you tested against.

Do not open a public issue for a security problem. Do not post it on social media
first. Anything sent by email is treated as confidential until we agree together
that it is fixed.

If you would rather encrypt the report, say so in a first email with no details in
it and we will send you a key.

## What happens next

| When | What |
|---|---|
| Within 3 days | We acknowledge your email. A human, not an autoresponder. |
| Within 14 days | We tell you whether we can reproduce it, and what we think the severity is. If we disagree with your assessment we will explain why rather than just closing it. |
| Within 90 days | A fix ships, or we explain in writing why it has not and when it will. |

Iriszip is maintained by one person. If a reply is slow it is because of that, not
because the report was ignored. Send a follow-up if two weeks pass in silence.

## Coordinated disclosure

We ask for 90 days from your first email before you publish. If a fix lands sooner
you are free to publish as soon as users have had a reasonable window to update —
tell us and we will agree a date together.

We will not threaten you, and we will not ask you to sign anything, for reporting a
flaw in good faith. If you want credit you get it, by whatever name you choose. If
you want to stay anonymous that is fine too.

There is no bug bounty. This is a self-funded project with no revenue, and we would
rather be honest about that than advertise a reward we cannot pay.

## Supported versions

Only the most recent release receives security fixes. There are no long-term
support branches. If you self-host, upgrade.

Self-hosters carry their own deployment: read [`SELFHOST.md`](./SELFHOST.md) in full,
particularly the environment variables that govern how the server identifies clients
behind a proxy. A misconfigured deployment can weaken protections that work correctly
by default.

## Scope

**In scope** — anything in this repository, and the service running at iriszip.com:

- The cryptography in `crypto/`: the handshake, the key schedule, nonce handling,
  the AEAD framing.
- The signalling server in `server/`: anything that lets it read plaintext, link two
  users, learn a pairing code, or be turned against its own users.
- The browser client in `client/`: anything that executes attacker-controlled code in
  a user's page, leaks a key out of the tab, or misreports the security state of a
  session to the person using it.
- Any case where the interface tells the user something untrue about what happened —
  a file reported as delivered that never arrived, or a connection described as
  direct when it was relayed. We treat honesty bugs as security bugs.

**Out of scope:**

- Volumetric denial of service. Sending more traffic than a server can absorb is not
  a finding.
- Missing HTTP headers, TLS configuration preferences, or scanner output with no
  demonstrated impact. Show us what an attacker actually achieves.
- Attacks that require malware on the user's own device, or physical access to an
  unlocked one. If your endpoint is compromised, the browser is already lost.
- Attacks by the person you deliberately paired with. Iriszip connects two devices that
  agreed on a code; the peer is a participant, not an outsider.
- Social engineering of the maintainer, or anything involving the domain registrar,
  the mail provider, or a hosting account.

## What Iriszip does not claim to protect

Being clear about the boundary is part of the security model, not an admission.

- **Metadata at the network level.** Iriszip does not hide that you connected, when, or
  from where. It hides what you sent. Use Tor or a VPN if the fact of a connection is
  itself sensitive.
- **The code the browser runs.** You load the client from a web server. If that
  server were compromised it could serve a modified client. Subresource Integrity
  pins the scripts against a tampered CDN, but not against a compromised origin. If
  that is in your threat model, self-host or build from this repository and check the
  hashes in [`BUILD.md`](./BUILD.md).
- **A device you do not control.** Once the file arrives, what happens to it is the
  receiving device's business.

## External review

The protocol has been reviewed by an outside cryptanalysis organisation, and the
certificate they issued is published in this repository as `certificate.pdf`. The
underlying report is confidential and is not published; the certificate is the
artefact we stand behind.

An external review is a point-in-time statement about a design. It is not a
guarantee, and it is not a substitute for you reading the code — which is why the
code is here.
