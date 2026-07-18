# Security Policy

UnityLAN is a WireGuard mesh VPN whose control plane signs short-lived attestations and whose
engine runs privileged (WireGuard, host firewall, DNS). Vulnerability reports are welcome and
taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's **[Report a vulnerability](https://github.com/gtosh4/unity_lan/security/advisories/new)**
flow (the repository's *Security* tab → *Advisories* → *Report a vulnerability*). This opens a
private advisory visible only to you and the maintainers.

Please include, as far as you can:

- the affected component (coordinator, engine, GUI, or `common`) and version / commit,
- a description of the issue and its impact (what trust boundary it crosses),
- steps to reproduce or a proof of concept,
- any suggested fix or mitigation.

You can expect an initial acknowledgement within a few days. We'll work with you on a fix and a
coordinated disclosure timeline, and credit you in the advisory unless you prefer otherwise.

## Scope

Especially of interest:

- **Attestation / trust model** — anchor pinning (TOFU), per-guild key isolation, rotation-chain
  handling, attestation forgery or replay, cross-guild vouching.
- **The privileged engine** — anything letting coordinator- or peer-supplied input reach the
  root-run daemon without validation (WireGuard peer/route installation, the nftables firewall, the
  DNS resolver, the control socket).
- **Signed auto-update** — the release-manifest verification path.
- **Coordinator** — authentication, rate-limiting, and the admin/metrics surface.

## What is *not* a vulnerability

- The coordinator is a **control plane**: it brokers discovery and NAT traversal but carries no
  peer traffic and holds no peer private keys. A malicious coordinator can deny or misdirect
  *discovery*; it cannot read tunnel traffic (WireGuard authenticates peers by public key).
- A **compromised guild signing key** can forge membership **within that one guild** — this is the
  documented blast-radius boundary (per-guild keys, `docs/design.md` §3.1), not a cross-tenant break.
- Reachability limits behind hostile NAT (symmetric / UDP-blocked) are a known functional gap, not
  a security issue.

## Supported versions

UnityLAN is pre-1.0; security fixes land on the latest `main` / most recent release. There is no
back-port guarantee for older tags yet.
