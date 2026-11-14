# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities by email to
**daniel@speakeasy.com**. Use the subject line `[xaa] security report`.

Do **not** open a public GitHub issue, pull request, or discussion thread for
security-sensitive reports — the crate's threat model includes hostile peers
on the OAuth wire, and a public report tips them off before downstream callers
can update.

A report ideally includes:

- The affected crate version (or commit hash).
- A minimal reproduction — the ID-JAG / token-exchange request bytes, IdP
  keys or metadata, the call site triggering the issue, and the observed vs.
  expected behavior.
- Your assessment of impact (e.g. signature bypass, audience confusion,
  replay, `client_id` substitution, panic / denial-of-service on the host
  process).
- Any constraints on disclosure timing (see below).

You will receive an acknowledgement within 72 hours.

## Supported Versions

While the crate is pre-alpha, only the most recent release receives security
fixes.

| Version | Supported |
| --- | --- |
| latest `0.0.x-alpha` | yes |
| anything older | no |

## Threat Model

The crate assumes hostile peers on the OAuth wire: a forged or replayed ID-JAG, a malicious
or compromised token endpoint, tampered metadata, and a client presenting another client's
grant. The per-component threat tables are in `docs/rfcs/RFC-002-jose-core.md` §13,
`RFC-003-client.md` §13, `RFC-004-resource-as.md` §12, and `RFC-005-idp.md` §13, derived from
draft-ietf-oauth-identity-assertion-authz-grant §9 and RFC 8725. Sender constraining is in
`RFC-007-sender-constraining.md`.

The caller is responsible for what the library does not hold:

- **The replay store.** Single-use `jti` enforcement needs a `ReplayStore` shared by every
  instance. `InMemoryReplayStore` covers one process only.
- **TLS.** The `HttpClient` MUST NOT follow redirects. For mTLS, the caller's TLS stack
  validates the client certificate before passing it to the library.
- **Keys and tokens.** Fetching and caching issuer JWK Sets, storing client credentials, and
  minting and validating access tokens are outside the crate.
- **Subject resolution.** Mapping a verified grant to a local account is caller policy.

The client and the Resource AS have been run by hand against the xaa.dev playground, on its OpenID Connect and SAML paths
(`docs/interop.md`). The IdP component has not been tested against a third-party deployment.

## Known Advisories

None.

## Disclosure Timeline

Standard timeline is **90 days** from receipt of the report to public
disclosure, regardless of fix availability. We aim to publish a fixed
release well within that window.

If you need a faster disclosure (for example, evidence of active
exploitation), say so in the initial report — we will accelerate. If you
need a slower disclosure for coordinated multi-party fixes, say so as well
and we will negotiate a date.

After a fixed release is published, the CHANGELOG entry will reference the
issue (with a CVE identifier if assigned) and credit the reporter unless
they prefer to remain anonymous.
