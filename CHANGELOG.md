# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-11-15

Tracks `draft-ietf-oauth-identity-assertion-authz-grant-06`. The client and the Resource AS have been run by hand against the xaa.dev playground, on its OpenID Connect and SAML paths; the IdP component has not been tested against a third-party deployment.

### Added

- `jose`: compact JWS parsing, verification, and signing for RS256/384/512, PS256/384/512, ES256, and ES384; JWK and JWK Set public keys; RFC 7638 thumbprints; the `JwsSigner` trait and an in-process `PrivateKey`.
- `claims`: the typed ID-JAG claim set (`IdJagClaims`), including `resource`, `scope`, `authorization_details`, `cnf`, and the `saml-nameid` Subject Identifier Format.
- `client_auth`: `client_secret_basic`, `client_secret_post`, `private_key_jwt` (RFC 10070), and `tls_client_auth`, for the client and for the server side.
- `replay`: the `ReplayStore` trait and `InMemoryReplayStore`.
- `secret`: token and credential newtypes with redacted `Debug`, zeroized on drop, and a constant-time `ct_eq` for checking presented credentials.
- `dpop` and `mtls`: DPoP proof creation and validation (RFC 9449), the `jwt-dpop` grant, certificate thumbprints (RFC 8705), and the binding decisions for the IdP and the Resource AS. `ValidatedDpopProof::is_for_access_token` gives a Resource Server the `ath` check.
- `metadata`: authorization server metadata with the OIDC Discovery fallback, Protected Resource Metadata, client metadata, and JWKS fetch, with the issuer and resource checks of draft §9.5 and §9.6.
- `client` feature: token exchange for an ID-JAG (`TokenExchange`, `exchange_for_id_jag`), self-checks on the issued ID-JAG, the access token request (`AccessTokenRequest`, `request_access_token`), the SAML → refresh token exchange, discovery (`discover_resource`, `discover_resource_as`, `discover_idp`), and `Remediation` for token endpoint errors.
- `resource-as` feature: `TokenRequest` parsing, `ResourceAs::validate`, the `VerifiedGrant` handle, and a decision builder that enforces granted ⊆ ID-JAG.
- `idp` feature: `TokenExchangeRequest` parsing, `IdTokenVerifier`, `Idp::exchange`, `Idp::exchange_saml_for_refresh_token`, and an `ExchangeRecord` per exchange.
- `reqwest-client` feature: `xaa::http::ReqwestClient`, an `HttpClient` that does not follow redirects.
- `xaa-client --playground`: the client example against xaa.dev, with a browser login. `--saml` signs in with SAML 2.0 instead and takes the draft §4.5 path.
- Cross-role flow tests (`tests/flow_test.rs`), a SAML flow test against the `saml` crate (`tests/saml_flow_test.rs`, dev-dependency only), the `fuzz_id_jag_decode` fuzz target, and closed-loop examples under `examples/`.
- Design documents `docs/rfcs/RFC-001` to `RFC-007`.
