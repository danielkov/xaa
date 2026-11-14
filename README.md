# xaa

[![CI](https://github.com/danielkov/xaa/actions/workflows/ci.yml/badge.svg)](https://github.com/danielkov/xaa/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/danielkov/xaa/branch/main/graph/badge.svg)](https://codecov.io/gh/danielkov/xaa)
[![crates.io](https://img.shields.io/crates/v/xaa.svg)](https://crates.io/crates/xaa)
[![docs.rs](https://img.shields.io/docsrs/xaa)](https://docs.rs/xaa)

`xaa` is a Rust library for Cross App Access (XAA).

Cross App Access lets one application get an access token for the API of a different application. The user does not see a consent screen. The identity provider (IdP) that the two applications use for single sign-on approves the access.

The protocol is the [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (ID-JAG), an IETF OAuth draft. [xaa.dev](https://xaa.dev/) gives an introduction and a public test environment.

## What the crate does

The protocol has three roles. `xaa` implements each role as a separate component.

| Component | Role | What it does |
| --- | --- | --- |
| `client` | Requesting application | Gets an ID-JAG from the IdP. Then gets an access token from the Resource Authorization Server. |
| `resource-as` | Resource Authorization Server | Validates an ID-JAG and decides which access to grant. |
| `idp` | IdP Authorization Server | Validates the subject token of the user and issues an ID-JAG. |

The crate does not keep state and does not start a server. Your application supplies these parts:

- The HTTP client. Implement the `HttpClient` trait, or enable the `reqwest-client` feature.
- The clock. Each operation takes the current time as a parameter.
- The replay store, for single-use checks.
- The access tokens. The crate validates the grant. Your server makes the token.

## The flow

```text
 Client                    IdP                  Resource AS          Resource API
       │  OIDC / SAML SSO   │                        │                     │
       │───────────────────>│                        │                     │
       │  id_token          │                        │                     │
       │<───────────────────│                        │                     │
       │  RFC 8693 token exchange                    │                     │
       │  requested_token_type=…:id-jag              │                     │
       │───────────────────>│                        │                     │
       │  ID-JAG            │                        │                     │
       │<───────────────────│                        │                     │
       │  RFC 7523 jwt-bearer, assertion=ID-JAG      │                     │
       │────────────────────────────────────────────>│                     │
       │  access_token                               │                     │
       │<────────────────────────────────────────────│                     │
       │  Authorization: Bearer …                                          │
       │──────────────────────────────────────────────────────────────────>│
```

1. The user signs in at the IdP. The client gets an ID Token or a SAML assertion.
2. The client sends this token to the IdP and gets an ID-JAG. The ID-JAG is a short-lived signed JWT for one Resource Authorization Server.
3. The client sends the ID-JAG to the Resource Authorization Server and gets an access token.
4. The client calls the API with the access token.

## Quick start

### Run the examples

The repository has the three roles as separate programs. Each program listens only on the local computer.

1. Clone the repository.
2. Start the IdP in one terminal:

   ```sh
   cargo run -p xaa-idp
   ```

3. Start the Resource Authorization Server in a second terminal:

   ```sh
   cargo run -p xaa-resource-as
   ```

4. Run the client in a third terminal:

   ```sh
   cargo run -p xaa-client
   ```

The client prints each step of the flow and then the to-do list of the demo user. [`examples/README.md`](examples/README.md) gives more options, and the procedure for the xaa.dev test environment.

### Use the crate in a client

1. Add the crate to your project:

   ```sh
   cargo add xaa@0.0.1-alpha.0 --features reqwest-client
   ```

2. Get an ID Token for the user from your OpenID Connect login. The crate does not do the login.
3. Exchange the ID Token for an ID-JAG, then exchange the ID-JAG for an access token:

   ```rust
   use std::time::SystemTime;

   use xaa::claims::{Issuer, Scope};
   use xaa::client::{
       AccessTokenRequest, ClientAuth, IdpConnection, ResourceAsClientAuth, ResourceAsConnection,
       ResourceIdentifier, SamlEncoding, SubjectToken, TokenExchange, exchange_for_id_jag,
       request_access_token,
   };
   use xaa::http::{BoxError, ReqwestClient};
   use xaa::secret::{AccessToken, ClientSecret, IdToken};

   async fn todo_api_token(id_token: String) -> Result<AccessToken, BoxError> {
       let http = ReqwestClient::new()?;

       // The client holds two independent registrations (draft §5).
       let idp = IdpConnection {
           issuer: Issuer::new("https://idp.example"),
           token_endpoint: "https://idp.example/token".parse()?,
           client_auth: ClientAuth::ClientSecretPost {
               client_id: "wiki-app".to_owned(),
               secret: ClientSecret::new("…"),
           },
           saml_encoding: SamlEncoding::default(),
       };
       let resource_as = ResourceAsConnection {
           issuer: Issuer::new("https://auth.resource.example"),
           token_endpoint: "https://auth.resource.example/token".parse()?,
           client_auth: ResourceAsClientAuth::Authenticated(ClientAuth::ClientSecretBasic {
               client_id: "wiki-app-at-todo".to_owned(),
               secret: ClientSecret::new("…"),
           }),
           supports_jwt_dpop: false,
       };

       // ID Token → ID-JAG at the IdP (RFC 8693).
       let subject = SubjectToken::IdToken(IdToken::new(id_token));
       let mut exchange = TokenExchange::new(&idp, &resource_as, &subject, SystemTime::now());
       exchange.resources = vec![ResourceIdentifier::new("https://api.resource.example/")];
       exchange.scope = Some(Scope::parse("todos.read")?);
       let id_jag = exchange_for_id_jag(&http, &exchange).await?;

       // ID-JAG → access token at the Resource AS (RFC 7523).
       let token = request_access_token(
           &http,
           &AccessTokenRequest {
               resource_as: &resource_as,
               id_jag: &id_jag,
               scope: None,
               dpop: None,
               now: SystemTime::now(),
           },
       )
       .await?;
       Ok(token.access_token)
   }
   ```

The `client` component has two registrations: one at the IdP and one at the Resource Authorization Server. The two client IDs are usually different.

If you know only the URL of the resource, `discover_resource`, `discover_resource_as`, and `discover_idp` make the two connections from metadata.

### Use the crate in a server

- For a Resource Authorization Server, read [`examples/resource-as`](examples/resource-as) and RFC-004 §11.
- For an IdP, read [`examples/idp`](examples/idp) and RFC-005 §12.

## Feature flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `client` | yes | The requesting application: token exchange at the IdP and the access token request at the Resource Authorization Server. |
| `resource-as` | yes | The Resource Authorization Server: ID-JAG validation and the grant decision. |
| `idp` | no | The IdP Authorization Server: subject token validation and ID-JAG issuance. |
| `reqwest-client` | no | `xaa::http::ReqwestClient`, an `HttpClient` that uses `reqwest` with rustls. It does not follow redirects. |

To use only one component, disable the default features:

```sh
cargo add xaa@0.0.1-alpha.0 --no-default-features --features resource-as
```

## Supported functions

- **Subject tokens:** ID Token, SAML 2.0 assertion, and refresh token.
- **SAML path:** the exchange of a SAML assertion for a refresh token (draft §4.5), and the `saml-nameid` subject identifier.
- **ID-JAG validation:** type, signature, issuer trust, audience, client binding, lifetime, tenant, subject identifier, resource, and replay.
- **Grant decision:** a builder that cannot grant more access than the ID-JAG permits.
- **Sender-constrained tokens:** DPoP (RFC 9449) with the `jwt-dpop` grant, and mTLS certificate binding (RFC 8705).
- **Client authentication:** `client_secret_basic`, `client_secret_post`, `private_key_jwt` (RFC 10070), and `tls_client_auth`.
- **Metadata:** authorization server metadata, OpenID Connect discovery, Protected Resource Metadata, client metadata, and JWKS.
- **Signatures:** RS256, RS384, RS512, PS256, PS384, PS512, ES256, and ES384. The crate rejects `none` and HMAC algorithms. The crate does not support JWE.

## Status

This crate is a pre-release: **v0.0.1-alpha.0**. The API can change before version 0.1.

The crate follows `draft-ietf-oauth-identity-assertion-authz-grant-06`. The draft is not final.

| Component | Tests in this repository | xaa.dev test environment |
| --- | --- | --- |
| `client` | Yes | Pass, with OpenID Connect and with SAML |
| `resource-as` | Yes | Pass, with OpenID Connect and with SAML |
| `idp` | Yes | Not tested |

The xaa.dev tests are manual, because the login needs a browser. They are not part of CI. The last run was on 2026-11-14. [`docs/interop.md`](docs/interop.md) records the differences that the tests found.

No independent security review of this crate exists at this time. [`SECURITY.md`](SECURITY.md) gives the security policy.

## How the crate is tested

1. **Unit tests** in each module. Each validation rule has a test that fails the rule. Known-answer vectors come from RFC 7638, RFC 9449, and RFC 8705.
2. **Flow tests** in [`tests/flow_test.rs`](tests/flow_test.rs). The three components exchange real JWTs in one process.
3. **SAML flow tests** in [`tests/saml_flow_test.rs`](tests/saml_flow_test.rs). These tests use the [`saml`](https://crates.io/crates/saml) crate, which is a development dependency only.
4. **Examples** in [`examples/`](examples/). The three components run as separate programs. CI runs them with `scripts/smoke-examples.sh`.
5. **Tests against xaa.dev.** Refer to the Status section.
6. **Fuzz target** in [`fuzz/`](fuzz/). `fuzz_id_jag_decode` sends untrusted bytes through the JWS parser and the ID-JAG claim rules.

## Documentation

- [`docs/rfcs/RFC-001-architecture.md`](docs/rfcs/RFC-001-architecture.md): design principles, roles, scope, and the map from each draft section to the code.
- [`docs/rfcs/RFC-002-jose-core.md`](docs/rfcs/RFC-002-jose-core.md): JWS, JWK, ID-JAG claims, client assertions, and the replay store.
- [`docs/rfcs/RFC-003-client.md`](docs/rfcs/RFC-003-client.md): the `client` component.
- [`docs/rfcs/RFC-004-resource-as.md`](docs/rfcs/RFC-004-resource-as.md): the `resource-as` component.
- [`docs/rfcs/RFC-005-idp.md`](docs/rfcs/RFC-005-idp.md): the `idp` component.
- [`docs/rfcs/RFC-006-metadata.md`](docs/rfcs/RFC-006-metadata.md): metadata and discovery.
- [`docs/rfcs/RFC-007-sender-constraining.md`](docs/rfcs/RFC-007-sender-constraining.md): DPoP and mTLS binding.
- [`docs/interop.md`](docs/interop.md): known differences in deployed systems.
- [`docs/releasing.md`](docs/releasing.md): the release procedure.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) is **1.91.0**. CI runs the tests on `stable`, `beta`, and `1.91.0`. An MSRV increase is a minor-version change, and the release notes record it.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT License

at your option.
