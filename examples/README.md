# examples

Runnable end-to-end proof, mirroring the three XAA
parties. Each crate is a workspace member (`publish = false`) and is
excluded from the published `xaa` tarball.

| Crate | Features | Role |
| --- | --- | --- |
| [`idp/`](idp/) | `idp` | Minimal IdP Authorization Server: a demo login stub that hands out ID Tokens, and the RFC 8693 token exchange that turns one into an ID-JAG. |
| [`resource-as/`](resource-as/) | `resource-as`, `reqwest-client` | Resource Authorization Server + a small protected todo API: validates ID-JAGs, issues access tokens, serves `GET /api/todos`. |
| [`client/`](client/) | `client`, `reqwest-client` | Client (requesting app), a CLI: login at the IdP, discovery, token exchange for an ID-JAG, jwt-bearer grant at the Resource AS, protected API call. |

The three are shaped like the xaa.dev playground: an IdP, a Resource AS, and
a todo API with scopes `todos.read` / `todos.write`.

## Run the closed loop

Three terminals, from the repository root. Everything listens on loopback and
keeps its state in memory.

```sh
cargo run -p xaa-idp            # http://127.0.0.1:4000
cargo run -p xaa-resource-as    # http://127.0.0.1:4001
cargo run -p xaa-client         # bearer tokens
cargo run -p xaa-client -- --dpop   # ID-JAG and access token bound to a DPoP key
```

The client prints each step and then the user's todos:

```text
[1/7] log in alice at http://127.0.0.1:4000 (demo stub)
[2/7] discover the resource http://127.0.0.1:4001/
[3/7] discover the Resource AS
[4/7] discover the IdP http://127.0.0.1:4000
[5/7] exchange the ID Token for an ID-JAG (RFC 8693)
[6/7] present the ID-JAG for an access token (RFC 7523)
[7/7] GET http://127.0.0.1:4001/api/todos
{ "owner": "alice", "todos": [ … ] }
```

Or let the smoke test do all of it on free ports, as CI does:

```sh
scripts/smoke-examples.sh
```

Things to try:

- `XAA_USERNAME=bob XAA_SCOPE=todos.write cargo run -p xaa-client`: the IdP's
  policy refuses (`access_denied`); bob may only delegate `todos.read`.
- `XAA_SCOPE=todos.write cargo run -p xaa-client`: every token is issued, and
  the API answers 403 because `GET /api/todos` needs `todos.read`.
- `XAA_RESOURCE_AS_CLIENT_ID=demo-app cargo run -p xaa-client`: the classic
  mistake of using the IdP-side client ID at the Resource AS. The client
  catches it from the ID-JAG before any credential is sent there.
- `XAA_REQUIRE_DPOP=1 cargo run -p xaa-resource-as`, then the client without
  `--dpop`: the Resource AS refuses to issue a bearer token.
- Restart the IdP while the Resource AS keeps running: the signing key is
  new, the Resource AS sees an unknown `kid`, refetches the JWK Set (at most
  once per 10 s) and carries on.

## What each one demonstrates

### `idp`

| Endpoint | |
| --- | --- |
| `POST /token` | Token exchange (draft §4.3): `TokenExchangeRequest::parse`, client authentication against an in-memory table (`client_secret_post` or `client_secret_basic`), then `Idp::exchange` with the caller's three pieces: an `IdTokenVerifier`, a `ResourceAsDirectory`, and an `ExchangePolicy`. One audit line per exchange. DPoP proofs are accepted and bind the ID-JAG. |
| `GET /jwks` | The public half of the signing key. |
| `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server` | Metadata from `Idp::metadata_builder`. |
| `POST /demo/login` | **Demo only.** Form fields `username` (`alice` or `bob`) and `client_id`; returns `{"id_token": …}` without checking a password. Real user authentication is outside the crate. |

The signing key is an ES256 key generated at startup; its `kid` is the key's
thumbprint.

### `resource-as`

| Endpoint | |
| --- | --- |
| `POST /token` | The ID-JAG as a jwt-bearer / jwt-dpop grant (draft §4.4): `TokenRequest::parse`, client authentication, `ResourceAs::validate` with single-use `jti`, subject resolution, a small scope policy through the decision builder, and an opaque access token kept in memory. |
| `GET /.well-known/oauth-authorization-server` | Metadata from `ResourceAs::metadata`. |
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (RFC 9728) for the todo API. |
| `GET /api/todos` | The demo protected resource. Needs an access token with scope `todos.read`; a DPoP-bound token also needs a proof for this request. |

The IdP's JWK Set is found through the IdP's metadata, fetched on first use
with `xaa::metadata`, cached, and refetched once when an ID-JAG names an
unknown `kid`. The library holds no cache and never fetches during validation;
this is the caller's part.

The todo API lives in this binary to keep the demo to three processes. The
Resource Server role is outside the crate: the token lookup, the scope check
and the DPoP `ath` check are plain example code.

### `client`

Starts from the resource URL alone, as an agent or MCP client would:
Protected Resource Metadata → Resource AS metadata → IdP metadata
(`discover_resource`, `discover_resource_as`, `discover_idp`), then
`exchange_for_id_jag` and `request_access_token`, then the API call. With
`--dpop` it generates a `DpopKey`, sends a proof on both token requests, and
signs a proof for the API call with `DpopKey::proof_for_resource`. It never
prints a token or a secret.

## Configuration

Environment variables, with defaults that make the three find each other on
localhost. The secrets are fake constants for the demo.

| Variable | Default | Read by |
| --- | --- | --- |
| `XAA_IDP_PORT` | `4000` | idp |
| `XAA_IDP_ISSUER` | `http://127.0.0.1:$XAA_IDP_PORT` | idp, resource-as, client |
| `XAA_RESOURCE_AS_PORT` | `4001` | resource-as |
| `XAA_RESOURCE_AS_ISSUER` | `http://127.0.0.1:$XAA_RESOURCE_AS_PORT` | idp, resource-as |
| `XAA_RESOURCE` | `$XAA_RESOURCE_AS_ISSUER/` | idp, resource-as, client |
| `XAA_IDP_CLIENT_ID` | `demo-app` | idp, client |
| `XAA_IDP_CLIENT_SECRET` | `demo-idp-secret-not-a-real-secret` | idp, client |
| `XAA_RESOURCE_AS_CLIENT_ID` | `demo-app-at-todos` | idp, resource-as, client |
| `XAA_RESOURCE_AS_CLIENT_SECRET` | `demo-resource-as-secret-not-a-real-secret` | resource-as, client |
| `XAA_REQUIRE_DPOP` | `0` | resource-as: `1` refuses bearer tokens for the todo API |
| `XAA_USERNAME` | `alice` | client |
| `XAA_SCOPE` | `todos.read` | client |

When you change a port, set the matching issuer (and `XAA_RESOURCE`) for the
other two as well: the defaults of one process do not follow another's
environment. The client's `XAA_RESOURCE` default is
`http://127.0.0.1:4001/`.

Issuers have no trailing slash and the resource has one, as on the
playground. Both are compared byte-for-byte.

Plain `http` works here only because every URL is a loopback address and each
example sets the library's explicit `allow_http_loopback` switch
(`FetchOptions`, and the metadata builders). Nothing else is relaxed.

## Two loops

- **Closed loop** — all three local crates against each other, as above. No
  third-party software; runs in CI (`scripts/smoke-examples.sh`).
- **Playground loop** — `client` against the public xaa.dev playground
  (`https://idp.xaa.dev`, `https://auth.resource.xaa.dev`,
  `https://api.resource.xaa.dev`), and `resource-as` registered as a test
  resource at `https://xaa.dev/developer/test-resource`. Opt-in; needs
  developer credentials in `.env`. Not wired up yet: the client gets its ID
  Token from the local IdP's `/demo/login` stub, which the playground does
  not have.

Per-deployment quirks found along the way go in [`../docs/interop.md`](../docs/interop.md).

## Against the xaa.dev playground

`xaa-client --playground` runs the same client against the public playground instead of the two local servers: `https://idp.xaa.dev` as the IdP, `https://auth.resource.xaa.dev` as the Resource AS, and the Todo API at `https://api.resource.xaa.dev/`.

1. Register an app at <https://xaa.dev/developer/register>. Any email address works; it is only a namespace. Add `http://127.0.0.1:8765/callback` as a redirect URI and connect the app to the Todo resource with the `todos.read` scope. Registration shows two sets of credentials: the main client, and the resource client whose ID looks like `{client_id}-at-{resource_id}`.
2. Export the four values:

   ```sh
   export XAA_IDP_CLIENT_ID=...               # main client_id
   export XAA_IDP_CLIENT_SECRET=...           # main client_secret
   export XAA_RESOURCE_AS_CLIENT_ID=...       # resource_client_id
   export XAA_RESOURCE_AS_CLIENT_SECRET=...   # resource_client_secret
   ```

3. Run `cargo run -p xaa-client -- --playground`. It prints a URL: open it, sign in (the playground accepts any email and any 6-digit code), and the browser is sent back to the loopback port the client is listening on. The client then exchanges the ID Token for an ID-JAG, redeems it for an access token, and prints the todos.

To skip the browser on later runs, add `--print-refresh-token` once, export the `XAA_REFRESH_TOKEN` it prints, and run again: the refresh token is then the subject token. It is a credential; keep it out of shell history and logs you share.

The playground does not advertise the `jwt-dpop` grant, so `--dpop` is refused by the client before anything is sent (`Error::ResourceAsLacksJwtDpop`).

### The SAML path

`xaa-client --playground --saml` signs the user in with SAML 2.0 instead, with the [`saml`](https://crates.io/crates/saml) crate as the Service Provider, and takes the draft §4.5 path: the signed assertion is exchanged for a refresh token, and the refresh token for the ID-JAG.

1. At <https://xaa.dev/developer/register>, on the SAML tab, register an app with SP Entity ID `http://localhost:8765/saml/metadata`, ACS URL `http://localhost:8765/saml/acs`, and the Email Address NameID format.
2. Connect it to the Todo0 Resource App with the `todos.read` scope. Adding the connection is what shows the resource client's secret; note it then.
3. Put the four credentials in `examples/client/.env.saml` (git-ignored), using the same variable names as above.
4. Run `source examples/client/.env.saml && cargo run -p xaa-client -- --playground --saml`, open the URL it prints, and sign in.

Every run needs a new sign-on: the playground revokes the refresh token once it has issued an ID-JAG.

### The Resource AS, tested by the playground

The playground can also drive `xaa-resource-as`: it logs a user in, gets an ID-JAG from its IdP for your server, and redeems it at your token endpoint. The server has to be reachable from the internet, so put a tunnel in front of it.

1. Start a tunnel to the port, for example `ngrok http 4001`, and note the public `https` URL.
2. Start the server with that URL as its issuer and resource (no trailing slash), trusting the playground IdP:

   ```sh
   export XAA_RESOURCE_AS_ISSUER=https://<your-tunnel>
   export XAA_RESOURCE=https://<your-tunnel>
   export XAA_IDP_ISSUER=https://idp.xaa.dev
   export XAA_RESOURCE_AS_CLIENT_ID=xaa-playground-tester
   export XAA_RESOURCE_AS_CLIENT_SECRET=<a secret you choose>
   export XAA_ACCEPT_ANY_SUBJECT=1
   export XAA_CORS_ORIGINS=https://xaa.dev,https://app.xaa.dev
   cargo run -p xaa-resource-as
   ```

3. At <https://xaa.dev/developer/test-resource>, register a resource with the tunnel URL as the server URL and choose "Use My Own Auth Server". Enter `https://<your-tunnel>/token` as the Token Endpoint (the full path: the field is used literally), keep the discovered issuer as the bare tunnel URL, and enter the client ID and secret from step 2 as the Target Client ID and Secret. Add the `todos.read` scope and the `GET /api/todos` endpoint.
4. Click "Run All". The server logs each request and, for a refusal, the exact rule that failed.

`XAA_ACCEPT_ANY_SUBJECT` and `XAA_CORS_ORIGINS` are off by default; they exist for this kind of trial.

For the SAML path, register the resource on the SAML tab of <https://xaa.dev/developer/test-resource-app> instead and also set `XAA_SAML_ISSUERS=https://idp.xaa.dev/saml`: the server refuses a `sub_id` from a SAML issuer it was not told to trust. The account is then keyed on the whole `sub_id`, not on `sub`.
