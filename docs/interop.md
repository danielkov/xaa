# Interop: Known Deployment Quirks

Field notes from running the client and Resource AS against real deployments. Each entry describes a specific behavior, where to verify it, and what to do about it.

Entries marked **verified** were checked against the live service. Entries marked **docs** come from the deployment's documentation, and still need to be confirmed by the playground interop test (RFC-001 §9).

---

## xaa.dev playground

Services: IdP `https://idp.xaa.dev`, Resource AS `https://auth.resource.xaa.dev`, Resource Server `https://api.resource.xaa.dev` (Todo REST API at `/api/todos`; MCP at `https://mcp.xaa.dev/mcp`).

### Metadata (verified 2026-11-14)

- **The IdP serves only OIDC discovery.** `https://idp.xaa.dev/.well-known/openid-configuration` returns 200; `/.well-known/oauth-authorization-server` returns 404. The RFC 8414 → OIDC Discovery fallback (RFC-006 §3) is required.
- **Issuers have no trailing slash:** `https://idp.xaa.dev`, `https://auth.resource.xaa.dev`. The issuer check (draft §9.5) is byte-exact, so configure them exactly like this.
- **IdP:**
  - `identity_chaining_requested_token_types_supported` lists `urn:ietf:params:oauth:token-type:id-jag` and `urn:ietf:params:oauth:token-type:refresh_token`.
  - There is no `id_jag_signing_alg_values_supported`.
  - `token_endpoint` is `https://idp.xaa.dev/token`.
  - The JWKS at `https://idp.xaa.dev/jwks` is one RSA key, `alg` `RS256`, `kid` `demo-key`.
- **Resource AS:**
  - `authorization_grant_profiles_supported` is `["urn:ietf:params:oauth:grant-profile:id-jag"]`, and `grant_types_supported` includes `jwt-bearer`. Neither server lists `jwt-dpop`.
  - `grant_types_supported` also lists `refresh_token`, even though draft §4.4.4 says the Resource AS SHOULD NOT issue refresh tokens for ID-JAG grants. Whether it does in practice is unverified.
- **Protected Resource Metadata:**
  - `resource` is `https://api.resource.xaa.dev/`, with a trailing slash. Send it byte-for-byte (draft §4.3, RFC-003 §3).
  - `authorization_servers` is `["https://auth.resource.xaa.dev"]`, and `scopes_supported` is `todos.read` / `todos.write`.
  - It also carries `authorization_grant_profiles_supported`, which isn't a registered PRM parameter. It is preserved in `extra`.

### Client flow (verified 2026-11-14)

From a full run of `xaa-client --playground`: browser login, token exchange, access token request, Todo API call.

- **The IdP drops the trailing slash of `resource`.** Requested `https://api.resource.xaa.dev/` (the PRM spelling); the ID-JAG carries `https://api.resource.xaa.dev`. Draft §4.3.3 requires an exact echo, so the client's self-check refuses it by default. `TokenExchange::tolerate_resource_trailing_slash(true)` accepts exactly this difference (RFC-003 §5).
- **The Resource AS grants no scope unless the access token request names one.** With no `scope` parameter it answers 200 with `"scope": ""`, and the Todo API then refuses the token with 403. Sending `scope=todos.read` gets `"scope": "todos.read"` and a working token. The draft makes the parameter optional; send it.
- **`"scope": ""` is not valid under RFC 6749 §3.3.** The client reads it as "no scope granted", distinct from an omitted `scope`, which means "as requested".
- **Token exchange response:** `issued_token_type` `urn:ietf:params:oauth:token-type:id-jag`, `token_type` `N_A`, `expires_in` 300, `scope` echoed.
- **Access token response:** `token_type` `Bearer`, `expires_in` 7200, no refresh token.
- **`client_secret_post` works on both legs**, and the ID-JAG `client_id` is the resource client (`{client_id}-at-todo0`).
- **No refresh token from the OIDC login**, even with `offline_access` requested. The refresh-token subject is exercised on the SAML path below.
- **The access token `sub`** as the API reports it is `customer1:usr_…`: `{providerName}:{userSub}`.

### Client flow, SAML path (verified 2026-11-14)

From a full run of `xaa-client --playground --saml`, with a SAML app registered at <https://xaa.dev/developer/register> (SAML tab): SAML sign-on with the `saml` crate as the Service Provider, assertion → refresh token, refresh token → ID-JAG, access token request, Todo API call. All steps pass.

- **The assertion puts `<ds:Signature>` before `<saml:Issuer>`.** The SAML schema requires `Issuer` first, so `saml` rejects the Response under its default `xsd-validate` feature ("child element appears out of schema order"). The example builds `saml` without that feature. Signature, audience, timing, destination, and `InResponseTo` checks still run and pass.
- **The Response is signed twice:** the `<samlp:Response>` and the `<saml:Assertion>` each carry an RSA-SHA256 signature with exclusive c14n. The assertion's own signature is what lets it travel alone; `consume_response_with_assertion` returns it as a standalone document and the IdP accepts that.
- **`saml2` subject tokens are base64url without padding**, the crate's default `SamlEncoding`.
- **Assertion → refresh token:** needs `scope` to include `openid offline_access email` plus the resource scopes. The answer has `issued_token_type` `…:refresh_token`, `token_type` `N_A`, `expires_in` 7776000 (90 days), and the scope echoed.
- **Refresh token → ID-JAG:** same response shape as the ID Token path. The docs say the IdP revokes the refresh token once it has minted an ID-JAG, so each run needs a new sign-on.
- **The resource client's secret differs from the IdP client's.** It is only shown when the resource connection is added. The Resource AS also authenticates the IdP client ID with the IdP secret, but the ID-JAG names the `-at-todo0` client, so that pairing is not usable (RFC-003 §5).
- **The access token `sub`** as the API reports it is `saml-user-<uuid>`. The docs say `sub_id` carries the real identity on this path.
- **Registration:** `http://localhost:<port>` is accepted for the SP entity ID and the ACS URL. The IdP's metadata is at `https://idp.xaa.dev/saml/metadata`, entity ID `https://idp.xaa.dev/saml`, SSO over HTTP-Redirect and HTTP-POST.

### Resource AS flow (verified 2026-11-14)

`examples/resource-as` behind an ngrok tunnel, registered at <https://xaa.dev/developer/test-resource> as "Use My Own Auth Server", then the wizard's "Run All": login, token exchange at the playground IdP, JWT bearer grant at the example, API call to the example. All four steps pass.

- **The playground's ID-JAG passes `ResourceAs::validate` unchanged**, with every check at its strict default: `typ`, issuer trust, RS256 signature against `https://idp.xaa.dev/jwks`, `aud` equal to the issuer URL as entered (no trailing slash), `client_id` equal to the wizard's "Target Client ID", lifetime, and `resource`.
- **The wizard's "Token Endpoint" field is used literally.** Entering the issuer URL there makes discovery succeed but the grant is then POSTed to `/` (404). Enter the full `…/token` URL and keep "Auth Server URL (issuer)" as the bare issuer.
- **The grant request** is `client_secret_post` with `grant_type`, `assertion`, `client_id`, `client_secret`, and `scope`.
- **Calls come from the browser**, origin `https://xaa.dev`: discovery, the token request (after a CORS preflight), and the API call. The server must allow that origin (`XAA_CORS_ORIGINS`).
- **The wizard wants `/health`** on the resource server and reads `jwks_uri` from the metadata.
- **`sub` is an opaque user ID** (`usr_…`), not an email, so the example needs `XAA_ACCEPT_ANY_SUBJECT=1` to give playground users an account.

### Resource AS flow, SAML path (verified 2026-11-14)

The same setup, registered on the SAML tab of <https://xaa.dev/developer/test-resource-app> with the Email address NameID format, and `XAA_SAML_ISSUERS=https://idp.xaa.dev/saml` on the example. The wizard's flow passes: SAML sign-on and both exchanges at the playground IdP, JWT bearer grant at the example, API call to the example.

- **The SAML-derived ID-JAG passes `ResourceAs::validate` at strict defaults**, including the `sub_id` rules: `format` `saml-nameid`, and `sub_id.issuer` listed under the ID-JAG issuer (draft §9.8).
- **`sub_id.issuer` is `https://idp.xaa.dev/saml`**, the IdP's SAML entity ID, not a per-resource one.
- **`sub_id` carries `nameid` and `nameid_format`** (`…:nameid-format:emailAddress`) and neither qualifier, so `SamlSubjectKey::Qualified` resolves on issuer, NameID, and format.
- **Without a trusted SAML issuer the grant is refused.** `saml_issuers` is empty by default.

### Requests and tokens (docs)

- **`resource` is required at token exchange.** The draft only RECOMMENDS it. Missing `audience` or `resource` gets `invalid_request`; an unknown audience + resource pair gets `invalid_target`.
- **Client authentication is `client_secret_post` on both legs.** The draft examples use `client_assertion` on the token exchange.
- **The ID-JAG `client_id` is the requesting app's client ID at the Resource AS.**
  - It has the form `{client_id}-at-{resource_id}`, from a second registration called the "resource client".
  - Using the IdP credentials at the Resource AS gets `invalid_client`. RFC-003 §5 catches this before sending.
- **Lifetimes and skew:** ID-JAG 5 minutes (header `typ` `oauth-id-jag+jwt`, RS256). Access token 2 hours (`at+jwt`). The Resource AS rejects an `iat` more than 30 s in the future.
- **The ID-JAG carries `nbf`** according to the token-structure page. RFC-002 §6 models it, and RFC-004 §4 rule 9 checks it.
- **Single use is documented only on the SAML path** ("this jti has already been redeemed"). Draft §4.4.4 allows either policy (RFC-004 §8).
- **The access token `sub` is `{providerName}:{userSub}`.** That is vendor-specific and not in the draft.
- **Scope handling is inconsistent across the docs.** One page says a request scope that isn't a subset gets the intersection; another lists `invalid_scope`. RFC-004 §6 allows either.
- **One page says only `id_token` subject tokens are accepted**, contradicting the metadata and other pages. Tested: `saml2` (for a refresh token) and `refresh_token` (for an ID-JAG) are both accepted.
- **DPoP:** not documented and not in metadata. Treat it as unsupported. The client refuses to request DPoP binding for this Resource AS, because it lacks `jwt-dpop` (RFC-003 §3). A DPoP-bound access token can still be requested with a proof on the access token request (RFC-003 §6); whether the playground honors that is untested.
- **The SAML path cites draft-04**, not draft-06. No drift showed up in the client run.

### Testing a Resource AS

- `https://xaa.dev/developer/test-resource` registers a resource whose auth server is "Playground" or "Own".
- For "Own", discovery tries `/.well-known/oauth-authorization-server`, then `/.well-known/openid-configuration`.
- The documented validation order for an own auth server is: `typ`, `iss`, signature (JWKS), `iat`/`exp`, `client_id`, `aud`, then the subject from `sub`. RFC-004 §4 covers all of these.

---

## Spec-level ambiguities

These are tracked in RFC-001 §12 and should be raised upstream:

- **Binding to a Resource AS without `jwt-dpop`.** Draft-06 §9.11.1.1 (the IdP MUST bind a valid DPoP proof) conflicts with jwt-dpop-grant-02 §7.1 (SHOULD NOT issue a DPoP-bound grant to an AS without `jwt-dpop` support). Handled by refusing the exchange with `invalid_target` (RFC-005 §6.1).
- **Missing-proof error code.** Draft-06 §9.11.1.2.2 says `invalid_grant`; jwt-dpop-grant-02 §5 says `invalid_dpop_proof`. Handled by following jwt-dpop-grant (RFC-007 §4.2).
- **`saml2` encoding.** RFC 8693 §3 says the token type is base64url; the draft-06 §4.5 example uses padded standard base64. Handled by accepting both at the IdP and making the client's encoding configurable (RFC-003 §2, RFC-005 §2). Still worth confirming what real IdPs expect.
