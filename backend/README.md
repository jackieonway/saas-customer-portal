# Customer portal backend

This is an independently deployed CUSTOMER relying party, with its own
PostgreSQL database and host-only `__Host-saas_customer` cookie namespace. It
communicates with the authentication provider and registered self-profile
resource over HTTPS. It has no dependency on the platform's business crates,
account tables, memberships tables, administrator UI, or notification actor.

`main.rs` only enters the library. The library owns the browser boundary,
protocol validation, persistence, and customer-selection use cases. The only
public operations are `run()` and `migrate(database_url)`.

## Configuration

Authentication is disabled by default. `CUSTOMER_PORTAL_ENABLED=true` requires
all relying-party and resource credentials. Secrets must be independently
provisioned; the example hostnames below are development candidates and do not
constitute production registration.

| Variable | Contract |
| --- | --- |
| `DATABASE_URL` | Explicit PostgreSQL URL for this service's independent database; no `.env` discovery |
| `BIND_ADDR` | HTTP reverse-proxy target, default `127.0.0.1:8092` |
| `CUSTOMER_PORTAL_ENABLED` | Exact `true` or `false`; default `false` |
| `PUBLIC_CUSTOMER_URL` | Exact HTTPS origin, e.g. `https://customer.saas.test` |
| `OIDC_ISSUER` | Exact HTTPS issuer origin, e.g. `https://auth.saas.test`; a different hostname from the portal |
| `OIDC_CLIENT_ID` | Canonical UUIDv7 public ID of a unified CONFIDENTIAL / WEB_BFF / USER / PLATFORM_CONTEXT client with application purpose `CUSTOMER_PORTAL` and exactly `['CUSTOMER']` |
| `OIDC_CLIENT_SECRET` | Issued RP secret: 64 lowercase hex characters, separate from every service/resource secret |
| `OIDC_REDIRECT_URI` | Exactly `${PUBLIC_CUSTOMER_URL}/auth/callback` |
| `OIDC_CA_FILE` | Optional absolute PEM CA bundle for the provider; normal hostname/chain validation remains enabled |
| `IDENTITY_SERVICE_URL` | Exact private identity HTTPS origin, distinct from the public issuer; public gateways reject `/internal/*` |
| `IDENTITY_SERVICE_CA_FILE` | Required absolute PEM CA bundle for that private identity connection; hostname/chain validation remains enabled |
| `CUSTOMER_SOURCE_SERVICE_CLIENT_ID` | Canonical UUIDv7 of a dedicated `CONTEXT_SELECTION_SOURCE` service scoped only to this customer RP |
| `CUSTOMER_SOURCE_SERVICE_CLIENT_SECRET` | Independent 64-character lowercase hex service secret; never reuse the platform source service, RP, resource or consumer credential |
| `CUSTOMER_RESOURCE_URL` | Fixed private HTTPS platform resource origin, e.g. `https://platform-internal.saas.test`; the public console gateway rejects `/internal/*` |
| `CUSTOMER_RESOURCE_CLIENT_ID` | Public ID of a separate confidential USER profile client registered to the CUSTOMER profile application |
| `CUSTOMER_RESOURCE_CLIENT_SECRET` | Resource client's own secret; must differ from the RP secret |
| `CUSTOMER_RESOURCE_CA_FILE` | Optional absolute PEM CA bundle for the resource origin |
| `PORTAL_TOKEN_KEY_FILE` | Absolute private AES-256-GCM keyring JSON file |
| `CONTEXT_SELECTION_ENABLED` | Exact `true` enables centralized selection; default `false`. Requires matching identity/platform RP registrations |
| `CONTEXT_SELECTION_CONSUMER_ID` | Canonical UUIDv7 of an independent `CONTEXT_SELECTION_CONSUMER`, scoped to this RP |
| `CONTEXT_SELECTION_CONSUMER_SECRET` | Independent 32-byte random secret as 64 lowercase hex characters; different from both RP and resource credentials |

Keyring shape (the placeholder is deliberately not usable key material):

```json
{
  "activeKid": "portal-a",
  "keys": [
    {"kid": "portal-a", "key": "<32 random bytes as canonical unpadded base64url>"}
  ]
}
```

Provision 1–8 unique key IDs. Retain previous keys until their envelopes have
expired or been migrated. An envelope authenticates this service's distinct
AEAD domain, record ID, issuer, client ID and credential kind. No token, Basic
credential, login query, cookie, private key or request body is logged.

## Database and process lifecycle

Create a new portal database using an operator-owned migration role, then run
`cargo run --locked --bin portal-migrate` with its explicit `DATABASE_URL`.
The migration creates only `portal_browsers`, `portal_login_flows`,
`portal_sessions`, `portal_backchannel_logout_receipts` and
`portal_backchannel_logout_sources`, plus SQLx's migration history. All 20 UUID columns have an
individual validated RFC UUID v7 check and no UUID default. The database holds
no authority replica and cannot create customer members.

With centralized selection enabled, the authorization request binds a backend-created
interaction to state, nonce, PKCE and an optional original session/version. The
identity UI confirms application consent, then tenant, then organization. The code
extension stays on the backend. The callback saves an encrypted pending operation
before calling platform consumption. `/auth/session` can resume only that recorded
operation: it queries the existing result first and consumes only an uncommitted
selection. A lost reply or failed local save returns the same encrypted customer
capability, without another issuance or expiry extension. A pending operation
cannot serve an ordinary session or profile. `/auth/context` rejects direct choices
for the enabled mode. The frontend uses the current session CSRF and version to
start a central switch and clears displayed data before navigation.

The platform must configure its BFF AES keyring for encrypted customer-result
recovery, along with independent source verification credentials and the existing
customer proof/resource registration. The external selection consumer secret does
not authenticate ordinary profile calls. See the workspace
[selection contract](../../saas-plateform/backend/docs/designs/context-selection-contract.md)
and [verification record](../../saas-plateform/backend/docs/designs/centralized-context-selection-verification.md)
for integration limits. Production enablement still requires the real HTTPS path
and deployment-registration checks described there.

Start `saas-customer-portal-backend` under a separate runtime role with only
SELECT/INSERT/UPDATE/DELETE on the three session/flow tables, SELECT/INSERT on
the two back-channel receipt/source tables, and EXECUTE/USAGE as needed for constraints.
The runtime cannot update or delete replay facts, own schema objects, inherit
owner roles, or create schemas, tables, roles or temporary objects. The HTTP
server verifies this schema/ACL contract before listening, does not run migrations and
does not require migration history access, DDL, superuser privileges or access
to the provider/platform databases. SIGTERM and Ctrl-C stop accepting requests,
drain handlers and close the connection pool. `/health` returns only
`{"status":"ok"}`.

Terminate TLS at a trusted same-origin proxy. It must retain the original exact
Host and Origin and route `/auth/*` and `/api/profile` to this service. Disable
query/body/header access logging on authentication routes. No CORS allowlist
or cross-origin browser credential access is exposed.

## Browser API

All responses use `Cache-Control: no-store`, `Pragma: no-cache`, no-referrer and
anti-framing headers. Reads require an exact portal Origin, or same-origin
Fetch Metadata with the exact Host. Mutations require exact Origin and
`X-CSRF-Token`; Authorization headers are rejected. Query parameters are
rejected except the strictly parsed OIDC callback. JSON has an 8 KiB limit and
rejects unknown fields.

| Method/path | Request and result |
| --- | --- |
| `GET /auth/config` | `{mode:'BFF'}` when enabled, otherwise `DISABLED` |
| `GET /auth/session` | `portal-session/1` snapshot; anonymous is 200 with version `0`, CSRF, null account/context and empty members; invalid authentication is 401 and unavailable authority is 503 |
| `GET /auth/login-bootstrap` | Explicit login/reconfirmation only: always a non-authorizing anonymous snapshot and independently bound browser CSRF, including when an old session cookie remains |
| `POST /auth/login` | `{returnTo:'/'}` plus bootstrap CSRF → `{redirectTo:<fixed-issuer authorize URL>}` |
| `GET /auth/callback` | Issuer, state, independent login binder and browser generation; consumes the flow once, validates the full code exchange, then redirects to the checked local path |
| `POST /auth/context` | `{expectedVersion,membershipId}` → fresh `portal-session/1`; organization and identity version come only from authenticated server candidates |
| `GET /api/profile` | Exactly the current resource contract `{context,account}`, including only the selected CUSTOMER membership and four account presentation fields |
| `POST /auth/logout` | `{expectedVersion,scope:'PORTAL'|'GLOBAL'}` → `{redirectTo:'/signed-out'}` after the durable original command is confirmed |

Authenticated session snapshots contain `contractVersion`, `version`,
`csrfToken`, `account`, `memberships` and `context`. No OIDC token, platform
token, opaque resource context or refresh credential is returned to JavaScript.
Cookies are independent `__Host-saas_customer`,
`__Host-saas_customer_browser` and `__Host-saas_customer_login`, with Path=/,
Secure, HttpOnly, SameSite=Lax and no Domain. Logout sends no expiry cookie:
a delayed response must not erase a later login's cookie.

Only a real CUSTOMER row can be explicitly selected. Selecting the same row
again still increments the version and replaces its resource capability.
Login replacement versions are monotonic within the same browser so delayed
responses cannot share a newer login's public generation. Cross-tab work is
fenced by the original version, access ciphertext, selected member, opaque
capability and current browser pointer, with exact SQL `UPDATE RETURNING`
snapshots. It never adopts a row reloaded after another tab's write.

## Provider and resource boundaries

The public provider uses fixed discovery and canonical `/oauth/*` endpoints.
The RP requests only `openid profile` and online refresh; `offline_access` is
not a business-context capability. It validates exact discovery endpoint URLs,
RS256, bounded RSA JWKS, issuer, own audience, nonce, iat/exp and auth_time.
ID Token and UserInfo subjects remain opaque strings and must agree with the
private customer proof. The BFF never parses a pairwise subject as an internal
UUID or requires an internal SSO session ID in a public ID Token.

`POST /internal/identity/auth/customer-account-proof` is called only at
`IDENTITY_SERVICE_URL`, using the independently registered customer source
service. Its `customer-account-proof/1` response proves the exact CUSTOMER RP,
`PLATFORM_CONTEXT`, `openid profile`, opaque subject, internal account and SSO
session IDs, grant, original authentication time, account/client/application
generations and access/absolute expiry. Employee, account-only, machine,
wrong-client and revoked sources cannot establish a customer session. Context
interaction creation also uses the private identity origin, authenticated by
the RP credential for its own transaction.

Authorization-code exchange requires a valid ID Token. Refresh may omit a new
ID Token, and the original source is rechecked using the newly issued access
proof. Refresh credentials go only to token/revoke endpoints; they are never
introspected or used as an access proof. Introspection is a resource-consumer
interface rather than the BFF's source of internal account IDs.

All provider and resource HTTP for one browser operation shares a 3-second
deadline, a 1-second connect timeout, and one of 16 non-queued concurrency
slots. Proxy discovery, redirects and retries are disabled. Responses are
bounded to 64 KiB; failure never returns cached business data.

The resource uses a distinct confidential Basic client and fixed
`/internal/customer-portal/{memberships,context,profile,revoke}` endpoints. It
alone checks platform account/session source, concrete CUSTOMER membership,
organization, application and client intersection, and authority after reads.
The RP compares every source binding and emits only typed, minimal DTOs. Its
opaque `cpc_` capability is encrypted in PostgreSQL and never sent to browsers.

Refresh is a durable compare-and-swap single flight. A 3-second lease or an
unknown external result becomes uncertain and cannot replay the old refresh
credential; the user can explicitly reconfirm via the independent bootstrap
and an intact SSO session. Before rotation, the old opaque is revoked using
its original still-live access proof. If both original access and opaque have
already expired, they are non-authorizing and need no network revocation.
The original absolute deadline never increases; a shorter authority deadline
shrinks the local session. After successful rotation, the exact original member and generation must get
a new resource capability because its access-source expiry has changed.
Neither refresh nor resource renewal can change or create a membership.

`PORTAL` maps to canonical `CURRENT_APP` and revokes only the original RP grant;
`GLOBAL` also closes its original SSO source. Both commands use Basic-authenticated
`POST /oauth/logout` with the original encrypted refresh, immutable public
`sid`/`sub`, scope and durable operation ID. Recovery first queries
`POST /oauth/logout/operations/{operationId}` with the same binding. Only an
explicit `NOT_FOUND` permits submitting that same operation; unknown results
never create a replacement ID. Consent is preserved by logout. The pending
command pauses profile access and can reconcile after the original source was
revoked. A later login is never cleared by an old logout or delayed response.

The initial ID Token requires its opaque 64-character public RP `sid` and opaque
`sub`; both are stored as immutable local source fields. A refresh ID Token must
retain both; refresh without an ID Token retains the stored originals. These
public fields never replace the separate private account/grant/SSO proof IDs.

`POST /auth/backchannel-logout` accepts only a bounded form containing
`logout_token`. It uses the configured issuer's fixed JWKS and validates RS256,
`typ=logout+jwt`, exact issuer and single RP audience, UUIDv7 `jti`, matching
`sid`/`sub`, the exact empty back-channel event and an original 120-second
window. Future issuance is bounded by five seconds. Nonce, unknown or duplicate
claims/fields and query credentials are rejected. This signed service request
does not require a browser Cookie/CSRF or an already revoked access proof.

A local transaction records the issuer/client/jti digest and timestamps, plus
a durable sid/sub digest revocation fact even when the callback has not yet
created a local session, then closes the exact original local source. Repeated `jti` returns
`409 BACKCHANNEL_REPLAY`; a fresh delivery attempt for an already closed source
acknowledges without further effects. A known sid with a different sub is
rejected. Browser pointers are cleared only if they still point at the matching
source. Receipt insertion and revocation both roll back if the original expiry
passes while waiting for a lock. Callback and refresh commits acquire the same
source advisory lock before browser/session row locks and reject an already
recorded source. Thus a returned provider proof cannot insert or restore a
session after its notification was acknowledged. The source fact outlives
the individual notification's short signature window. No raw logout token or
public sid/sub is logged.

## Verification

Ordinary checks run with `cargo fmt --all -- --check`,
`cargo check --locked --all-targets --all-features`,
`cargo clippy --locked --all-targets --all-features -- -D warnings`,
`cargo test --locked --all-targets --all-features`, and
`cargo doc --locked --no-deps`.

The ignored PostgreSQL suite reads only
`IDENTITY_PHASE11_TEST_DATABASE_URL`, requires loopback and the explicit
task-owned cluster identity, creates a fresh
`identity_phase11_portal_test_<v7>` database per test and drops only that checked
name. Run it with:

```sh
cargo test --locked --all-targets --all-features phase11_pg_ -- --ignored --test-threads=1
```

It verifies UUID/schema isolation, both post-write cross-tab snapshot races,
unknown refresh no-replay, and explicit login bootstrap after an invalid old
cookie. Tests use deterministic boundaries rather than timing sleeps. Actual
shared-SSO/customer-only/profile/revocation browser acceptance is recorded by
the current deployment validation report; compiling these tests does
not itself claim that end-to-end acceptance.

Phase 20 receiver/receipt regressions are explicitly executed using
`cargo test --locked --lib tests::pg::phase20_ -- --ignored --test-threads=1`.
They use the same owned-cluster guards and clean every fixture database. They
exercise signed requests against the actual router and real local PostgreSQL,
with an explicit JWKS transport fixture; this is distinct from the full
identity/platform/portal HTTPS delivery acceptance maintained by the main task.
