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
| `OIDC_CLIENT_ID` | Canonical RFC UUID v7 of a confidential `CUSTOMER_PORTAL` client with exactly `['CUSTOMER']` |
| `OIDC_CLIENT_SECRET` | Independently provisioned confidential RP secret, at least 32 characters |
| `OIDC_REDIRECT_URI` | Exactly `${PUBLIC_CUSTOMER_URL}/auth/callback` |
| `OIDC_CA_FILE` | Optional absolute PEM CA bundle for the provider; normal hostname/chain validation remains enabled |
| `CUSTOMER_RESOURCE_URL` | Fixed HTTPS platform resource origin, e.g. `https://console.saas.test` |
| `CUSTOMER_RESOURCE_CLIENT_ID` | Public ID of a separate confidential USER profile client registered to the CUSTOMER profile application |
| `CUSTOMER_RESOURCE_CLIENT_SECRET` | Resource client's own secret; must differ from the RP secret |
| `CUSTOMER_RESOURCE_CA_FILE` | Optional absolute PEM CA bundle for the resource origin |
| `PORTAL_TOKEN_KEY_FILE` | Absolute private AES-256-GCM keyring JSON file |

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
The migration creates only `portal_browsers`, `portal_login_flows` and
`portal_sessions`, plus SQLx's migration history. All 15 UUID columns have an
individual validated RFC UUID v7 check and no UUID default. The database holds
no authority replica and cannot create customer members.

Start `saas-customer-portal-backend` under a separate runtime role with only
SELECT/INSERT/UPDATE/DELETE on those three portal tables and EXECUTE/USAGE as
needed for their constraints. The HTTP server does not run migrations and
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
| `GET /api/profile` | Exactly Phase 6 `{context,account}`, including only the selected CUSTOMER membership and four account presentation fields |
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

The provider uses only fixed discovery/JWKS/token/UserInfo/introspection/revoke
endpoints. The RP validates exact discovery endpoint URLs, RS256, bounded RSA
JWKS, issuer, canonical UUID v7 subject/sid, own audience, nonce, iat/exp,
auth_time, own-client `oidc-account-proof/1`, exact purpose/type set, grant and
account/client policy generations. UserInfo must have the same subject.

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
After successful rotation, the exact original member and generation must get
a new resource capability because its access-source expiry has changed.
Neither refresh nor resource renewal can change or create a membership.

`PORTAL` revokes only this RP grant; `GLOBAL` uses the provider's durable
idempotent account logout command. A durable pending command pauses profile
access, can be reconciled through `/auth/session`, and retains its original
scope, grant and user. A later login is never cleared by an old logout.

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
the platform identity Phase 11 validation evidence; compiling these tests does
not itself claim that end-to-end acceptance.
