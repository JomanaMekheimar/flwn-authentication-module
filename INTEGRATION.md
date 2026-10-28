# Flwn authentication integration contract

This repository contains the standalone Go authentication prototype only. The
backend, database, frontend, AI Engine, Data Engine, Atoms service, and deployment
configuration were not present in the inspected workspace. The service paths
below are proposed integration interfaces, not claims about existing routes.

## Current issuer and local API

`AuthService` is the only token issuer in this module. It currently issues human
HS256 access tokens for the configured `JWT_AUDIENCE` and verifies those tokens
in `TokenManager`. The local demo exposes `POST /auth/login`,
`POST /auth/refresh`, `POST /auth/logout`, and `GET /api/protected` for
standalone JSON clients. Browser endpoints are `POST /auth/browser/login`,
`/auth/browser/refresh`, and `/auth/browser/logout`. Browser refresh credentials
use HttpOnly cookies, and refresh/logout validate a double-submit CSRF token in
`X-CSRF-Token`. Do not use the JSON token-pair transport as a browser session.

The configured names are `HTTP_ADDR`, `JWT_SECRET` (at least 32 characters),
`JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_KEY_ID`, `ACCESS_TOKEN_TTL` (at most 15m),
`REFRESH_TOKEN_TTL`, and `REFRESH_COOKIE_SECURE`. `AGENT_TOKENS_ENABLED` is
forced to `false`; configuration fails if it is set to true. `.env.example`
documents variable names and safe placeholders; the app reads process
environment variables and does not load dotenv files. Setting
`REFRESH_COOKIE_SECURE=false` additionally requires `FLWN_ENV=development`;
the default remains secure. No deployment configuration is present.

## Canonical claims

| Claim | Meaning and current use |
| --- | --- |
| `iss` | Issuer identifier; currently `JWT_ISSUER`. |
| `aud` | Recipient; currently the single `JWT_AUDIENCE` value. A verifier must require its own audience. |
| `sub` | Authenticated human member ID. |
| `ws` | Authoritative workspace ID associated with the member. |
| `typ` | Required identity class; current value is `human`. Refresh tokens are opaque and never JWTs. |
| `scope` | Current permitted action strings, issued from `User.Scopes`; operation handlers must require their specific scope. |
| `iat`, `nbf`, `exp` | Issued-at, not-before, and expiry timestamps. |
| `jti` | Unique access-token ID. In-memory revocation exists only within one process. |
| `kid` | Signing key identifier in the JWT header. Current verifier accepts only the configured ID. |
| `mem`, `ctx` | Reserved struct fields only; neither is emitted by the current issuer. Do not populate without an agreed consumer and semantics. |
| `obo`, `act`, `agent`, `run_id` | Reserved struct fields only; none is emitted by the current issuer and no delegated identity flow is enabled. |

`atom_id` is not currently a field in `Claims`. Do not add or populate legacy
identity fields as duplicate identifiers without a concrete consumer and agreed
semantics. An agent/run contract must
define effective scopes as the intersection of current human grants, explicit
agent grants, and target-service allowed scopes. Engines must never modify
signed claims or mint trusted tokens.

## Proposed service contract (requires agreement with each owner)

| Caller → recipient | Proposed interface and audience | Scope examples | Recipient validation |
| --- | --- | --- | --- |
| Frontend → Backend | Existing human login/session and business APIs; audience `flwn-api` | User-operation scopes such as `workspace:read` or `document:write` | Backend validates signature, issuer, `aud=flwn-api`, type, expiry, current member/workspace, and each operation scope. |
| Backend → Data Engine | Backend obtains a target-specific service token; audience `flwn-data-engine` | `data:read`, `data:write` narrowed by operation/workspace | Data Engine validates trusted issuer, exact audience, service/delegation type, workspace, expiry, and required scope. |
| Backend → AI Engine | Backend obtains a target-specific service or delegated token; audience `flwn-ai-engine` | `ai:execute` plus narrowly defined tool scopes | AI Engine validates the same claims and may call only explicitly allowed tools. |
| AI Engine → Data Engine / Atoms | Only if product architecture explicitly allows; separate audience-specific authorization | Per-tool scopes, never broad inherited access | Target validates its own audience and scope. Forwarded tokens remain byte-for-byte unchanged; otherwise obtain a new token from the trusted backend. |
| Scheduled run → service | Backend-authorized run identity; target-specific audience | Run-specific scopes and resource boundary | Target validates run identity, workspace, expiry, audience, and revocation policy. |

The endpoint/path, service identity, and scopes in this table are proposals. The
backend and each engine owner must map them to actual routes, network ingress,
service credentials, and permission names. No engine route or credential flow
was available to inspect. `X-Data-API-Key`, if present in another repository,
must remain in place until its purpose is established and a replacement is
implemented and tested.

## Persistence and revocation adapter requirements

`UserStore` is the adapter boundary for authoritative member lookup. Its
production implementation must return current active status, workspace
membership, and grants. `RefreshTokenStore` is the adapter boundary for refresh
sessions; production `Rotate` must atomically consume one hash and create its
replacement across all instances. `Inspect` returns a store-issued generation;
`Rotate` receives that generation unchanged and must return a distinct
concurrent-rotation result only when that inspected generation was consumed by
another in-flight request. Retain a consumed-token generation tombstone through
the token's expiry so such requests do not get confused with a later stale,
unknown, expired, or revoked token; a new `Inspect` of a consumed token remains
invalid. The included `RefreshStore` is an in-memory
prototype and cannot provide cross-instance persistence, revocation, or session
family reuse response. The token manager's access-token revocation map is also
process-local. A production adapter should persist `jti` revocation through
expiry, or explicitly accept short-lived access tokens without immediate
revocation.

Logout revokes refresh only. Already issued access tokens remain usable until
expiry unless a verifier shares a `jti` revocation store. No family-revocation
semantics are implemented. Never log raw refresh tokens or bearer credentials.

## Browser and signing boundaries

The browser handlers use an HttpOnly refresh cookie, configurable `Secure`,
`SameSite=Strict`, a narrow auth path, and a double-submit CSRF token checked on
refresh/logout. The refresh and CSRF cookie expiries follow `REFRESH_TOKEN_TTL`;
logout sends matching cookie attributes with an expired value. The frontend must
be same-site for Strict cookies; cross-site
frontend deployment requires an explicit cookie and CSRF review. The short-lived
access token is returned in JSON; the raw refresh token is not.

HS256 is currently suitable only while one trusted backend controls both
issuance and verification. Before independent services verify tokens, migrate
to Ed25519 or ES256: private keys remain only at the issuer, each verifier gets
public keys through authenticated/controlled JWKS distribution, `kid` selects
exactly one key, unknown IDs fail closed, and key overlap/retirement is tested.
This module does not yet implement asymmetric keys or JWKS.

## Agent feature gate and completion prerequisites

Agent issuance is not implemented. `AGENT_TOKENS_ENABLED=true` is rejected.
Do not change this until backend authorization, scope intersection, target
audiences, bounded lifetimes, delegation-chain rules, revocation, and integration
tests are implemented. The module alone cannot verify those guarantees.

To complete deployment integration, obtain the backend repository and its member
and workspace repository interfaces, database conventions/migrations, frontend
session requirements, engine route and ingress definitions, service identity
provisioning, and deployment secret/key distribution configuration. Then build
adapters and cross-service tests against those actual components.
