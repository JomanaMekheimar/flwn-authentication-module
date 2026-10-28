# Flwn authentication module

This Go service is the backend authentication front door. It issues 15 minute
HS256 access tokens with `iss`, `aud`, `sub`, `ws`, `typ`, `scope`, `iat`,
`exp`, `jti`, and a `kid` header. It accepts only the configured issuer,
audience, algorithm, and key ID. Protected member routes recheck that the
member is active, still belongs to the token workspace, and still has every
scope in the token.

## Login and refresh

`POST /auth/login` returns `access_token`, `refresh_token`, and `token_type` in
the JSON response. Send `refresh_token` in the JSON body to
`POST /auth/refresh`; the response contains the rotated token pair. Logout
accepts `refresh_token` in the JSON body at `POST /auth/logout`. These JSON
routes are for standalone non-browser clients and local tests. Browser clients
use `POST /auth/browser/login`, `/auth/browser/refresh`, and
`/auth/browser/logout`: refresh credentials stay in an HttpOnly cookie, and
refresh/logout require the returned CSRF token in `X-CSRF-Token`. Cookies use
`SameSite=Strict` and `Secure` follows `REFRESH_COOKIE_SECURE` (true by default).
For local HTTP browser testing only, set `FLWN_ENV=development` together with
`REFRESH_COOKIE_SECURE=false`.
The refresh and revocation stores in this prototype are in memory, so sessions
do not survive restarts and multi-instance deployments need shared persistent
stores.

## Engine integration status

The claims struct reserves the delegation fields (`mem`, `obo`, `act`,
`agent`, `run_id`, and `ctx`), while this prototype currently mints and accepts
human tokens only. No engine token mint route is exposed. The configured
audience prevents tokens issued for another audience from being accepted.
HS256 is suitable only while this backend is the sole verifier; move to
Ed25519/ES256 with a backend-held private key and a public JWKS endpoint before
adding independent engine verifiers. Engine ingress restrictions and the
frontend's use of the refresh cookie must be configured in their respective
deployments; this repository cannot enforce cloud network ingress policy.

The demo user store is local and in memory. Replace it with the real member
database before deployment.

See [INTEGRATION.md](INTEGRATION.md) for the standalone boundary audit, claim
semantics, proposed backend/engine contract, persistence interfaces, and exact
integration prerequisites. `.env.example` lists variable names only; this
application reads process environment variables and does not load dotenv files.

