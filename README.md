# Flwn authentication module

This Go service is the backend authentication front door. It issues 15 minute
HS256 access tokens with `iss`, `aud`, `sub`, `ws`, `typ`, `scope`, `iat`,
`exp`, `jti`, and a `kid` header. It accepts only the configured issuer,
audience, algorithm, and key ID. Protected member routes recheck that the
member is active, still belongs to the token workspace, and still has every
scope in the token.

## Login and refresh

`POST /auth/login` returns an access token and sets the rotating refresh token
as an HttpOnly, SameSite=Strict cookie named `flwn_refresh`. Send that cookie
to `POST /auth/refresh` to rotate it and receive a new access token. The demo
server marks this cookie Secure; use HTTPS in deployment. The refresh and
revocation stores in this prototype are in memory, so sessions do not survive
restarts and multi-instance deployments need shared persistent stores.
For local HTTP testing only, set `REFRESH_COOKIE_SECURE=false`; keep it `true`
when serving over HTTPS.

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

