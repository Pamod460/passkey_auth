# passkey_auth

WebAuthn/Passkey authentication for Frappe Framework / ERPNext 16.

## Install

```bash
bench get-app /path/to/passkey_auth
bench --site <site> install-app passkey_auth
bench --site <site> migrate
bench build --app passkey_auth
bench restart
```

Then open **Passkey Settings** and set **RP ID** (e.g. `erp.example.com`). Users add passkeys at `/app/passkey-settings`
and sign in from the login page ("Sign in with Passkey", or browser autofill when conditional UI is enabled).

## Features

- Passwordless login with biometrics, PIN, or security key; several passkeys per user
- Discoverable credentials (usernameless login) and conditional UI / autofill
- Server-side enforcement of user verification when set to *required*
- Challenges are single-use, short-lived and bound to a per-attempt session token
- Sign-count regression (possible cloned authenticator) is rejected and logged
- Rate limiting (atomic Redis counters), audit log with configurable retention
- Optional "passkey only" mode: with *Allow Password Login* off, users who own an active passkey
  cannot sign in with a password (Administrator is exempt)

## Notes

- Origins: if *Allowed Origins* is empty, the origin is derived from RP ID (and the request port for localhost).
  Set it explicitly (JSON array) when serving from several hostnames.
- Behind nginx, the right-most `X-Forwarded-For` / `X-Real-IP` is trusted only when the direct peer is a private/loopback address.

## Tests

```bash
python -m unittest passkey_auth.passkey_authentication.tests.test_core passkey_auth.passkey_authentication.tests.test_flow
```
`test_flow` simulates registration and login with a software authenticator against a stubbed `frappe`;
it needs `webauthn` and `cryptography` but no bench.
