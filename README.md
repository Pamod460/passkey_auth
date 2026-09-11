# passkey_auth

Production-ready WebAuthn/Passkey authentication for Frappe Framework / ERPNext 16.

## Quick Start

```bash
bench get-app /path/to/passkey_auth
bench --site <site> install-app passkey_auth
bench --site <site> migrate
bench build
bench restart
```

## Features

- Passwordless login with biometrics, PIN, or security key
- Multiple passkeys per user (cross-device support)
- Discoverable credentials (usernameless login)
- Conditional UI / autofill integration
- Admin controls and audit logging
- Rate limiting, CSRF protection, origin validation
- Password login fallback (configurable)

## Documentation

See `passkey_auth/README.md` for full details.
