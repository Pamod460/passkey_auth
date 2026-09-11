# Passkey Authentication for Frappe/ERPNext

Production-ready WebAuthn/Passkey authentication for ERPNext 16.

## Features

- Passwordless login with biometrics, PIN, or security key
- Multiple passkeys per user
- Discoverable credentials (usernameless login)
- Conditional UI / autofill support
- Cross-device authentication
- Admin controls and audit logging
- Rate limiting and security controls
- Password login fallback

## Installation

```bash
bench get-app /path/to/passkey_auth
bench --site <site> install-app passkey_auth
bench --site <site> migrate
bench build
bench restart
```

## Configuration

Go to **Passkey Settings** in Frappe Desk:
- Set RP ID to your domain (e.g., `erp.example.com`)
- Configure allowed origins
- Enable/disable features

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `passkey_auth.api.registration_options` | User | Get registration options |
| `passkey_auth.api.verify_registration` | User | Verify registration |
| `passkey_auth.api.authentication_options` | Guest | Get auth options |
| `passkey_auth.api.verify_authentication` | Guest | Verify & login |
| `passkey_auth.api.list_credentials` | User | List passkeys |
| `passkey_auth.api.rename_credential` | User | Rename passkey |
| `passkey_auth.api.revoke_credential` | User | Revoke passkey |
| `passkey_auth.api.delete_credential` | User | Delete passkey |
| `passkey_auth.api.get_status` | Guest | Get status |

## Browser Support

Chrome 67+, Edge 18+, Firefox 60+, Safari 13+, Android Chrome, iOS Safari 14+

## License

MIT
