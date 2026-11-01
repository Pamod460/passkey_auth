"""WebAuthn authentication (login) flow."""
import hashlib
import hmac
import json

import frappe

from .audit import log_event
from .challenges import (
    generate_challenge, get_and_clear_authentication_challenge, store_authentication_challenge,
)
from .security import (
    check_authentication_rate_limit, check_secure_context, get_client_ip, get_expected_origins,
    get_rp_id,
)
from .serialization import base64url_decode, base64url_encode
from .session import create_session_after_passkey_auth

try:
    import webauthn  # noqa: F401
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

GENERIC_FAILURE = "Passkey authentication failed."


def _settings():
    return frappe.get_single("Passkey Settings")


def _decoy_credential_id(user_email: str) -> str:
    """Stable fake credential id so unknown users / users without passkeys look identical."""
    secret = (frappe.local.conf.get("encryption_key") or frappe.local.site or "passkey").encode()
    return base64url_encode(hmac.new(secret, user_email.lower().encode(), hashlib.sha256).digest())


def get_authentication_options(user_email: str = None) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = _settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}
    if not check_authentication_rate_limit(get_client_ip()):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    rp_id = get_rp_id(settings)
    insecure = check_secure_context(settings, rp_id)
    if insecure:
        return {"success": False, "message": insecure}

    challenge = generate_challenge()
    options = {
        "rpId": rp_id,
        "challenge": base64url_encode(challenge),
        "timeout": (settings.challenge_timeout or 120) * 1000,
        "userVerification": settings.require_user_verification or "preferred",
    }

    if user_email:
        user_email = user_email.strip()
        credentials = frappe.get_all(
            "Passkey Credential",
            filters={"user": user_email, "enabled": 1, "revoked": 0},
            fields=["credential_id", "transports"],
        )
        allow = []
        for cred in credentials:
            entry = {"id": cred.credential_id, "type": "public-key"}
            try:
                transports = json.loads(cred.transports or "[]")
                if transports:
                    entry["transports"] = transports
            except (json.JSONDecodeError, TypeError):
                pass
            allow.append(entry)
        if not allow:
            # Do not reveal whether the account exists / has passkeys.
            allow = [{"id": _decoy_credential_id(user_email), "type": "public-key"}]
        options["allowCredentials"] = allow
        token = store_authentication_challenge(challenge, user_email)
    else:
        if not settings.allow_discoverable_credentials:
            return {"success": False, "message": "Discoverable credentials are not enabled."}
        token = store_authentication_challenge(challenge, None)

    return {"success": True, "options": options, "session_token": token}


def verify_authentication(credential_json: dict, session_token: str) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = _settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}

    ip = get_client_ip()
    if not check_authentication_rate_limit(ip):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    rp_id = get_rp_id(settings)
    insecure = check_secure_context(settings, rp_id)
    if insecure:
        return {"success": False, "message": insecure}

    expected_challenge, expected_user = get_and_clear_authentication_challenge(session_token)
    if not expected_challenge:
        return {"success": False, "message": "Authentication challenge expired. Please try again."}

    try:
        from webauthn.helpers import parse_authentication_credential_json
        credential = parse_authentication_credential_json(credential_json)
    except Exception as e:
        log_event(expected_user, None, "authentication", False, f"Malformed response: {e}")
        return {"success": False, "message": "Invalid authentication response."}

    credential_id = base64url_encode(credential.raw_id)
    filters = {"credential_id": credential_id, "enabled": 1, "revoked": 0}
    if expected_user:
        filters["user"] = expected_user
    cred = frappe.db.get_value(
        "Passkey Credential", filters,
        ["name", "user", "public_key", "sign_count", "user_handle"], as_dict=True,
    )
    if not cred:
        log_event(expected_user, None, "authentication", False, "Credential not found")
        return {"success": False, "message": GENERIC_FAILURE}

    user = cred.user
    # Discoverable flow: the authenticator-reported user handle must match what we issued.
    returned_handle = credential.response.user_handle
    if returned_handle is not None and cred.user_handle and returned_handle != cred.user_handle.encode("utf-8"):
        log_event(user, cred.name, "authentication", False, "User handle mismatch")
        return {"success": False, "message": GENERIC_FAILURE}

    enabled = frappe.db.get_value("User", user, "enabled")
    if not enabled:
        log_event(user, cred.name, "authentication", False, "User disabled")
        return {"success": False, "message": GENERIC_FAILURE}

    current_count = cred.sign_count or 0
    try:
        from webauthn import verify_authentication_response as webauthn_verify_auth

        verification = webauthn_verify_auth(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=get_expected_origins(settings, rp_id),
            credential_public_key=base64url_decode(cred.public_key),
            credential_current_sign_count=current_count,
            require_user_verification=(settings.require_user_verification == "required"),
        )
    except Exception as e:
        reason = str(e)
        if "sign count" in reason.lower():
            # Counter did not advance: possible cloned authenticator. Reject and record it.
            frappe.log_error(title="Passkey Sign Count Violation",
                             message=f"User: {user}, credential: {cred.name}, {reason}")
            reason = f"Possible cloned authenticator: {reason}"
        else:
            frappe.log_error(title="Passkey Verification Error", message=f"User: {user}\n{reason}")
        log_event(user, cred.name, "authentication", False, reason, sign_count_before=current_count)
        return {"success": False, "message": GENERIC_FAILURE}

    new_count = verification.new_sign_count or 0
    updates = {"last_used_at": frappe.utils.now(), "last_used_ip": ip}
    if new_count > 0:
        updates["sign_count"] = new_count
    frappe.db.set_value("Passkey Credential", cred.name, updates, update_modified=False)
    log_event(user, cred.name, "authentication", True,
              sign_count_before=current_count, sign_count_after=new_count)

    session = create_session_after_passkey_auth(user)
    if not session["success"]:
        return {"success": False, "message": session.get("message", "Session creation failed.")}
    return {"success": True, "message": "Authentication successful.", "user": user,
            "full_name": session.get("full_name", "")}
