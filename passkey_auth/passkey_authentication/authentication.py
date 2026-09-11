"""WebAuthn authentication (login) flow."""
import json
import frappe
from .serialization import base64url_encode, base64url_decode
from .challenges import (
    generate_challenge, store_authentication_challenge, get_and_clear_authentication_challenge,
    store_discovery_challenge, get_and_clear_discovery_challenge,
)
from .security import get_client_ip, get_user_agent, get_origin, check_authentication_rate_limit
from .session import create_session_after_passkey_auth
from .doctype.passkey_settings.passkey_settings import get_settings

try:
    from webauthn.helpers.structs import UserVerificationRequirement
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False


def get_authentication_options(user_email: str = None) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = get_settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}

    rp_id = settings.rp_id or (frappe.request.host.split(":")[0] if frappe.request and frappe.request.host else "localhost")
    uv = settings.require_user_verification or "preferred"

    ip = get_client_ip()
    if not check_authentication_rate_limit(ip):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    challenge = generate_challenge()

    options_dict = {
        "rpId": rp_id,
        "challenge": challenge,
        "timeout": (settings.challenge_timeout or 120) * 1000,
        "userVerification": uv,
    }

    if user_email:
        credentials = frappe.db.get_all(
            "Passkey Credential",
            filters={"user": user_email, "enabled": 1, "revoked": 0},
            fields=["credential_id", "transports"],
        )
        if not credentials:
            return {"success": False, "message": "No passkeys registered for this user."}

        allow_credentials = []
        for cred in credentials:
            entry = {"id": base64url_decode(cred.credential_id), "type": "public-key"}
            if cred.transports:
                try:
                    transports = json.loads(cred.transports)
                    if transports:
                        entry["transports"] = transports
                except (json.JSONDecodeError, TypeError):
                    pass
            allow_credentials.append(entry)

        options_dict["allowCredentials"] = allow_credentials
        store_authentication_challenge(user_email, challenge)
    else:
        if not settings.allow_discoverable_credentials:
            return {"success": False, "message": "Discoverable credentials are not enabled."}
        session_token = store_discovery_challenge(challenge)
        options_dict["_session_token"] = session_token

    return {"success": True, "options": options_dict}


def verify_authentication(user_email: str = None, credential_json: dict = None,
                          session_token: str = None, origin: str = None) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = get_settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}

    ip = get_client_ip()
    if not check_authentication_rate_limit(ip):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    rp_id = settings.rp_id or (frappe.request.host.split(":")[0] if frappe.request and frappe.request.host else "localhost")
    expected_origin = origin or _determine_expected_origin(settings, rp_id)

    try:
        from webauthn.helpers import parse_authentication_credential_json
        credential = parse_authentication_credential_json(credential_json)
    except Exception as e:
        frappe.log_error(title="Passkey Auth Parse Error", message=str(e))
        return {"success": False, "message": "Invalid authentication response."}

    # Get challenge and identify user
    expected_challenge = None
    identified_user = user_email

    if user_email:
        expected_challenge = get_and_clear_authentication_challenge(user_email)
    elif session_token:
        expected_challenge = get_and_clear_discovery_challenge(session_token)

    if not expected_challenge:
        return {"success": False, "message": "Authentication challenge expired. Please try again."}

    # Identify user from credential if discoverable flow
    credential_id = base64url_encode(credential.raw_id)

    if not identified_user:
        cred_doc = frappe.db.get_value(
            "Passkey Credential",
            {"credential_id": credential_id, "enabled": 1, "revoked": 0},
            ["user", "name", "public_key", "sign_count"],
            as_dict=True,
        )
        if not cred_doc:
            _log_event(None, None, "authentication", False, "Credential not found")
            return {"success": False, "message": "Passkey authentication failed."}
        identified_user = cred_doc.user
    else:
        cred_doc = frappe.db.get_value(
            "Passkey Credential",
            {"credential_id": credential_id, "user": identified_user, "enabled": 1, "revoked": 0},
            ["user", "name", "public_key", "sign_count"],
            as_dict=True,
        )
        if not cred_doc:
            _log_event(identified_user, None, "authentication", False, "Credential not found")
            return {"success": False, "message": "Passkey authentication failed."}

    # Verify user is active
    user_data = frappe.db.get_value("User", identified_user, ["name", "enabled", "full_name"], as_dict=True)
    if not user_data or not user_data.enabled:
        _log_event(identified_user, cred_doc.name, "authentication", False, "User disabled")
        return {"success": False, "message": "User account is disabled."}

    # Verify WebAuthn assertion
    try:
        from webauthn import verify_authentication_response as webauthn_verify_auth

        credential_public_key = base64url_decode(cred_doc.public_key)
        current_sign_count = cred_doc.sign_count or 0

        verification = webauthn_verify_auth(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=current_sign_count,
        )

        new_sign_count = verification.new_sign_count or 0

        if new_sign_count > 0:
            frappe.db.set_value("Passkey Credential", cred_doc.name, "sign_count", new_sign_count)
        frappe.db.set_value("Passkey Credential", cred_doc.name, "last_used_at", frappe.utils.now())
        frappe.db.set_value("Passkey Credential", cred_doc.name, "last_used_ip", ip)
        frappe.db.commit()

        _log_event(identified_user, cred_doc.name, "authentication", True, None,
                    sign_count_before=current_sign_count, sign_count_after=new_sign_count)

        session_result = create_session_after_passkey_auth(identified_user)
        if session_result["success"]:
            return {"success": True, "message": "Authentication successful.", "user": identified_user, "full_name": session_result.get("full_name", "")}
        else:
            return {"success": False, "message": session_result.get("message", "Session creation failed.")}

    except Exception as e:
        error_msg = str(e)
        if "sign count" in error_msg.lower():
            frappe.log_error(title="Passkey Sign Count Warning", message=f"User: {identified_user}, Error: {error_msg}")
            frappe.db.set_value("Passkey Credential", cred_doc.name, "sign_count", 0)
            frappe.db.commit()
            _log_event(identified_user, cred_doc.name, "authentication", True, f"Sign count mismatch")
            session_result = create_session_after_passkey_auth(identified_user)
            if session_result["success"]:
                return {"success": True, "message": "Authentication successful.", "user": identified_user, "full_name": session_result.get("full_name", "")}
            return {"success": False, "message": session_result.get("message", "Session creation failed.")}

        frappe.log_error(title="Passkey Auth Verification Error", message=f"User: {identified_user}, Error: {error_msg}")
        _log_event(identified_user, cred_doc.name, "authentication", False, error_msg)
        return {"success": False, "message": "Passkey authentication failed."}


def _determine_expected_origin(settings, rp_id):
    if settings.allowed_origins:
        try:
            origins = json.loads(settings.allowed_origins)
            if origins:
                return origins[0]
        except (json.JSONDecodeError, TypeError):
            pass
    protocol = "https"
    if frappe.request:
        forwarded = frappe.request.headers.get("X-Forwarded-Proto")
        if forwarded:
            protocol = forwarded
        elif "localhost" in (frappe.request.host or ""):
            protocol = "http"
    return f"{protocol}://{rp_id}"


def _log_event(user_email, credential_name, operation, success, failure_reason,
                sign_count_before=None, sign_count_after=None):
    settings = get_settings()
    if not settings.audit_logging_enabled:
        return
    try:
        data = {
            "doctype": "Passkey Authentication Log",
            "user": user_email or "Guest",
            "credential": credential_name,
            "operation": operation,
            "success": 1 if success else 0,
            "failure_reason": failure_reason,
            "ip_address": get_client_ip(),
            "user_agent": get_user_agent(),
            "origin": get_origin(),
        }
        if sign_count_before is not None:
            data["sign_count_before"] = sign_count_before
        if sign_count_after is not None:
            data["sign_count_after"] = sign_count_after
        frappe.get_doc(data).insert(ignore_permissions=True)
    except Exception:
        frappe.log_error(title="Passkey Log Error", message="Failed to log event")
