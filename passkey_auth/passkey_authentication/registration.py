"""WebAuthn registration flow."""
import json
import frappe
from .serialization import base64url_encode, base64url_decode
from .challenges import generate_challenge, store_registration_challenge, get_and_clear_registration_challenge
from .security import get_client_ip, get_user_agent, get_origin
from .doctype.passkey_settings.passkey_settings import get_settings

try:
    from webauthn.helpers.structs import UserVerificationRequirement
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False


def get_registration_options(user_email: str) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = get_settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}

    user = frappe.db.get_value("User", user_email, ["name", "full_name", "email", "enabled"], as_dict=True)
    if not user:
        return {"success": False, "message": "User not found."}
    if not user.enabled:
        return {"success": False, "message": "User account is disabled."}

    existing_count = frappe.db.count("Passkey Credential", filters={"user": user_email, "enabled": 1, "revoked": 0})
    max_creds = settings.max_credentials_per_user or 10
    if existing_count >= max_creds:
        return {"success": False, "message": f"Maximum number of passkeys ({max_creds}) reached."}

    from .utils import generate_user_handle
    user_handle = frappe.db.get_value("User", user_email, "custom_passkey_user_handle")
    if not user_handle:
        user_handle = generate_user_handle()
        frappe.db.set_value("User", user_email, "custom_passkey_user_handle", user_handle)
        frappe.db.commit()

    rp_id = settings.rp_id or (frappe.request.host.split(":")[0] if frappe.request and frappe.request.host else "localhost")
    rp_name = settings.rp_name or "ERPNext"

    challenge = generate_challenge()
    store_registration_challenge(user_email, challenge)

    existing_creds = frappe.db.get_all("Passkey Credential", filters={"user": user_email, "enabled": 1, "revoked": 0}, pluck="credential_id")
    exclude_credentials = []
    for cred_id in existing_creds:
        exclude_credentials.append({"id": cred_id, "type": "public-key"})

    uv = settings.require_user_verification or "preferred"

    user_handle_b64 = base64url_encode(user_handle.encode("utf-8"))
    display_name = user.full_name or user.email or user_email

    options_dict = {
        "rp": {"name": rp_name, "id": rp_id},
        "user": {"id": user_handle_b64, "name": user_email, "displayName": display_name},
        "challenge": base64url_encode(challenge),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": (settings.challenge_timeout or 120) * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": uv,
        },
    }

    if exclude_credentials:
        options_dict["excludeCredentials"] = exclude_credentials

    return {"success": True, "options": options_dict, "challenge": base64url_encode(challenge)}


def verify_registration_response(user_email: str, credential_json: dict, origin: str = None) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = get_settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}

    expected_challenge = get_and_clear_registration_challenge(user_email)
    if not expected_challenge:
        return {"success": False, "message": "Registration challenge expired. Please try again."}

    rp_id = settings.rp_id or (frappe.request.host.split(":")[0] if frappe.request and frappe.request.host else "localhost")
    expected_origin = origin or _determine_expected_origin(settings, rp_id)

    try:
        from webauthn.helpers import parse_registration_credential_json
        from webauthn import verify_registration_response as webauthn_verify_reg

        credential = parse_registration_credential_json(credential_json)
        verification = webauthn_verify_reg(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
        )

        credential_id = base64url_encode(verification.credential_id)
        public_key = base64url_encode(verification.credential_public_key)
        sign_count = verification.sign_count

        if frappe.db.exists("Passkey Credential", {"credential_id": credential_id}):
            return {"success": False, "message": "This passkey is already registered."}

        user_handle = frappe.db.get_value("User", user_email, "custom_passkey_user_handle")

        # Extract metadata
        device_type = "cross-platform"
        backed_up = False
        aaguid = ""

        auth_data_raw = getattr(verification, "auth_data", None)
        if auth_data_raw and len(auth_data_raw) > 53:
            try:
                aaguid = auth_data_raw[37:53].hex()
                flags = auth_data_raw[32]
                backed_up = bool(flags & 0x08)
            except Exception:
                pass

        nickname = _suggest_nickname(user_email)

        cred_doc = frappe.get_doc({
            "doctype": "Passkey Credential",
            "user": user_email,
            "credential_id": credential_id,
            "public_key": public_key,
            "user_handle": user_handle or "",
            "sign_count": sign_count,
            "transports": "[]",
            "device_type": device_type,
            "backed_up": 1 if backed_up else 0,
            "backup_eligible": 0,
            "authenticator_attachment": "none",
            "aaguid": aaguid,
            "nickname": nickname,
            "enabled": 1,
            "revoked": 0,
            "created_ip": get_client_ip(),
            "user_agent": get_user_agent(),
            "origin": expected_origin,
            "rp_id": rp_id,
        })
        cred_doc.insert(ignore_permissions=True)
        frappe.db.commit()

        _log_event(user_email, cred_doc.name, "registration", True, None)

        return {"success": True, "message": "Passkey registered successfully.", "credential_name": cred_doc.name, "nickname": nickname}

    except Exception as e:
        frappe.log_error(title="Passkey Registration Error", message=f"User: {user_email}, Error: {str(e)}")
        _log_event(user_email, None, "registration", False, str(e))
        return {"success": False, "message": "Passkey registration failed. Please try again."}


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


def _suggest_nickname(user_email):
    ua = get_user_agent().lower()
    if "windows" in ua:
        if "edg/" in ua:
            return "Windows Edge Passkey"
        elif "chrome" in ua:
            return "Windows Chrome Passkey"
        return "Windows Passkey"
    elif "macintosh" in ua or "macos" in ua:
        return "Mac Passkey"
    elif "linux" in ua:
        return "Linux Passkey"
    elif "android" in ua:
        return "Android Passkey"
    elif "iphone" in ua or "ipad" in ua:
        return "iOS Passkey"
    count = frappe.db.count("Passkey Credential", filters={"user": user_email, "enabled": 1})
    return f"Passkey {count + 1}"


def _log_event(user_email, credential_name, operation, success, failure_reason):
    settings = get_settings()
    if not settings.audit_logging_enabled:
        return
    try:
        frappe.get_doc({
            "doctype": "Passkey Authentication Log",
            "user": user_email or "Guest",
            "credential": credential_name,
            "operation": operation,
            "success": 1 if success else 0,
            "failure_reason": failure_reason,
            "ip_address": get_client_ip(),
            "user_agent": get_user_agent(),
            "origin": get_origin(),
        }).insert(ignore_permissions=True)
    except Exception:
        frappe.log_error(title="Passkey Log Error", message="Failed to log event")
