"""API endpoints for WebAuthn/Passkey authentication."""
import json
import frappe
from frappe import _


def _get_data():
    """Get request data from JSON body or form-encoded args."""
    data = {}
    if frappe.request:
        if frappe.request.content_type and "json" in frappe.request.content_type:
            data = frappe.request.json or {}
        else:
            data = frappe.form_dict or {}
    return data


def _parse_credential(data):
    """Extract credential from data, handling both dict and JSON string."""
    credential = data.get("credential")
    if isinstance(credential, str):
        try:
            credential = json.loads(credential)
        except (json.JSONDecodeError, TypeError):
            pass
    return credential


@frappe.whitelist(allow_guest=True)
def registration_options():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    from .registration import get_registration_options
    return get_registration_options(user)


@frappe.whitelist(allow_guest=True)
def verify_registration():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    data = _get_data()
    credential = _parse_credential(data)
    if not credential:
        return {"success": False, "message": "Credential data is required."}
    from .registration import verify_registration_response
    return verify_registration_response(user, credential)


@frappe.whitelist(allow_guest=True)
def authentication_options():
    data = _get_data()
    user_email = data.get("user_email", "").strip()
    from .authentication import get_authentication_options
    return get_authentication_options(user_email or None)


@frappe.whitelist(allow_guest=True)
def verify_authentication():
    data = _get_data()
    user_email = data.get("user_email", "").strip() or None
    credential = _parse_credential(data)
    session_token = data.get("session_token")
    if not credential:
        return {"success": False, "message": "Credential data is required."}
    from .authentication import verify_authentication as do_verify
    return do_verify(user_email=user_email, credential_json=credential, session_token=session_token)


@frappe.whitelist()
def list_credentials():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    credentials = frappe.db.get_all(
        "Passkey Credential",
        filters={"user": user, "revoked": 0},
        fields=["name", "nickname", "device_type", "authenticator_attachment", "backed_up", "enabled", "created_at", "last_used_at", "aaguid"],
        order_by="created_at desc",
    )
    return {"success": True, "credentials": credentials}


@frappe.whitelist()
def rename_credential():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    data = _get_data()
    credential_name = data.get("credential_name")
    nickname = data.get("nickname", "").strip()
    if not credential_name or not nickname:
        return {"success": False, "message": "Credential name and nickname are required."}
    credential = frappe.db.get_value("Passkey Credential", {"name": credential_name, "user": user}, ["name"])
    if not credential:
        return {"success": False, "message": "Credential not found."}
    frappe.db.set_value("Passkey Credential", credential_name, "nickname", nickname)
    frappe.db.commit()
    return {"success": True, "message": "Passkey renamed."}


@frappe.whitelist()
def revoke_credential():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    data = _get_data()
    credential_name = data.get("credential_name")
    if not credential_name:
        return {"success": False, "message": "Credential name is required."}
    credential = frappe.db.get_value("Passkey Credential", {"name": credential_name, "user": user}, ["name", "enabled"])
    if not credential:
        return {"success": False, "message": "Credential not found."}
    active_count = frappe.db.count("Passkey Credential", filters={"user": user, "enabled": 1, "revoked": 0, "name": ["!=", credential_name]})
    if active_count == 0:
        settings = frappe.get_single("Passkey Settings")
        if not settings.password_fallback_enabled:
            return {"success": False, "message": "Cannot revoke the last passkey when password login is disabled."}
    frappe.db.set_value("Passkey Credential", credential_name, "revoked", 1)
    frappe.db.set_value("Passkey Credential", credential_name, "enabled", 0)
    frappe.db.commit()
    return {"success": True, "message": "Passkey revoked."}


@frappe.whitelist()
def delete_credential():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": "Authentication required."}
    data = _get_data()
    credential_name = data.get("credential_name")
    if not credential_name:
        return {"success": False, "message": "Credential name is required."}
    credential = frappe.db.get_value("Passkey Credential", {"name": credential_name, "user": user}, ["name"])
    if not credential:
        return {"success": False, "message": "Credential not found."}
    active_count = frappe.db.count("Passkey Credential", filters={"user": user, "enabled": 1, "revoked": 0, "name": ["!=", credential_name]})
    if active_count == 0:
        settings = frappe.get_single("Passkey Settings")
        if not settings.password_fallback_enabled:
            return {"success": False, "message": "Cannot delete the last passkey when password login is disabled."}
    frappe.delete_doc("Passkey Credential", credential_name, ignore_permissions=True)
    frappe.db.commit()
    return {"success": True, "message": "Passkey deleted."}


@frappe.whitelist(allow_guest=True)
def get_status():
    enabled = False
    password_allowed = True
    try:
        settings = frappe.get_single("Passkey Settings")
        enabled = bool(settings.enabled)
        password_allowed = bool(settings.password_fallback_enabled if enabled else True)
    except Exception:
        pass
    passkey_count = 0
    user = frappe.session.user
    if user and user != "Guest":
        passkey_count = frappe.db.count("Passkey Credential", filters={"user": user, "enabled": 1, "revoked": 0})
    return {
        "success": True,
        "enabled": enabled,
        "passkey_count": passkey_count,
        "password_allowed": password_allowed,
    }
