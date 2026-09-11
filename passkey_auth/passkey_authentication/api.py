"""API endpoints for WebAuthn/Passkey authentication."""
import frappe
from frappe import _


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
    data = frappe.request.json or {}
    credential = data.get("credential")
    if not credential:
        return {"success": False, "message": "Credential data is required."}
    from .registration import verify_registration_response
    return verify_registration_response(user, credential)


@frappe.whitelist(allow_guest=True)
def authentication_options():
    data = frappe.request.json or {}
    user_email = data.get("user_email", "").strip()
    from .authentication import get_authentication_options
    return get_authentication_options(user_email or None)


@frappe.whitelist(allow_guest=True)
def verify_authentication():
    data = frappe.request.json or {}
    user_email = data.get("user_email", "").strip() or None
    credential = data.get("credential")
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
    data = frappe.request.json or {}
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
    data = frappe.request.json or {}
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
    data = frappe.request.json or {}
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
    try:
        settings = frappe.get_single("Passkey Settings")
        enabled = bool(settings.enabled)
    except Exception:
        enabled = False
    passkey_count = 0
    user = frappe.session.user
    if user and user != "Guest":
        passkey_count = frappe.db.count("Passkey Credential", filters={"user": user, "enabled": 1, "revoked": 0})
    return {
        "success": True,
        "enabled": enabled,
        "passkey_count": passkey_count,
        "password_allowed": bool(settings.password_fallback_enabled if enabled else True),
    }
