"""API endpoints for WebAuthn/Passkey authentication.

Called from the browser as ``passkey_auth.passkey.api.<method>`` via frappe.call,
so all inputs arrive as form fields (nested objects as JSON strings).
"""
import frappe

from .audit import log_event
from .authentication import get_authentication_options as _auth_options
from .authentication import verify_authentication as _verify_auth
from .registration import get_registration_options as _reg_options
from .registration import verify_registration_response as _verify_reg

NOT_AUTHENTICATED = {"success": False, "message": "Authentication required."}


def _logged_in_user():
    user = frappe.session.user
    return None if (not user or user == "Guest") else user


def _as_dict(value):
    if isinstance(value, str):
        value = frappe.parse_json(value)
    return value if isinstance(value, dict) else None


# -- registration ------------------------------------------------------------

@frappe.whitelist(methods=["POST"])
def registration_options():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    return _reg_options(user)


@frappe.whitelist(methods=["POST"])
def verify_registration(credential=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    credential = _as_dict(credential)
    if not credential:
        return {"success": False, "message": "Credential data is required."}
    return _verify_reg(user, credential)


# -- authentication (guest) --------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["POST"])
def authentication_options(user_email=None):
    return _auth_options((user_email or "").strip() or None)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def verify_authentication(credential=None, session_token=None):
    credential = _as_dict(credential)
    if not credential or not session_token:
        return {"success": False, "message": "Credential data is required."}
    return _verify_auth(credential, session_token)


# -- management --------------------------------------------------------------

@frappe.whitelist(methods=["GET", "POST"])
def list_credentials():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    credentials = frappe.get_all(
        "Passkey Credential",
        filters={"user": user, "revoked": 0},
        fields=["name", "nickname", "device_type", "authenticator_attachment", "backed_up",
                "enabled", "created_at", "last_used_at", "aaguid"],
        order_by="created_at desc",
    )
    return {"success": True, "credentials": credentials}


def _owned_credential(user, credential_name):
    if not credential_name:
        return None
    return frappe.db.get_value("Passkey Credential", {"name": credential_name, "user": user}, "name")


def _is_last_usable_passkey(user, credential_name) -> bool:
    others = frappe.db.count("Passkey Credential", filters={
        "user": user, "enabled": 1, "revoked": 0, "name": ["!=", credential_name]})
    if others:
        return False
    return not frappe.get_single("Passkey Settings").password_fallback_enabled


@frappe.whitelist(methods=["POST"])
def rename_credential(credential_name=None, nickname=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    nickname = (nickname or "").strip()[:64]
    if not credential_name or not nickname:
        return {"success": False, "message": "Credential name and nickname are required."}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": "Credential not found."}
    frappe.db.set_value("Passkey Credential", credential_name, "nickname", nickname)
    return {"success": True, "message": "Passkey renamed."}


@frappe.whitelist(methods=["POST"])
def revoke_credential(credential_name=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    if not credential_name:
        return {"success": False, "message": "Credential name is required."}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": "Credential not found."}
    if _is_last_usable_passkey(user, credential_name):
        return {"success": False, "message": "Cannot revoke the last passkey when password login is disabled."}
    frappe.db.set_value("Passkey Credential", credential_name, {"revoked": 1, "enabled": 0})
    log_event(user, credential_name, "revocation", True)
    return {"success": True, "message": "Passkey revoked."}


@frappe.whitelist(methods=["POST"])
def delete_credential(credential_name=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    if not credential_name:
        return {"success": False, "message": "Credential name is required."}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": "Credential not found."}
    if _is_last_usable_passkey(user, credential_name):
        return {"success": False, "message": "Cannot delete the last passkey when password login is disabled."}
    frappe.delete_doc("Passkey Credential", credential_name, ignore_permissions=True)
    log_event(user, credential_name, "deletion", True)
    return {"success": True, "message": "Passkey deleted."}


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
def get_status():
    enabled = False
    password_allowed = True
    conditional_ui = False
    discoverable = False
    try:
        settings = frappe.get_single("Passkey Settings")
        enabled = bool(settings.enabled)
        if enabled:
            password_allowed = bool(settings.password_fallback_enabled)
            conditional_ui = bool(settings.enable_conditional_ui and settings.allow_discoverable_credentials)
            discoverable = bool(settings.allow_discoverable_credentials)
    except Exception:
        pass
    passkey_count = 0
    user = _logged_in_user()
    if user:
        passkey_count = frappe.db.count("Passkey Credential",
                                        filters={"user": user, "enabled": 1, "revoked": 0})
    return {"success": True, "enabled": enabled, "passkey_count": passkey_count,
            "password_allowed": password_allowed, "conditional_ui": conditional_ui,
            "discoverable": discoverable}
