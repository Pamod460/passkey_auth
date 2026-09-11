"""Post-install setup."""
import frappe


def after_install():
    _create_custom_field_on_user()
    _create_default_settings()
    frappe.db.commit()


def _create_custom_field_on_user():
    if frappe.db.exists("Custom Field", {"dt": "User", "fieldname": "custom_passkey_user_handle"}):
        return
    frappe.get_doc({
        "doctype": "Custom Field",
        "dt": "User",
        "fieldname": "custom_passkey_user_handle",
        "fieldtype": "Data",
        "label": "Passkey User Handle",
        "hidden": 1,
        "read_only": 1,
        "no_copy": 1,
        "unique": 1,
        "description": "Internal WebAuthn user handle.",
        "module": "Passkey Authentication",
    }).insert(ignore_permissions=True)


def _create_default_settings():
    if frappe.db.exists("Passkey Settings", "Passkey Settings"):
        return
    frappe.get_doc({
        "doctype": "Passkey Settings",
        "enabled": 1,
        "rp_name": "ERPNext",
        "require_user_verification": "preferred",
        "password_fallback_enabled": 1,
        "challenge_timeout": 120,
        "max_credentials_per_user": 10,
        "allow_discoverable_credentials": 1,
        "enable_conditional_ui": 1,
        "authentication_rate_limit": 10,
        "registration_rate_limit": 5,
        "audit_logging_enabled": 1,
        "enforce_https": 1,
    }).insert(ignore_permissions=True)
