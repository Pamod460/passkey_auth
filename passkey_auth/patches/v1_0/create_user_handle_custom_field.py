"""Patch: Create custom field and generate user handles."""
import frappe
import secrets
import base64


def execute():
    _ensure_custom_field()
    _generate_missing_handles()
    frappe.db.commit()


def _ensure_custom_field():
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


def _generate_missing_handles():
    users = frappe.db.get_all("User", filters=[["custom_passkey_user_handle", "is", "not set"], ["enabled", "=", 1], ["name", "!=", "Administrator"]], pluck="name")
    for user in users:
        handle = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        frappe.db.set_value("User", user, "custom_passkey_user_handle", handle)
    if users:
        frappe.logger().info(f"Passkey: Generated handles for {len(users)} users.")
