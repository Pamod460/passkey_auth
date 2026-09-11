"""Utility functions for passkey authentication."""
import os
import base64
import secrets
import frappe


def generate_user_handle() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def generate_user_handle_on_insert(doc, method):
    if not doc.name:
        return
    existing = frappe.db.get_value("User", doc.name, "custom_passkey_user_handle")
    if not existing:
        handle = generate_user_handle()
        frappe.db.set_value("User", doc.name, "custom_passkey_user_handle", handle)


def get_webauthn_user_handle(user_email: str) -> str:
    handle = frappe.db.get_value("User", user_email, "custom_passkey_user_handle")
    if not handle:
        handle = generate_user_handle()
        frappe.db.set_value("User", user_email, "custom_passkey_user_handle", handle)
        frappe.db.commit()
    return handle
