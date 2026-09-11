import frappe
from frappe.model.document import Document


class PasskeyAuthenticationLog(Document):
    pass


def has_permission(doc, user):
    if not user:
        user = frappe.session.user
    return frappe.db.exists("Has Role", {"parent": user, "role": "System Manager"})
