import frappe
from frappe.model.document import Document


class PasskeyCredential(Document):
    def validate(self):
        if self.credential_id:
            existing = frappe.db.exists(
                "Passkey Credential",
                {"credential_id": self.credential_id, "name": ["!=", self.name]},
            )
            if existing:
                frappe.throw("A passkey with this Credential ID already exists.")


def has_permission(doc, user):
    if not user:
        user = frappe.session.user
    if frappe.db.exists("Has Role", {"parent": user, "role": "System Manager"}):
        return True
    if doc.user == user:
        return True
    return False
