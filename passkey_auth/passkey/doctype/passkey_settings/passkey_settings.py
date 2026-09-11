import json
import frappe
from frappe.model.document import Document


class PasskeySettings(Document):
    def validate(self):
        if self.rp_id:
            rp_id = self.rp_id.strip()
            if rp_id.startswith("http://") or rp_id.startswith("https://"):
                frappe.throw("RP ID must not include a scheme.")
            if "/" in rp_id:
                frappe.throw("RP ID must not contain path separators.")
            self.rp_id = rp_id

        if self.allowed_origins:
            try:
                origins = json.loads(self.allowed_origins)
                if not isinstance(origins, list):
                    frappe.throw("Allowed Origins must be a JSON array.")
                for origin in origins:
                    if not isinstance(origin, str):
                        frappe.throw("Each origin must be a string.")
            except json.JSONDecodeError:
                frappe.throw("Allowed Origins must be valid JSON.")

        if self.challenge_timeout and (self.challenge_timeout < 30 or self.challenge_timeout > 600):
            frappe.throw("Challenge timeout must be between 30 and 600 seconds.")

        if self.max_credentials_per_user and (self.max_credentials_per_user < 1 or self.max_credentials_per_user > 50):
            frappe.throw("Max credentials per user must be between 1 and 50.")


def has_permission(doc, user):
    if not user:
        user = frappe.session.user
    return frappe.db.exists("Has Role", {"parent": user, "role": "System Manager"})


def get_settings():
    return frappe.get_single("Passkey Settings")
