import frappe


def execute():
    """Drop unique constraint on user_handle in Passkey Credential.

    user_handle is a user-level identifier shared across all passkeys for a
    user, so it should not be unique at the credential level.
    """
    if frappe.db.exists("DocType", "Passkey Credential"):
        frappe.db.sql(
            """
            ALTER TABLE `tabPasskey Credential`
            DROP INDEX IF EXISTS `unique_user_handle`
            """
        )
        frappe.db.commit()
