"""Session management for passkey authentication."""
import frappe


def create_session_after_passkey_auth(user_email: str) -> dict:
    try:
        enabled, full_name = frappe.db.get_value("User", user_email, ["enabled", "full_name"])
    except Exception:
        return {"success": False, "message": "User account not found."}
    if not enabled:
        return {"success": False, "message": "User account is disabled."}

    try:
        # Mark this login as passkey-based so the on_login hook lets it through.
        frappe.flags.passkey_login = True
        login_manager = frappe.auth.LoginManager()
        login_manager.user = user_email
        # post_login runs the standard on_login hooks, IP / login-hour restrictions
        # and creates the session + cookies.
        login_manager.post_login()
        frappe.local.login_manager = login_manager
        return {"success": True, "message": "Login successful.", "user": user_email,
                "full_name": full_name or user_email}
    except Exception:
        frappe.log_error(title="Passkey Session Error", message=frappe.get_traceback())
        return {"success": False, "message": "Authentication failed."}


def on_login(login_manager=None):
    """`on_login` hook: enforce 'passkey only' when password login is disabled.

    Only users who already have an active passkey are blocked from password login
    (and never Administrator), so switching the setting on cannot lock out
    everyone who has not enrolled yet.
    """
    if getattr(frappe.flags, "passkey_login", False):
        return
    user = getattr(login_manager, "user", None) or frappe.session.user
    if not user or user in ("Guest", "Administrator"):
        return
    try:
        settings = frappe.get_single("Passkey Settings")
    except Exception:
        return
    if not settings.enabled or settings.password_fallback_enabled:
        return
    if frappe.db.exists("Passkey Credential", {"user": user, "enabled": 1, "revoked": 0}):
        frappe.throw(frappe._("Password login is disabled. Please sign in with your passkey."),
                     frappe.AuthenticationError)
