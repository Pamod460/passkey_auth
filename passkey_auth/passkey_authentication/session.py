"""Session management for passkey authentication."""
import frappe


def create_session_after_passkey_auth(user_email: str) -> dict:
    try:
        user = frappe.get_doc("User", user_email)
        if not user or not user.enabled:
            return {"success": False, "message": "User account is not enabled."}

        login_manager = frappe.auth.LoginManager()
        login_manager.user = user_email
        login_manager.login_user(user_email)
        frappe.db.commit()

        return {
            "success": True,
            "message": "Login successful.",
            "user": user_email,
            "full_name": user.full_name or user_email,
        }
    except frappe.DoesNotExistError:
        return {"success": False, "message": "User account not found."}
    except Exception as e:
        frappe.log_error(title="Passkey Session Error", message=str(e))
        return {"success": False, "message": "Authentication failed."}
