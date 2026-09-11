"""Scheduled tasks."""
import frappe


def cleanup_expired_challenges():
    frappe.logger().info("Passkey: Running daily cleanup.")
    try:
        frappe.db.sql(
            """DELETE FROM `tabPasskey Authentication Log`
               WHERE timestamp < DATE_SUB(NOW(), INTERVAL 90 DAY)"""
        )
        frappe.db.commit()
    except Exception as e:
        frappe.log_error(title="Passkey Cleanup Error", message=str(e))
