import frappe


def get_context(context):
    context.title = frappe._("Passkey Settings")
