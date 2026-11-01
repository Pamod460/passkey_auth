app_name = "passkey_auth"
app_title = "Passkey Authentication"
app_publisher = "UCSC"
app_description = "Production-ready WebAuthn/Passkey authentication for Frappe/ERPNext"
app_email = "admin@ucsc.cmb.ac.lk"
app_license = "MIT"

# --------------------------------------------------------------------------
# Includes
# --------------------------------------------------------------------------
# Desk: shared helpers + the after-login "set up a passkey" prompt
# (the management page ships its own JS in page/passkey-settings/).
app_include_css = "/assets/passkey_auth/css/passkey.css"
app_include_js = [
    "/assets/passkey_auth/js/passkey_utils.js",
    "/assets/passkey_auth/js/passkey_registration_popup.js",
]

# Website (login page): helpers + the "Sign in with Passkey" button.
web_include_css = "/assets/passkey_auth/css/passkey.css"
web_include_js = [
    "/assets/passkey_auth/js/passkey_utils.js",
    "/assets/passkey_auth/js/passkey_login.js",
]

# --------------------------------------------------------------------------
# Doc Events
# --------------------------------------------------------------------------
doc_events = {
    "User": {
        "after_insert": "passkey_auth.passkey_authentication.utils.generate_user_handle_on_insert",
    }
}

# --------------------------------------------------------------------------
# Login hook (enforces "passkey only" when password login is disabled)
# --------------------------------------------------------------------------
on_login = "passkey_auth.passkey_authentication.session.on_login"

# --------------------------------------------------------------------------
# Scheduler Events
# --------------------------------------------------------------------------
scheduler_events = {
    "daily": ["passkey_auth.passkey_authentication.tasks.cleanup_old_logs"],
}

# --------------------------------------------------------------------------
# Permission Hooks
# --------------------------------------------------------------------------
has_permission = {
    "Passkey Credential": "passkey_auth.passkey_authentication.doctype.passkey_credential.passkey_credential.has_permission",
    "Passkey Authentication Log": "passkey_auth.passkey_authentication.doctype.passkey_authentication_log.passkey_authentication_log.has_permission",
    "Passkey Settings": "passkey_auth.passkey_authentication.doctype.passkey_settings.passkey_settings.has_permission",
}

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
fixtures = [
    {"dt": "Custom Field", "filters": [["module", "=", "Passkey Authentication"]]},
]

# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------
after_install = "passkey_auth.passkey_authentication.setup.after_install"
