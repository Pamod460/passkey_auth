/**
 * Passkey utility functions for base64url encoding/decoding and WebAuthn helpers.
 */
window.UCSCPasskey = window.UCSCPasskey || {};

UCSCPasskey.utils = {
    base64urlEncode: function (buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },

    base64urlDecode: function (str) {
        str = str.replace(/-/g, "+").replace(/_/g, "/");
        while (str.length % 4) {
            str += "=";
        }
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    isWebAuthnSupported: function () {
        return window.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === "function";
    },

    showToast: function (message, type) {
        type = type || "info";
        frappe.show_alert({
            message: message,
            indicator: type === "success" ? "green" : type === "error" ? "red" : "blue",
        });
    },

    showError: function (message) {
        frappe.msgprint({ title: __("Error"), indicator: "red", message: message });
    },

    showSuccess: function (message) {
        frappe.show_alert({ message: message, indicator: "green" });
    },

    mapWebAuthnError: function (error) {
        const errorMap = {
            NotAllowedError: __("Authentication was cancelled or not allowed."),
            InvalidStateError: __("Passkey is not valid for this request."),
            SecurityError: __("A security error occurred. Ensure you are using HTTPS."),
            NotSupportedError: __("WebAuthn is not supported in this browser."),
            ConstraintError: __("The authenticator does not meet the required constraints."),
            AbortError: __("The operation was aborted."),
            OperationError: __("An operation error occurred. Please try again."),
        };
        return errorMap[error.name] || error.message || __("An unexpected error occurred.");
    },

    apiCallAsync: function (method, args) {
        return new Promise(function (resolve, reject) {
            var safeArgs = args || {};
            if (safeArgs.credential && typeof safeArgs.credential === "object") {
                safeArgs.credential = JSON.stringify(safeArgs.credential);
            }
            frappe.call({
                method: "passkey_auth.passkey_authentication.api." + method,
                args: safeArgs,
                callback: function (r) {
                    resolve(r.message || r);
                },
                error: function (r) {
                    reject(r);
                },
            });
        });
    },
};
