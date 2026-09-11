/**
 * After-login passkey registration prompt.
 * Shows a dialog once per session for users with no registered passkeys.
 */
(function () {
    "use strict";

    const utils = UCSCPasskey.utils;
    const SKIP_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days

    frappe.ready(function () {
        if (frappe.session.user === "Guest") return;
        if (!utils.isWebAuthnSupported()) return;
        if (window._passkey_popup_shown) return;

        const skipKey = "passkey_popup_skip_" + frappe.session.user;
        const skipTime = parseInt(localStorage.getItem(skipKey) || "0", 10);
        if (skipTime && Date.now() - skipTime < SKIP_DURATION) return;

        window._passkey_popup_shown = true;

        setTimeout(checkAndShowPopup, 2000);
    });

    async function checkAndShowPopup() {
        try {
            const status = await utils.apiCallAsync("get_status", {});
            if (!status.enabled || status.passkey_count > 0 || !status.password_allowed) return;
            showRegistrationDialog();
        } catch (e) {
            // Silently ignore — popup is non-critical
        }
    }

    function showRegistrationDialog() {
        const d = new frappe.ui.Dialog({
            title: __("Set Up Passkey"),
            indicator: "blue",
            size: "small",
            static: true,
            onhide: function () {
                if (!d._registered) {
                    const skipKey = "passkey_popup_skip_" + frappe.session.user;
                    localStorage.setItem(skipKey, String(Date.now()));
                }
            },
            primary_action_label: __("Register Passkey"),
            primary_action: function () {
                handlePopupRegister(d);
            },
            secondary_action_label: __("Skip for Now"),
            secondary_action: function () {
                d.hide();
            },
        });

        d.$body.html(
            '<div style="padding: 8px 0;">' +
                '<div style="text-align: center; margin-bottom: 16px;">' +
                    '<i class="fa fa-key" style="font-size: 48px; color: #5e64ff;"></i>' +
                "</div>" +
                '<p style="text-align: center; margin-bottom: 12px;">' +
                    __("Register a passkey to sign in with your fingerprint, face, or PIN — no password needed.") +
                "</p>" +
                '<p style="text-align: center; color: #8d99a6; font-size: 12px;">' +
                    __("You can always set this up later from Settings > Passkeys.") +
                "</p>" +
            "</div>"
        );

        d.show();
    }

    async function handlePopupRegister(dialog) {
        if (!utils.isWebAuthnSupported()) {
            utils.showError(__("Your browser does not support passkeys."));
            return;
        }

        try {
            dialog.get_primary_btn().prop("disabled", true).text(__("Registering..."));
            frappe.show_alert({ message: __("Requesting passkey..."), indicator: "blue" });

            const optionsResult = await utils.apiCallAsync("registration_options", {});
            if (!optionsResult.success) throw new Error(optionsResult.message);

            const options = optionsResult.options;
            const createOptions = {
                publicKey: {
                    rp: options.rp,
                    user: {
                        id: utils.base64urlDecode(options.user.id),
                        name: options.user.name,
                        displayName: options.user.displayName,
                    },
                    challenge: utils.base64urlDecode(options.challenge),
                    pubKeyCredParams: options.pubKeyCredParams,
                    timeout: options.timeout,
                    attestation: options.attestation || "none",
                    authenticatorSelection: options.authenticatorSelection || {},
                },
            };

            if (options.excludeCredentials && options.excludeCredentials.length > 0) {
                createOptions.publicKey.excludeCredentials = options.excludeCredentials.map(function (c) {
                    return { id: utils.base64urlDecode(c.id), type: c.type };
                });
            }

            const credential = await navigator.credentials.create(createOptions);
            const credentialData = {
                id: credential.id,
                rawId: utils.base64urlEncode(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: utils.base64urlEncode(credential.response.clientDataJSON),
                    attestationObject: utils.base64urlEncode(credential.response.attestationObject),
                },
                authenticatorAttachment: credential.authenticatorAttachment,
                clientExtensionResults: credential.getClientExtensionResults(),
            };

            const verifyResult = await utils.apiCallAsync("verify_registration", { credential: credentialData });
            if (verifyResult.success) {
                dialog._registered = true;
                dialog.hide();
                utils.showSuccess(__("Passkey registered: ") + (verifyResult.nickname || ""));
            } else {
                throw new Error(verifyResult.message);
            }
        } catch (error) {
            console.error("Passkey registration popup error:", error);
            const message = error.name ? utils.mapWebAuthnError(error) : error.message || __("Registration failed.");
            utils.showError(message);
        } finally {
            dialog.get_primary_btn().prop("disabled", false).text(__("Register Passkey"));
        }
    }
})();
