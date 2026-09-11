/**
 * Passkey management UI for Frappe Desk.
 */
(function () {
    "use strict";

    function waitForDesk(callback) {
        function check() {
            if (typeof frappe !== "undefined" && frappe.session && frappe.session.user && frappe.pages) {
                callback();
            } else {
                setTimeout(check, 200);
            }
        }
        check();
    }

    waitForDesk(function () {
        var utils = UCSCPasskey.utils;

        if (!frappe.pages["passkey-settings"]) return;

        frappe.pages["passkey-settings"].on_page_load = function (wrapper) {
            var page = frappe.pages["passkey-settings"];
            page.set_title(__("Passkeys"));
            renderPasskeyPage(page, wrapper);
        };

        function renderPasskeyPage(page, wrapper) {
            var $wrapper = $(wrapper).find(".page-body");
            $wrapper.html(
                '<div class="passkey-container" style="max-width: 800px; margin: 0 auto; padding: 20px;">' +
                    '<div style="margin-bottom: 24px;">' +
                        '<h3 style="margin-bottom: 8px;">' + __("Passkeys") + "</h3>" +
                        '<p class="text-muted" style="margin-bottom: 16px;">' +
                            __("Sign in using your device's fingerprint, face recognition, PIN, or security key.") +
                        "</p>" +
                        '<button class="btn btn-primary btn-sm" id="add-passkey-btn">' +
                            '<i class="fa fa-plus"></i> ' + __("Add Passkey") +
                        "</button>" +
                    "</div>" +
                    '<div id="passkey-list-container"><div class="text-center" style="padding: 40px;"><span class="spinner-border text-primary"></span></div></div>' +
                "</div>"
            );

            $wrapper.find("#add-passkey-btn").on("click", handleAddPasskey);
            loadPasskeyList();
        }

        async function loadPasskeyList() {
            var $container = $("#passkey-list-container");
            try {
                var result = await utils.apiCallAsync("list_credentials", {});
                if (!result.success) throw new Error(result.message);

                var credentials = result.credentials || [];
                if (credentials.length === 0) {
                    $container.html(
                        '<div class="text-center" style="padding: 40px;">' +
                            '<i class="fa fa-key text-muted" style="font-size: 48px; margin-bottom: 16px;"></i>' +
                            '<p class="text-muted">' + __("No passkeys registered yet.") + "</p>" +
                        "</div>"
                    );
                    return;
                }

                var html = "";
                credentials.forEach(function (cred) {
                    var lastUsed = cred.last_used_at ? frappe.datetime.str_to_user(cred.last_used_at) : __("Never");
                    var synced = cred.backed_up ? " | " + __("Synced") : "";
                    var badge = cred.enabled ? '<span class="badge badge-success">' + __("Active") + "</span>" : '<span class="badge badge-danger">' + __("Disabled") + "</span>";

                    html += '<div style="border: 1px solid #ebeef0; border-radius: 8px; padding: 16px; margin-bottom: 12px;">' +
                        '<div style="display: flex; align-items: center; justify-content: space-between;">' +
                            '<div>' +
                                '<div style="font-weight: 600;">' + frappe.utils.escape_html(cred.nickname || __("Passkey")) + "</div>" +
                                '<div style="font-size: 12px; color: #8d99a6;">' + __("Last used: ") + lastUsed + synced + "</div>" +
                            "</div>" +
                            '<div style="display: flex; gap: 8px; align-items: center;">' +
                                badge +
                                '<button class="btn btn-xs btn-default passkey-rename" data-name="' + frappe.utils.escape_html(cred.name) + '" data-nickname="' + frappe.utils.escape_html(cred.nickname || "") + '"><i class="fa fa-pencil"></i></button>' +
                                (cred.enabled ? '<button class="btn btn-xs btn-warning passkey-revoke" data-name="' + frappe.utils.escape_html(cred.name) + '"><i class="fa fa-ban"></i></button>' : "") +
                                '<button class="btn btn-xs btn-danger passkey-delete" data-name="' + frappe.utils.escape_html(cred.name) + '"><i class="fa fa-trash"></i></button>' +
                            "</div>" +
                        "</div>" +
                    "</div>";
                });

                $container.html(html);

                $container.find(".passkey-rename").on("click", function () {
                    handleRenamePasskey($(this).data("name"), $(this).data("nickname"));
                });
                $container.find(".passkey-revoke").on("click", function () {
                    handleRevokePasskey($(this).data("name"));
                });
                $container.find(".passkey-delete").on("click", function () {
                    handleDeletePasskey($(this).data("name"));
                });
            } catch (error) {
                $container.html('<div class="alert alert-danger">' + __("Failed to load passkeys: ") + (error.message || "") + "</div>");
            }
        }

        async function handleAddPasskey() {
            if (!utils.isWebAuthnSupported()) {
                utils.showError(__("Your browser does not support passkeys."));
                return;
            }
            try {
                frappe.show_alert({ message: __("Requesting passkey..."), indicator: "blue" });

                var optionsResult = await utils.apiCallAsync("registration_options", {});
                if (!optionsResult.success) throw new Error(optionsResult.message);

                var options = optionsResult.options;
                var createOptions = {
                    publicKey: {
                        rp: options.rp,
                        user: { id: utils.base64urlDecode(options.user.id), name: options.user.name, displayName: options.user.displayName },
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

                var credential = await navigator.credentials.create(createOptions);
                var credentialData = {
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

                var verifyResult = await utils.apiCallAsync("verify_registration", { credential: credentialData });
                if (verifyResult.success) {
                    utils.showSuccess(__("Passkey registered: ") + (verifyResult.nickname || ""));
                    loadPasskeyList();
                } else {
                    throw new Error(verifyResult.message);
                }
            } catch (error) {
                console.error("Passkey registration error:", error);
                var message = error.name ? utils.mapWebAuthnError(error) : error.message || __("Registration failed.");
                utils.showError(message);
            }
        }

        function handleRenamePasskey(credentialName, currentNickname) {
            frappe.prompt({ label: __("Passkey Name"), fieldname: "new_nickname", fieldtype: "Data", reqd: 1, default: currentNickname },
                async function (values) {
                    var result = await utils.apiCallAsync("rename_credential", { credential_name: credentialName, nickname: values.new_nickname });
                    if (result.success) {
                        utils.showSuccess(__("Renamed."));
                        loadPasskeyList();
                    } else {
                        utils.showError(result.message);
                    }
                }, __("Rename Passkey"), __("Save"));
        }

        function handleRevokePasskey(credentialName) {
            frappe.confirm(__("Revoke this passkey?"),
                async function () {
                    var result = await utils.apiCallAsync("revoke_credential", { credential_name: credentialName });
                    if (result.success) { utils.showSuccess(__("Revoked.")); loadPasskeyList(); }
                    else { utils.showError(result.message); }
                });
        }

        function handleDeletePasskey(credentialName) {
            frappe.confirm(__("Permanently delete this passkey?"),
                async function () {
                    var result = await utils.apiCallAsync("delete_credential", { credential_name: credentialName });
                    if (result.success) { utils.showSuccess(__("Deleted.")); loadPasskeyList(); }
                    else { utils.showError(result.message); }
                });
        }
    });
})();
