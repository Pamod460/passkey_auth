/**
 * Passkey login integration for the Frappe login page.
 * Adds "Sign in with Passkey" button.
 */
(function () {
    "use strict";

    $(document).ready(function () {
        setTimeout(addPasskeyButton, 800);
    });

    function addPasskeyButton() {
        if (document.getElementById("passkey-login-btn")) return;
        if (typeof UCSCPasskey === "undefined" || !UCSCPasskey.utils) {
            setTimeout(addPasskeyButton, 500);
            return;
        }
        if (!UCSCPasskey.utils.isWebAuthnSupported()) return;

        // Frappe 16 login: .page-card-actions contains submit button
        // Frappe <16: #login-form .btn-primary
        var actions = document.querySelector(".for-login .page-card-actions")
            || document.querySelector(".page-card-actions")
            || document.querySelector("#login-form")
            || document.querySelector(".login-content");

        if (!actions) {
            setTimeout(addPasskeyButton, 500);
            return;
        }

        var container = document.createElement("div");
        container.id = "passkey-login-container";

        var divider = document.createElement("div");
        divider.style.cssText = "display: flex; align-items: center; margin: 8px 0; color: #8d99a6; font-size: 12px;";
        divider.innerHTML = '<div style="flex: 1; border-bottom: 1px solid #ebeef0;"></div><span style="padding: 0 12px;">or</span><div style="flex: 1; border-bottom: 1px solid #ebeef0;"></div>';

        var btn = document.createElement("button");
        btn.id = "passkey-login-btn";
        btn.type = "button";
        btn.className = "es-button w-full";
        btn.setAttribute("data-variant", "outline");
        btn.style.cssText = "display: flex; align-items: center; justify-content: center; gap: 8px;";
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>' + __("Sign in with Passkey");
        btn.addEventListener("click", handlePasskeyLogin);

        container.appendChild(divider);
        container.appendChild(btn);

        // Insert after submit button or at end of actions
        var submitBtn = actions.querySelector('button[type="submit"]');
        if (submitBtn && submitBtn.parentNode) {
            submitBtn.parentNode.insertBefore(container, submitBtn.nextSibling);
        } else {
            actions.appendChild(container);
        }
    }

    async function handlePasskeyLogin(e) {
        e.preventDefault();
        var utils = UCSCPasskey.utils;
        var btn = document.getElementById("passkey-login-btn");
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + __("Authenticating...");
        }

        try {
            var result = await utils.apiCallAsync("authentication_options", { user_email: null });
            if (!result.success) throw new Error(result.message);

            var options = result.options;
            var credentialRequestOptions = {
                publicKey: {
                    challenge: utils.base64urlDecode(options.challenge),
                    rpId: options.rpId,
                    timeout: options.timeout,
                    userVerification: options.userVerification,
                },
            };

            if (options.allowCredentials && options.allowCredentials.length > 0) {
                credentialRequestOptions.publicKey.allowCredentials = options.allowCredentials.map(function (cred) {
                    return { id: utils.base64urlDecode(cred.id), type: cred.type, transports: cred.transports };
                });
            }

            var assertion = await navigator.credentials.get(credentialRequestOptions);

            var credential = {
                id: assertion.id,
                rawId: utils.base64urlEncode(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: utils.base64urlEncode(assertion.response.clientDataJSON),
                    authenticatorData: utils.base64urlEncode(assertion.response.authenticatorData),
                    signature: utils.base64urlEncode(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? utils.base64urlEncode(assertion.response.userHandle) : null,
                },
                authenticatorAttachment: assertion.authenticatorAttachment,
                clientExtensionResults: assertion.getClientExtensionResults(),
            };

            var verifyResult = await utils.apiCallAsync("verify_authentication", {
                credential: credential,
                session_token: options._session_token || null,
            });

            if (verifyResult.success) {
                utils.showSuccess(__("Login successful! Redirecting..."));
                setTimeout(function () { window.location.href = "/app"; }, 500);
            } else {
                throw new Error(verifyResult.message);
            }
        } catch (error) {
            console.error("Passkey login error:", error);
            var message = error.name ? utils.mapWebAuthnError(error) : error.message || __("Passkey authentication failed.");
            utils.showError(message);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>' + __("Sign in with Passkey");
            }
        }
    }
})();
