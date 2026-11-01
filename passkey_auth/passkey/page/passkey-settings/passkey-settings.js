frappe.pages["passkey-settings"].on_page_load = function (wrapper) {
    const utils = UCSCPasskey.utils;
    const page = frappe.ui.make_app_page({
        parent: wrapper,
        title: __("Passkeys"),
        single_column: true,
    });

    page.set_primary_action(__("Add Passkey"), handleAdd, "add");
    $(page.body).html(
        '<div class="passkey-container">' +
            '<p class="text-muted">' +
                __("Sign in using your device's fingerprint, face recognition, PIN, or security key.") +
            "</p>" +
            '<div id="passkey-list-container"></div>' +
        "</div>"
    );
    const $list = $(page.body).find("#passkey-list-container");
    load();

    async function load() {
        $list.html('<div class="text-center" style="padding:40px"><span class="spinner-border text-primary"></span></div>');
        try {
            const result = await utils.apiCallAsync("list_credentials", {});
            if (!result.success) throw new Error(result.message);
            render(result.credentials || []);
        } catch (e) {
            $list.html('<div class="alert alert-danger">' + __("Failed to load passkeys.") + "</div>");
        }
    }

    function render(credentials) {
        if (!credentials.length) {
            $list.html('<div class="text-center text-muted" style="padding:40px">' + __("No passkeys registered yet.") + "</div>");
            return;
        }
        const esc = frappe.utils.escape_html;
        const rows = credentials.map(function (c) {
            const lastUsed = c.last_used_at ? frappe.datetime.str_to_user(c.last_used_at) : __("Never");
            const created = c.created_at ? frappe.datetime.str_to_user(c.created_at) : "";
            const synced = c.backed_up ? " · " + __("Synced") : "";
            const badge = c.enabled
                ? '<span class="badge badge-success">' + __("Active") + "</span>"
                : '<span class="badge badge-danger">' + __("Disabled") + "</span>";
            return '<div class="passkey-card" data-name="' + esc(c.name) + '" data-nickname="' + esc(c.nickname || "") + '">' +
                '<div class="passkey-card-info">' +
                    '<div class="passkey-card-title">' + esc(c.nickname || __("Passkey")) + "</div>" +
                    '<div class="passkey-card-meta">' + __("Created") + ": " + esc(created) + " · " +
                        __("Last used") + ": " + esc(lastUsed) + esc(synced) + "</div>" +
                "</div>" +
                '<div class="passkey-card-actions">' + badge +
                    '<button class="btn btn-xs btn-default act-rename" title="' + __("Rename") + '"><i class="fa fa-pencil"></i></button>' +
                    (c.enabled ? '<button class="btn btn-xs btn-warning act-revoke" title="' + __("Revoke") + '"><i class="fa fa-ban"></i></button>' : "") +
                    '<button class="btn btn-xs btn-danger act-delete" title="' + __("Delete") + '"><i class="fa fa-trash"></i></button>' +
                "</div></div>";
        });
        $list.html(rows.join(""));
        $list.find(".act-rename").on("click", function () { rename($(this).closest(".passkey-card")); });
        $list.find(".act-revoke").on("click", function () { act("revoke_credential", $(this).closest(".passkey-card"), __("Revoke this passkey?")); });
        $list.find(".act-delete").on("click", function () { act("delete_credential", $(this).closest(".passkey-card"), __("Permanently delete this passkey?")); });
    }

    async function handleAdd() {
        if (!utils.isWebAuthnSupported()) {
            utils.showError(__("Your browser does not support passkeys."));
            return;
        }
        try {
            const opts = await utils.apiCallAsync("registration_options", {});
            if (!opts.success) throw new Error(opts.message);

            const credential = await navigator.credentials.create({ publicKey: utils.toCreationOptions(opts.options) });
            const verify = await utils.apiCallAsync("verify_registration", {
                credential: utils.serializeAttestation(credential),
            });
            if (!verify.success) throw new Error(verify.message);

            utils.showSuccess(__("Passkey registered: ") + (verify.nickname || ""));
            load();
        } catch (error) {
            console.error("Passkey registration error:", error);
            utils.showError(error.name ? utils.mapWebAuthnError(error) : (error.message || __("Registration failed.")));
        }
    }

    function rename($card) {
        frappe.prompt(
            { label: __("Passkey Name"), fieldname: "nickname", fieldtype: "Data", reqd: 1, default: $card.data("nickname") },
            async function (values) {
                const r = await utils.apiCallAsync("rename_credential", { credential_name: $card.data("name"), nickname: values.nickname });
                r.success ? (utils.showSuccess(__("Renamed.")), load()) : utils.showError(r.message);
            },
            __("Rename Passkey"), __("Save")
        );
    }

    function act(method, $card, question) {
        frappe.confirm(question, async function () {
            const r = await utils.apiCallAsync(method, { credential_name: $card.data("name") });
            r.success ? (utils.showSuccess(r.message), load()) : utils.showError(r.message);
        });
    }
};
