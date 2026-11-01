"""End-to-end registration + login simulation with a software authenticator.

Runs without a bench: when `frappe` is not importable, a small in-memory fake is
installed. Needs `webauthn`, `cbor2` and `cryptography`.
"""
import hashlib
import json
import os
import struct
import sys
import types
import unittest

try:
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import webauthn  # noqa: F401
    HAVE_LIBS = True
except ImportError:  # pragma: no cover
    HAVE_LIBS = False

try:
    import frappe as _real_frappe  # noqa: F401
    HAVE_REAL_FRAPPE = True
except ImportError:
    HAVE_REAL_FRAPPE = False


# ---------------------------------------------------------------------------
# Minimal in-memory frappe
# ---------------------------------------------------------------------------

class DD(dict):
    __getattr__ = dict.get

    def __setattr__(self, k, v):
        self[k] = v


class FakeCache:
    def __init__(self):
        self.store, self.counters = {}, {}

    def set_value(self, key, val, user=None, expires_in_sec=None):
        self.store[key] = val

    def get_value(self, key, *a, **k):
        return self.store.get(key)

    def delete_value(self, key, *a, **k):
        self.store.pop(key, None)

    def make_key(self, key):
        return "site|" + key

    def incr(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    def expire(self, key, secs):
        pass


class FakeDB:
    def __init__(self, tables):
        self.t = tables

    @staticmethod
    def _match(row, filters):
        for k, v in filters.items():
            if isinstance(v, list) and len(v) == 2 and v[0] == "!=":
                if row.get(k) == v[1]:
                    return False
            elif row.get(k) != v:
                return False
        return True

    def _rows(self, dt, filters):
        if isinstance(filters, str):
            filters = {"name": filters}
        return [r for r in self.t.setdefault(dt, []) if self._match(r, filters or {})]

    def get_value(self, dt, filters, fields=None, as_dict=False):
        rows = self._rows(dt, filters)
        if not rows:
            return None
        row = rows[0]
        if isinstance(fields, (list, tuple)):
            return DD({f: row.get(f) for f in fields}) if as_dict else tuple(row.get(f) for f in fields)
        return row.get(fields)

    def set_value(self, dt, name, field, val=None, update_modified=True):
        updates = field if isinstance(field, dict) else {field: val}
        for r in self._rows(dt, name):
            r.update(updates)

    def exists(self, dt, filters):
        return bool(self._rows(dt, filters))

    def count(self, dt, filters=None):
        return len(self._rows(dt, filters or {}))


def install_fake_frappe():
    state = DD(tables={"User": [], "Passkey Credential": [], "Passkey Authentication Log": []},
               sessions=[], errors=[])
    f = types.ModuleType("frappe")
    f.cache = FakeCache()
    f.db = FakeDB(state.tables)
    f.flags = DD()
    f.local = DD(conf=DD(), site="test.local")
    f.session = DD(user="Guest")
    f._ = lambda s: s
    f.AuthenticationError = type("AuthenticationError", (Exception,), {})
    f.whitelist = lambda **kw: (lambda fn: fn)
    f.parse_json = lambda v: json.loads(v) if isinstance(v, str) else v
    f.get_traceback = lambda: "traceback"
    f.log_error = lambda title=None, message=None: state.errors.append((title, message))
    f.utils = types.SimpleNamespace(now=lambda: "2026-01-01 00:00:00")
    f.request = DD(headers={"User-Agent": "Mozilla/5.0 (Windows) Chrome", "X-Forwarded-Proto": "https"},
                   host="erp.example.com", remote_addr="127.0.0.1", scheme="http")
    f.get_single = lambda name: state.settings

    def get_all(dt, filters=None, fields=None, pluck=None, order_by=None):
        rows = f.db._rows(dt, filters or {})
        if pluck:
            return [r.get(pluck) for r in rows]
        return [DD({k: r.get(k) for k in (fields or r.keys())}) for r in rows]
    f.get_all = get_all

    class Doc:
        def __init__(self, data):
            self.__dict__.update(data)

        def insert(self, ignore_permissions=False):
            table = state.tables.setdefault(self.doctype, [])
            self.name = f"{self.doctype[:3].upper()}-{len(table) + 1}"
            table.append(dict(self.__dict__))
            return self
    f.get_doc = lambda data: Doc(data)

    def delete_doc(dt, name, ignore_permissions=False):
        state.tables[dt] = [r for r in state.tables[dt] if r["name"] != name]
    f.delete_doc = delete_doc

    class LoginManager:
        user = None

        def post_login(self):
            state.sessions.append(self.user)
    f.auth = types.SimpleNamespace(LoginManager=LoginManager)

    sys.modules["frappe"] = f
    return f, state


def default_settings(**over):
    s = DD(enabled=1, rp_id="erp.example.com", rp_name="ERPNext", allowed_origins=None,
           require_user_verification="preferred", password_fallback_enabled=1, challenge_timeout=120,
           max_credentials_per_user=10, allow_discoverable_credentials=1, enable_conditional_ui=1,
           authentication_rate_limit=10, registration_rate_limit=5, audit_logging_enabled=1,
           enforce_https=1)
    s.update(over)
    return s


# ---------------------------------------------------------------------------
# Software authenticator
# ---------------------------------------------------------------------------

def b64u(b):
    from passkey_auth.passkey.serialization import base64url_encode
    return base64url_encode(b)


def unb64u(s):
    from passkey_auth.passkey.serialization import base64url_decode
    return base64url_decode(s)


class SoftAuthenticator:
    def __init__(self, uv=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0
        self.uv = uv

    def _flags(self, attested=False):
        return 0x01 | (0x04 if self.uv else 0) | (0x40 if attested else 0)

    def _client_data(self, typ, challenge_b64, origin):
        return json.dumps({"type": typ, "challenge": challenge_b64, "origin": origin,
                           "crossOrigin": False}).encode()

    def create(self, options, origin):
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        auth_data = (rp_hash + bytes([self._flags(True)]) + struct.pack(">I", self.count) + bytes(16)
                     + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cd = self._client_data("webauthn.create", options["challenge"], origin)
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att),
                             "transports": ["internal"]},
                "authenticatorAttachment": "platform", "clientExtensionResults": {}}

    def get(self, options, origin, user_handle=None, count=None):
        self.count = self.count + 1 if count is None else count
        rp_hash = hashlib.sha256(options["rpId"].encode()).digest()
        auth_data = rp_hash + bytes([self._flags()]) + struct.pack(">I", self.count)
        cd = self._client_data("webauthn.get", options["challenge"], origin)
        sig = self.key.sign(auth_data + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig),
                             "userHandle": b64u(user_handle) if user_handle else None},
                "authenticatorAttachment": "platform", "clientExtensionResults": {}}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

ORIGIN = "https://erp.example.com"
EMAIL = "alice@example.com"


@unittest.skipUnless(HAVE_LIBS, "webauthn / cbor2 / cryptography not installed")
@unittest.skipIf(HAVE_REAL_FRAPPE, "uses an in-memory fake frappe; run outside a bench")
class TestPasskeyFlow(unittest.TestCase):
    def setUp(self):
        self.frappe, self.state = install_fake_frappe()
        self.state.settings = default_settings()
        self.state.tables["User"].append({"name": EMAIL, "enabled": 1, "full_name": "Alice",
                                          "custom_passkey_user_handle": None})
        self.frappe.session.user = EMAIL
        # (re)import app modules against the fresh fake
        for m in [m for m in sys.modules if m.startswith("passkey_auth.passkey") and ".tests" not in m]:
            del sys.modules[m]
        from passkey_auth.passkey import api
        self.api = api

    def register(self, auth=None):
        auth = auth or SoftAuthenticator()
        opts = self.api.registration_options()
        self.assertTrue(opts["success"], opts)
        json.dumps(opts)  # must be JSON-serialisable (no raw bytes)
        res = self.api.verify_registration(credential=json.dumps(auth.create(opts["options"], ORIGIN)))
        return auth, res

    def login_options(self, email=None):
        self.frappe.session.user = "Guest"
        res = self.api.authentication_options(user_email=email)
        self.assertTrue(res["success"], res)
        json.dumps(res)
        return res

    # -- registration -------------------------------------------------------
    def test_register_and_metadata(self):
        auth, res = self.register()
        self.assertTrue(res["success"], res)
        cred = self.state.tables["Passkey Credential"][0]
        self.assertEqual(cred["credential_id"], b64u(auth.cred_id))
        self.assertEqual(json.loads(cred["transports"]), ["internal"])
        self.assertEqual(cred["authenticator_attachment"], "platform")
        self.assertEqual(cred["user_verified"], 1)
        self.assertTrue(cred["user_handle"])

    def test_second_passkey_same_user(self):
        _, r1 = self.register()
        _, r2 = self.register()
        self.assertTrue(r1["success"] and r2["success"], (r1, r2))
        handles = {c["user_handle"] for c in self.state.tables["Passkey Credential"]}
        self.assertEqual(len(handles), 1)

    def test_duplicate_credential_rejected(self):
        auth, _ = self.register()
        _, res = self.register(auth)
        self.assertFalse(res["success"])

    def test_registration_wrong_origin(self):
        opts = self.api.registration_options()
        auth = SoftAuthenticator()
        res = self.api.verify_registration(
            credential=json.dumps(auth.create(opts["options"], "https://evil.example.net")))
        self.assertFalse(res["success"])

    def test_guest_cannot_register(self):
        self.frappe.session.user = "Guest"
        self.assertFalse(self.api.registration_options()["success"])

    # -- login ----------------------------------------------------------------
    def test_login_with_email(self):
        auth, _ = self.register()
        res = self.login_options(EMAIL)
        self.assertEqual(res["options"]["allowCredentials"][0]["id"], b64u(auth.cred_id))
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], ORIGIN)), session_token=res["session_token"])
        self.assertTrue(out["success"], out)
        self.assertEqual(self.state.sessions, [EMAIL])
        self.assertEqual(self.state.tables["Passkey Credential"][0]["sign_count"], 1)

    def test_discoverable_login_with_none_email(self):
        auth, _ = self.register()
        res = self.login_options(None)  # the login page sends no email
        self.assertNotIn("allowCredentials", res["options"])
        handle = self.state.tables["User"][0]["custom_passkey_user_handle"].encode()
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], ORIGIN, user_handle=handle)),
            session_token=res["session_token"])
        self.assertTrue(out["success"], out)
        self.assertEqual(out["user"], EMAIL)

    def test_wrong_user_handle_rejected(self):
        auth, _ = self.register()
        res = self.login_options(None)
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], ORIGIN, user_handle=b"someone-else")),
            session_token=res["session_token"])
        self.assertFalse(out["success"])
        self.assertEqual(self.state.sessions, [])

    def test_challenge_is_single_use(self):
        auth, _ = self.register()
        res = self.login_options(EMAIL)
        cred = json.dumps(auth.get(res["options"], ORIGIN))
        self.assertTrue(self.api.verify_authentication(credential=cred, session_token=res["session_token"])["success"])
        self.assertFalse(self.api.verify_authentication(credential=cred, session_token=res["session_token"])["success"])

    def test_concurrent_attempts_do_not_collide(self):
        auth, _ = self.register()
        a, b = self.login_options(EMAIL), self.login_options(EMAIL)
        self.assertNotEqual(a["session_token"], b["session_token"])
        for res in (a, b):
            out = self.api.verify_authentication(
                credential=json.dumps(auth.get(res["options"], ORIGIN)), session_token=res["session_token"])
            self.assertTrue(out["success"], out)

    def test_wrong_origin_rejected(self):
        auth, _ = self.register()
        res = self.login_options(EMAIL)
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], "https://evil.example.net")),
            session_token=res["session_token"])
        self.assertFalse(out["success"])
        self.assertEqual(self.state.sessions, [])

    def test_sign_count_regression_rejected(self):
        auth, _ = self.register()
        for _ in range(2):
            res = self.login_options(EMAIL)
            self.api.verify_authentication(credential=json.dumps(auth.get(res["options"], ORIGIN)),
                                           session_token=res["session_token"])
        self.assertEqual(len(self.state.sessions), 2)
        res = self.login_options(EMAIL)
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], ORIGIN, count=1)),  # cloned device, counter went back
            session_token=res["session_token"])
        self.assertFalse(out["success"])
        self.assertEqual(len(self.state.sessions), 2)
        self.assertEqual(self.state.tables["Passkey Credential"][0]["sign_count"], 2)  # not reset

    def test_user_verification_required_is_enforced(self):
        auth, _ = self.register(SoftAuthenticator(uv=True))
        self.state.settings.require_user_verification = "required"
        weak = SoftAuthenticator(uv=False)
        weak.key, weak.cred_id = auth.key, auth.cred_id  # same credential, but no UV on this assertion
        res = self.login_options(EMAIL)
        out = self.api.verify_authentication(
            credential=json.dumps(weak.get(res["options"], ORIGIN)), session_token=res["session_token"])
        self.assertFalse(out["success"])

    def test_disabled_user_rejected(self):
        auth, _ = self.register()
        self.state.tables["User"][0]["enabled"] = 0
        res = self.login_options(EMAIL)
        out = self.api.verify_authentication(
            credential=json.dumps(auth.get(res["options"], ORIGIN)), session_token=res["session_token"])
        self.assertFalse(out["success"])

    def test_no_user_enumeration(self):
        self.register()
        known = self.login_options(EMAIL)["options"]
        unknown = self.login_options("nobody@example.com")["options"]
        self.assertEqual(len(known["allowCredentials"]), len(unknown["allowCredentials"]))
        self.assertEqual(set(known), set(unknown))

    def test_rate_limit(self):
        self.state.settings.authentication_rate_limit = 3
        results = [self.api.authentication_options(user_email=None)["success"] for _ in range(5)]
        self.assertEqual(results, [True, True, True, False, False])

    # -- management -----------------------------------------------------------
    def test_last_passkey_guard(self):
        auth, _ = self.register()
        name = self.state.tables["Passkey Credential"][0]["name"]
        self.state.settings.password_fallback_enabled = 0
        self.assertFalse(self.api.delete_credential(credential_name=name)["success"])
        self.state.settings.password_fallback_enabled = 1
        self.assertTrue(self.api.delete_credential(credential_name=name)["success"])

    def test_cannot_touch_other_users_credential(self):
        self.register()
        name = self.state.tables["Passkey Credential"][0]["name"]
        self.frappe.session.user = "mallory@example.com"
        self.assertFalse(self.api.delete_credential(credential_name=name)["success"])
        self.assertFalse(self.api.rename_credential(credential_name=name, nickname="x")["success"])


if __name__ == "__main__":
    unittest.main()
