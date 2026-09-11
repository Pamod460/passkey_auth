"""Challenge management for WebAuthn operations. Stored in Redis cache."""
import os
import frappe
from .serialization import base64url_encode

_PREFIX = "passkey_challenge:"


def _get_ttl():
    try:
        s = frappe.get_single("Passkey Settings")
        if s.challenge_timeout:
            return int(s.challenge_timeout)
    except Exception:
        pass
    return 120


def generate_challenge() -> bytes:
    return os.urandom(32)


def store_registration_challenge(user_email: str, challenge: bytes):
    key = f"{_PREFIX}reg:{user_email}"
    frappe.cache().set(key, base64url_encode(challenge), expires_in_sec=_get_ttl())


def get_and_clear_registration_challenge(user_email: str):
    key = f"{_PREFIX}reg:{user_email}"
    challenge = frappe.cache().get(key)
    if challenge:
        frappe.cache().delete(key)
    return challenge


def store_authentication_challenge(user_email: str, challenge: bytes):
    key = f"{_PREFIX}auth:{user_email}"
    frappe.cache().set(key, base64url_encode(challenge), expires_in_sec=_get_ttl())


def get_and_clear_authentication_challenge(user_email: str):
    key = f"{_PREFIX}auth:{user_email}"
    challenge = frappe.cache().get(key)
    if challenge:
        frappe.cache().delete(key)
    return challenge


def store_discovery_challenge(challenge: bytes) -> str:
    token = base64url_encode(os.urandom(16))
    key = f"{_PREFIX}disc:{token}"
    frappe.cache().set(key, base64url_encode(challenge), expires_in_sec=_get_ttl())
    return token


def get_and_clear_discovery_challenge(token: str):
    key = f"{_PREFIX}disc:{token}"
    challenge = frappe.cache().get(key)
    if challenge:
        frappe.cache().delete(key)
    return challenge
