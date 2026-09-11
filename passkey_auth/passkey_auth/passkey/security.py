"""Security utilities: origin validation, rate limiting, IP extraction."""
import json
import frappe


def get_client_ip():
    forwarded_for = frappe.request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = frappe.request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return frappe.request.remote_addr or "unknown"


def get_user_agent():
    return frappe.request.headers.get("User-Agent", "unknown")


def get_origin():
    return frappe.request.headers.get("Origin", "")


def validate_origin(origin: str, rp_id: str) -> bool:
    if not origin:
        return False
    settings = frappe.get_single("Passkey Settings")
    if settings.allowed_origins:
        try:
            allowed = json.loads(settings.allowed_origins)
            if origin in allowed:
                return True
        except (json.JSONDecodeError, TypeError):
            pass
    if rp_id:
        if origin == f"https://{rp_id}":
            return True
        if rp_id in ("localhost", "127.0.0.1") and origin == f"http://{rp_id}":
            return True
    return False


def validate_rp_id(rp_id: str) -> bool:
    if not rp_id:
        return False
    if rp_id.startswith("http://") or rp_id.startswith("https://"):
        return False
    if "/" in rp_id:
        return False
    return rp_id == "localhost" or "." in rp_id


def check_rate_limit(key: str, limit: int, window: int = 60) -> bool:
    cache_key = f"passkey_ratelimit:{key}"
    current = frappe.cache().get(cache_key)
    if current is None:
        frappe.cache().set(cache_key, 1, expires_in_sec=window)
        return True
    count = int(current)
    if count >= limit:
        return False
    frappe.cache().set(cache_key, count + 1, expires_in_sec=window)
    return True


def check_authentication_rate_limit(ip_address: str) -> bool:
    settings = frappe.get_single("Passkey Settings")
    limit = settings.authentication_rate_limit or 10
    return check_rate_limit(f"auth:{ip_address}", limit, 60)


def check_registration_rate_limit(user_email: str) -> bool:
    settings = frappe.get_single("Passkey Settings")
    limit = settings.registration_rate_limit or 5
    return check_rate_limit(f"reg:{user_email}", limit, 60)
