"""Security utilities: client IP, RP ID / origin resolution, rate limiting."""
import ipaddress
import json

import frappe

from .challenges import _cache


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _is_internal(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def get_client_ip() -> str:
    """Client IP, honouring proxy headers only when the direct peer is a local/private proxy.

    Behind nginx (which appends the real peer address) the right-most
    X-Forwarded-For entry is the one our proxy added; left-most entries are
    client-controlled and must not be trusted.
    """
    req = frappe.request
    if not req:
        return "unknown"
    remote = req.remote_addr or ""
    if remote and not _is_internal(remote):
        return remote
    real_ip = req.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded_for = req.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return remote or "unknown"


def get_user_agent() -> str:
    return (frappe.request.headers.get("User-Agent", "unknown") if frappe.request else "unknown")[:500]


def get_origin() -> str:
    return frappe.request.headers.get("Origin", "") if frappe.request else ""


def _request_scheme() -> str:
    req = frappe.request
    if not req:
        return "https"
    forwarded = req.headers.get("X-Forwarded-Proto")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.scheme or "https"


# ---------------------------------------------------------------------------
# RP ID / origin
# ---------------------------------------------------------------------------

def validate_rp_id(rp_id: str) -> bool:
    if not rp_id:
        return False
    if rp_id.startswith("http://") or rp_id.startswith("https://"):
        return False
    if "/" in rp_id or ":" in rp_id:
        return False
    return rp_id == "localhost" or "." in rp_id


def get_rp_id(settings) -> str:
    if settings.rp_id:
        return settings.rp_id.strip()
    if frappe.request and frappe.request.host:
        return frappe.request.host.split(":")[0]
    return "localhost"


def parse_allowed_origins(settings) -> list:
    if not settings.allowed_origins:
        return []
    try:
        origins = json.loads(settings.allowed_origins)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(origins, list):
        return []
    return [o.strip().rstrip("/") for o in origins if isinstance(o, str) and o.strip()]


def get_expected_origins(settings, rp_id: str) -> list:
    """All origins a ceremony may legitimately come from."""
    origins = parse_allowed_origins(settings)
    if origins:
        return origins
    scheme = _request_scheme()
    host = frappe.request.host if frappe.request and frappe.request.host else rp_id
    # Keep the port (e.g. localhost:8000) only when the host really is the RP ID.
    if host.split(":")[0] != rp_id:
        host = rp_id
    return [f"{scheme}://{host}"]


def check_secure_context(settings, rp_id: str):
    """Return an error message when HTTPS is enforced but not used, else None."""
    if not settings.enforce_https:
        return None
    if rp_id in ("localhost", "127.0.0.1"):
        return None
    if _request_scheme() != "https":
        return "Passkeys require a secure (HTTPS) connection."
    return None


# ---------------------------------------------------------------------------
# Rate limiting (atomic counter with fixed window)
# ---------------------------------------------------------------------------

def check_rate_limit(key: str, limit: int, window: int = 60) -> bool:
    try:
        cache = _cache()
        rkey = cache.make_key(f"passkey_ratelimit:{key}")
        count = cache.incr(rkey)
        if count == 1:
            cache.expire(rkey, window)
        return count <= limit
    except Exception:
        frappe.log_error(title="Passkey Rate Limit Error", message=frappe.get_traceback())
        return True


def check_authentication_rate_limit(ip_address: str) -> bool:
    settings = frappe.get_single("Passkey Settings")
    return check_rate_limit(f"auth:{ip_address}", settings.authentication_rate_limit or 10, 60)


def check_registration_rate_limit(user_email: str) -> bool:
    settings = frappe.get_single("Passkey Settings")
    return check_rate_limit(f"reg:{user_email}", settings.registration_rate_limit or 5, 60)
