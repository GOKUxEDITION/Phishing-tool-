"""Small defensive web hardening helpers for the local analysis lab."""
from collections import defaultdict
from time import monotonic
from threading import Lock

_lock=Lock(); _hits=defaultdict(list)
def rate_limited(key: str, limit: int=60, window: int=60) -> bool:
    now=monotonic()
    with _lock:
        hits=[t for t in _hits[key] if now-t < window]
        if len(hits)>=limit: _hits[key]=hits; return True
        hits.append(now); _hits[key]=hits
        return False

def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("Referrer-Policy","no-referrer")
    response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
    return response
