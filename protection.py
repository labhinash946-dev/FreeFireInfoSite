"""Rate limiting and /refresh authentication (standard library + Flask only).

Environment variables (all optional):
  REFRESH_TOKEN               Secret (24+ chars) that enables POST /refresh. Unset = endpoint disabled (404).
  REFRESH_COOLDOWN_SECONDS    Minimum gap between successful /refresh runs (default 60).
  RATE_LIMIT_INFO_PER_MIN     /player-info requests per client per minute (default 30, 0 = off).
  RATE_LIMIT_MEDIA_PER_MIN    banner/avatar image requests per client per minute (default 60, 0 = off).
  RATE_LIMIT_REFRESH_FAIL_PER_MIN  wrong-token attempts on /refresh per client per minute (default 5).
  API_KEYS                    Comma-separated keys. A request with a valid X-API-Key header uses its own,
                              higher limit instead of the shared per-IP one (for your top-up store).
  RATE_LIMIT_KEY_PER_MIN      Limit per API key (default 300, 0 = off).
  CLIENT_IP_HEADER            Header that carries the real visitor IP. Defaults: CF-Connecting-IP on Render,
                              X-Forwarded-For on Vercel, otherwise the socket address.

Limits are kept in memory per process. That is enough for one gunicorn worker; with several workers or
serverless instances each one counts separately, so the effective limit is looser.
"""
import hashlib
import hmac
import ipaddress
import os
import threading
import time

from flask import jsonify, request

MIN_TOKEN_LENGTH = 24
LIMITED_ENDPOINTS = {
    'get_account_info': ('info', 'RATE_LIMIT_INFO_PER_MIN', 30),
    'get_player_banner': ('media', 'RATE_LIMIT_MEDIA_PER_MIN', 60),
    'get_player_avatar': ('media', 'RATE_LIMIT_MEDIA_PER_MIN', 60),
}


def env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)).strip())
    except ValueError:
        return default


class RateLimiter:
    """Sliding-window counter. hit() returns 0 if allowed, else seconds until the client may retry."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def hit(self, bucket, key, limit, window=60):
        if limit <= 0:
            return 0
        now = time.time()
        k = (bucket, key)
        with self._lock:
            hits = [t for t in self._hits.get(k, ()) if now - t < window]
            if len(hits) >= limit:
                self._hits[k] = hits
                return max(1, int(window - (now - hits[0])) + 1)
            hits.append(now)
            self._hits[k] = hits
            if len(self._hits) > 10000:
                for old in [x for x, v in self._hits.items() if not v or now - v[-1] > window]:
                    self._hits.pop(old, None)
            return 0

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip():
    header = os.environ.get('CLIENT_IP_HEADER', '').strip()
    if not header:
        if os.environ.get('RENDER'):
            header = 'CF-Connecting-IP'
        elif os.environ.get('VERCEL'):
            header = 'X-Forwarded-For'
    if header:
        raw = request.headers.get(header, '')
        if header.lower() == 'x-forwarded-for':
            raw = raw.split(',')[0]
        try:
            return str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            pass  # header missing or malformed: fall back to the socket address
    return request.remote_addr or 'unknown'


def too_many(retry_after, message='Too many requests. Please slow down and try again shortly.'):
    resp = jsonify({'error': message, 'code': 'RATE_LIMITED', 'retry_after': retry_after})
    resp.status_code = 429
    resp.headers['Retry-After'] = str(retry_after)
    return resp


def _valid_api_key():
    supplied = request.headers.get('X-API-Key', '').strip()
    if not supplied:
        return None
    for key in os.environ.get('API_KEYS', '').split(','):
        key = key.strip()
        if key and hmac.compare_digest(supplied.encode(), key.encode()):
            return supplied
    return None


def _check_request_limits():
    rule = LIMITED_ENDPOINTS.get(request.endpoint)
    if not rule:
        return None
    bucket, env_name, default = rule
    key = _valid_api_key()
    if key:
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        wait = limiter.hit('key-' + bucket, digest, env_int('RATE_LIMIT_KEY_PER_MIN', 300))
    else:
        wait = limiter.hit(bucket, client_ip(), env_int(env_name, default))
    return too_many(wait) if wait else None


def init_rate_limits(app):
    app.before_request(_check_request_limits)


# ---------------------------------------------------------------- /refresh
_refresh_lock = threading.Lock()
_last_refresh = [0.0]


def refresh_token():
    token = os.environ.get('REFRESH_TOKEN', '').strip()
    return token if len(token) >= MIN_TOKEN_LENGTH else ''


def refresh_authorized():
    token = refresh_token()
    header = request.headers.get('Authorization', '')
    supplied = header[7:].strip() if header.lower().startswith('bearer ') else ''
    supplied = supplied or request.headers.get('X-Refresh-Token', '').strip()
    return bool(token and supplied) and hmac.compare_digest(supplied.encode(), token.encode())


def refresh_cooldown_wait():
    """Seconds the caller must wait before another refresh may run (0 = go ahead, and claims the slot)."""
    cooldown = env_int('REFRESH_COOLDOWN_SECONDS', 60)
    with _refresh_lock:
        now = time.time()
        wait = int(_last_refresh[0] + cooldown - now) + 1
        if cooldown > 0 and _last_refresh[0] and wait > 0:
            return wait
        _last_refresh[0] = now
        return 0


def reset_refresh_cooldown():
    with _refresh_lock:
        _last_refresh[0] = 0.0
