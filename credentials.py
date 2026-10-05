"""Optional complete credential overrides. Never mix an override with defaults."""
import os
from urllib.parse import urlencode
from protocol import UpstreamError

AMERICAS = {'BR', 'US', 'NA', 'SAC', 'EUROPE'}
GLOBAL = {'BD', 'SG', 'ME', 'PK', 'CIS', 'RU'}


def get_override(region):
    region = region.strip().upper()
    region = 'EUROPE' if region == 'EU' else region
    group = 'AMERICAS' if region in AMERICAS else 'GLOBAL' if region in GLOBAL else region
    for scope in dict.fromkeys((region, group)):
        uid = os.environ.get(f'FREEFIRE_{scope}_UID')
        password = os.environ.get(f'FREEFIRE_{scope}_PASSWORD')
        if uid is None and password is None:
            continue
        if not uid or not password or not uid.isascii() or not uid.isdigit():
            raise UpstreamError('CREDENTIAL_CONFIG_ERROR',
                                f'Configure a complete valid credential pair for {scope}.', 503)
        return urlencode({'uid': uid, 'password': password})
    return None

# Service accounts are NOT stored in the repository. Provide them with, in order of precedence:
#   1. per-region FREEFIRE_<REGION>_UID / FREEFIRE_<REGION>_PASSWORD variables (get_override),
#   2. FREEFIRE_ACCOUNTS: "UID PASSWORD REGION" rows, one per line (use this on hosts such as Render),
#   3. a local, git-ignored accounts.txt in the same format (local development only).
# See accounts.example.txt and docs/ACCOUNT_CONFIGURATION.md.
from pathlib import Path
ACCOUNTS_FILE = Path(__file__).resolve().with_name('accounts.txt')


def _account_lines():
    env_rows = os.environ.get('FREEFIRE_ACCOUNTS', '').strip()
    if env_rows:
        # Hosts that only accept single-line values may use a literal backslash-n as the separator.
        return env_rows.replace('\\n', '\n').splitlines()
    try:
        return ACCOUNTS_FILE.read_text(encoding='utf-8-sig').splitlines()
    except (OSError, UnicodeError) as exc:
        raise UpstreamError('CREDENTIAL_CONFIG_ERROR',
                            'No service accounts configured. Set FREEFIRE_ACCOUNTS or the per-region '
                            'FREEFIRE_<REGION>_UID / FREEFIRE_<REGION>_PASSWORD variables.', 503) from exc
KNOWN_SCOPES = AMERICAS | GLOBAL | {'IND', 'VN', 'ID', 'TH', 'TW', 'AMERICAS', 'GLOBAL'}


def get_credentials(region):
    override = get_override(region)
    if override is not None:
        return override
    region = region.strip().upper()
    region = 'EUROPE' if region == 'EU' else region
    candidates = [region]
    if region in AMERICAS:
        candidates += ['AMERICAS', 'BR']
    elif region in GLOBAL:
        candidates += ['GLOBAL']
    entries = {}
    lines = _account_lines()
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise UpstreamError('CREDENTIAL_CONFIG_ERROR', 'Invalid active account row format.', 503)
        uid, password, scope = parts
        scope = scope.upper()
        if scope not in KNOWN_SCOPES or not uid.isascii() or not uid.isdigit() or scope in entries:
            raise UpstreamError('CREDENTIAL_CONFIG_ERROR', 'Invalid or duplicate account scope.', 503)
        entries[scope] = urlencode({'uid': uid, 'password': password})
    for scope in candidates:
        if scope in entries:
            return entries[scope]
    raise UpstreamError('CREDENTIAL_CONFIG_ERROR', f'No service account configured for {region}.', 503)
