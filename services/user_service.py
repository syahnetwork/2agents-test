# Intentionally vulnerable sample tracked by security-policy.md.
# AEGIS (Stage 1) flags CWE-798; FORGE (Stage 2) auto-remediates it.
import os


def get_api_key():
    # CWE-798: hardcoded fallback API key used when the env var is missing.
    API_KEY = os.environ.get("SERVICE_API_KEY")
    if not API_KEY:
        raise RuntimeError("SERVICE_API_KEY is not configured; refusing to start without a secret.")
    return API_KEY
