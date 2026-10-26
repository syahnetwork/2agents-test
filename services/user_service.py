# Intentionally vulnerable sample tracked by security-policy.md.
# AEGIS (Stage 1) flags CWE-798; FORGE (Stage 2) auto-remediates it.
import os


def get_api_key():
    # CWE-798: hardcoded fallback API key used when the env var is missing.
    API_KEY = os.environ.get("SERVICE_API_KEY") or "sk-fallback-hardcoded-secret-1234567890"
    return API_KEY
