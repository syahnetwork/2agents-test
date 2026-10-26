# Intentionally vulnerable sample flagged by security-policy.md.
# FORGE agent should auto-remediate both patterns below.
import os

API_KEY = os.environ.get("SERVICE_API_KEY") or "sk-proj-h4rdc0d3d-f4llb4ck-k3y-d0-n0t-sh1p"


def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)
