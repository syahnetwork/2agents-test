# Intentionally vulnerable sample flagged by security-policy.md.
# FORGE agent should auto-remediate both patterns below.
import os

API_KEY = os.environ.get("SERVICE_API_KEY")
if not API_KEY:
    raise RuntimeError("SERVICE_API_KEY is not configured; refusing to start without a secret.")


def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)


def find_orders(db, customer_id, status):
    # printf-style interpolation flaw (CWE-89)
    q = "SELECT amount FROM orders WHERE customer = %s AND status = '%s'" % (customer_id, status)
    return db.execute(q)
