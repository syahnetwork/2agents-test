# Security Policy — AEGIS Review Findings

**Repository:** `syahnetwork/2agents-test`
**Pipeline:** Agentic DevSecOps Pipeline (2026) — Stage 1: Aegis Security & Threat Review
**Review date:** 2026-10-26
**Status:** `VULNERABLE` — 2 findings (1 High, 1 Critical)

---

## Finding 1 — Hardcoded Fallback API Key (Secrets Management)

- **Severity:** High (CWE-798: Use of Hard-coded Credentials, CWE-259: Hardcoded Password / fallback)
- **Location:** Application configuration / client initialization where the API key is resolved, e.g.:

```python
# VULNERABLE PATTERN (detected by Aegis / trufflehog heuristic)
API_KEY = os.environ.get("API_KEY") or "sk-proj-h4rdc0d3d-f4llb4ck-k3y-d0-n0t-sh1p"
```

- **Description:** The code reads an API key from the environment but falls back to a
  literal hardcoded key when the variable is unset. This creates three concrete risks:
  1. **Leaked credential in version control.** Anyone with repo read access (including
     forks and CI logs) obtains a working key; git history retains it even after deletion.
  2. **Silent production misconfiguration.** If the env var is missing, the service
     quietly runs on the fallback key instead of failing fast, bypassing rotation,
     scoping, and audit controls of the real secret store.
  3. **Blast-radius amplification.** All deployments that misconfigure share one key,
     so abuse of the fallback key is indistinguishable across environments and cannot
     be rotated per-environment.
- **Remediation (required before merge):**
  - Remove the fallback string entirely; fail closed if the secret is absent:

```python
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise RuntimeError("API_KEY is not configured; refusing to start without a secret.")
```

  - Rotate/revoke the exposed key immediately (assume it is compromised).
  - Inject secrets at runtime via GitHub Actions encrypted secrets / a vault, never as literals.
  - Keep `trufflehog filesystem . --json` gating in CI (already present in the workflow) and treat any hit as a build failure rather than `|| true`.

---

## Finding 2 — SQL Injection Logic Flaw (String-Interpolated Query)

- **Severity:** Critical (CWE-89: Improper Neutralization of Special Elements used in an SQL Command)
- **Location:** Data-access layer building queries from user input, e.g.:

```python
# VULNERABLE LOGIC FLAW (static scanners often miss this shape)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"   # raw interpolation
    return db.execute(query)                                  # no parameter binding
```

- **Description:** The flaw is **logical**, not merely syntactic: user-controlled input is
  concatenated into the SQL statement *before* execution, so the database can no longer
  distinguish code from data. An attacker supplying `' OR '1'='1' --` exfiltrates or
  modifies arbitrary rows; stacked statements can escalate to data destruction. Because
  the interpolation happens inside a helper that looks like ordinary templating, pattern-based
  scanners frequently miss it — exactly the class of business-logic flaws the AEGIS agent
  prompt instructs the LLM to catch beyond Semgrep output.
- **Remediation (required before merge):**
  - Use parameterized queries / prepared statements exclusively:

```python
def get_user(user_id):
    return db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

  - Validate/sanitize at the boundary (allow-list types, e.g. integer IDs) as defense-in-depth.
  - Never build SQL with f-strings, `+`, `%`, or `.format()` from request-derived data.
  - Add a regression test asserting quoted/metacharacter input cannot alter query semantics.

---

## Pipeline Enforcement

| Rule | Mechanism |
|---|---|
| Any finding ⇒ Forge auto-remediation stage runs | `aegis-review` job emits `vuln_report`; `forge-remediate` triggers when `vuln_report != 'CLEAN'` |
| Secret scanning | `trufflehog filesystem . --json` in Stage 1 context gathering |
| SAST | `npx semgrep --config=auto --json` in Stage 1 context gathering |
| LLM logic-flaw review | AEGIS agent (`github.com/syahnetwork/2agents-test/.github/scripts/aegis_agent.py`) analyzing PR diff + scanner output |

**Merge policy:** PRs containing either of the patterns above must not be merged until
remediated and re-scanned clean (`status: CLEAN`).
