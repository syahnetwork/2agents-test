# .github/scripts/forge_agent.py
"""FORGE - Auto-Remediation Agent (Stage 2 of the Agentic DevSecOps pipeline).

Takes the vulnerability report produced by AEGIS and applies safe, deterministic
fixes for the two classes of findings this repo's security-policy.md tracks:

1. Hardcoded fallback API keys (CWE-798) -> env-var lookup with fail-closed validation.
2. SQL injection logic flaws     (CWE-89) -> parameterized queries instead of interpolation.

If no automatic fix can be applied, it still exits 0 so the workflow can push
whatever remediation was made (the commit step tolerates "nothing to commit").
"""
import argparse
import json
import os
import re
import sys


def parse_args():
    p = argparse.ArgumentParser(description="FORGE auto-remediation agent")
    p.add_argument("--vuln_report", default="", help="AEGIS vulnerability report text or JSON")
    return p.parse_args()


def load_report(raw):
    """Best-effort parse of the AEGIS report (may be strict JSON or free text)."""
    if not raw:
        return {"status": "UNKNOWN", "report": "", "severity": ""}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"status": "VULNERABLE", "report": str(raw), "severity": "unknown"}


# ---------------------------------------------------------------------------
# Fix 1: hardcoded fallback API key  (CWE-798)
#   Pattern:  API_KEY = os.environ.get("X") or "sk-literal..."
#   Replaced with an env-var lookup that fails closed when the secret is absent.
#   The leading indentation is captured so the guard stays inside functions.
# ---------------------------------------------------------------------------
FALLBACK_KEY_RE = re.compile(
    r"(?P<indent>^[ \t]*)(?P<var>\w+)\s*=\s*os\.environ\.get\(\s*[\"'](?P<env>[^\"']+)[\"']\s*\)\s*(?:or|\|\|)\s*"
    r"[\"'][^\"']+[\"']",
    re.MULTILINE,
)


def fix_hardcoded_key(match):
    indent = match.group("indent")
    var = match.group("var")
    env = match.group("env")
    return (
        '{i}{v} = os.environ.get("{e}")\n'
        "{i}if not {v}:\n"
        '{i}    raise RuntimeError("{e} is not configured; refusing to start without a secret.")'
    ).format(i=indent, v=var, e=env)


def is_pipeline_script(path):
    """Never rewrite the DevSecOps pipeline's own scripts (they contain the
    detection/fix patterns as documentation and live regexes)."""
    norm = path.replace("\\", "/")
    return ".github/scripts" in norm


def fix_hardcoded_keys(root="."):
    fixed = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            if is_pipeline_script(path):
                continue
            try:
                src = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            new_src, n = FALLBACK_KEY_RE.subn(fix_hardcoded_key, src)
            if n:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new_src)
                fixed.append((path, n))
                print("[Forge] Removed hardcoded fallback key(s) in {} ({} occurrence[s])".format(path, n))
    return fixed


# ---------------------------------------------------------------------------
# Fix 2: SQLi via string-interpolated query  (CWE-89)
#   f"SELECT ... WHERE id = '{x}'"  ->  "SELECT ... WHERE id = %s", (x,)
#   "SELECT ... WHERE x = '%s'" % y ->  "SELECT ... WHERE x = %s", (y,)
#   "SELECT ... {}".format(z)       ->  "SELECT ... %s", (z,)
# Quote-aware: one compiled variant per string delimiter, built from hex
# escapes so this source file never needs fragile backreference tricks and
# stays shell-safe. Only single-line SELECT/UPDATE/DELETE shaped queries are
# rewritten; anything else is left untouched for human review (fail-safe).
# ---------------------------------------------------------------------------
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][\w.\[\]]*)\}")
_DQ = chr(0x22)  # double quote
_SQ = chr(0x27)  # single quote


def _compile_sql_patterns(delim_hex):
    d = delim_hex
    fstring = re.compile(
        "\"f(?P<sql>(?:SELECT|UPDATE|DELETE)[^" + d + "]*?)\"" , re.IGNORECASE)
    percent = re.compile(
        "\"(?P<sql>(?:SELECT|UPDATE|DELETE)[^" + d + "]*?)\"" + "\\s*%\\s*(?P<args>\\([^)]*\\)|[A-Za-z_]\\w*)",
        re.IGNORECASE,
    )
    fmt = re.compile(
        "\"(?P<sql>(?:SELECT|UPDATE|DELETE)[^" + d + "]*?)\"" + "\\s*\\.\\s*format\\((?P<args>[^)]*)\\)",
        re.IGNORECASE,
    )
    return fstring, percent, fmt


SQLI_PATTERNS = _compile_sql_patterns("\\x22") + _compile_sql_patterns("\\x27")


def _as_tuple(params):
    joined = ", ".join(params)
    if len(params) == 1:
        joined += ","
    return "({})".format(joined)


def _repl_fstring(m):
    body = m.group("sql")
    params = PLACEHOLDER_RE.findall(body)
    if not params:
        return m.group(0)
    converted = PLACEHOLDER_RE.sub("%s", body)
    return '"{}", {}'.format(converted, _as_tuple(params))


def _repl_percent(m):
    body = m.group("sql")
    args_raw = m.group("args").strip()
    if args_raw.startswith("("):
        params = [p.strip() for p in args_raw[1:-1].split(",") if p.strip()]
    else:
        params = [args_raw]
    if not params:
        return m.group(0)
    return '"{}", {}'.format(body, _as_tuple(params))


def _repl_format(m):
    body = m.group("sql")
    params = [p.strip() for p in m.group("args").split(",") if p.strip()]
    if not params:
        return m.group(0)
    converted = re.sub(r"\{\d*\}", "%s", body)
    return '"{}", {}'.format(converted, _as_tuple(params))


_REPLACERS = (_repl_fstring, _repl_percent, _repl_format, _repl_fstring, _repl_percent, _repl_format)

# Character classes are built from hex escapes so the regex source never
# contains a literal quote character (shell-safe to embed anywhere).
_DQ = chr(0x22)
_SQ = chr(0x27)
_QUOTE_CLASS = "[\\x22\\x27]"          # " or '
_NONQUOTE_CLASS = "[^\\x22\\x27]"      # any char except " and '


def _build_fstring_re():
    """f-string SQLi pattern, assembled without literal quotes in the source:
       f"SELECT ... {expr} ..."  /  f'SELECT ...'  (optional rb/br prefixes)"""
    return re.compile(
        "(?P<body>[rbu]{0,2})f(?P<quote>" + _QUOTE_CLASS + ")"
        "(?P<sql>(?:SELECT|UPDATE|DELETE)(?:" + _NONQUOTE_CLASS + "|\\\\.)*?)"
        "(?P<brace>\\{[^}]+\\})"
        "(?P<tail>(?:" + _NONQUOTE_CLASS + "|\\\\.)*)"
        "(?P=quote)",
        re.IGNORECASE,
    )


SQLI_FSTRING_BUILDER_RE = _build_fstring_re()


def fix_sqli_queries(root="."):
    fixed = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            if is_pipeline_script(path):
                continue
            try:
                src = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            new_src = src
            total = 0
            for regex, repl in zip(SQLI_PATTERNS, _REPLACERS):
                new_src, n = regex.subn(repl, new_src)
                total += n
            if total:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new_src)
                fixed.append((path, total))
                print("[Forge] Parameterized interpolated SQL in {} ({} query[ies])".format(path, total))
    return fixed


def main():
    args = parse_args()
    report = load_report(args.vuln_report)
    print("[Forge] Received AEGIS report status={} severity={}".format(
        report.get("status"), report.get("severity")))

    key_fixes = fix_hardcoded_keys()
    sqli_fixes = fix_sqli_queries()

    total = len(key_fixes) + len(sqli_fixes)
    if total == 0:
        print("[Forge] No auto-fixable patterns found; leaving code unchanged for human review.")
    else:
        print("[Forge] Applied remediations to {} file(s).".format(total))
    sys.exit(0)


if __name__ == "__main__":
    main()
