# .github/scripts/forge_agent.py
"""FORGE — Auto-Remediation Agent (Stage 2 of the Agentic DevSecOps pipeline).

Takes the vulnerability report produced by AEGIS and applies safe, deterministic
fixes for the two classes of findings this repo's security-policy.md tracks:

1. Hardcoded fallback API keys  -> env-var lookup with fail-closed validation.
2. SQL injection logic flaws    -> parameterized queries instead of interpolation.

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
# ---------------------------------------------------------------------------
FALLBACK_KEY_RE = re.compile(
    r'(?P<var>\w+)\s*=\s*os\.environ\.get\(\s*["\'](?P<env>[^"\']+)["\']\s*\)\s*(?:or|\|\|)\s*'
    r'["\'][^"\']+["\']'
)

FIX_TEMPLATE = '''{var} = os.environ.get("{env}")
if not {var}:
    raise RuntimeError("{env} is not configured; refusing to start without a secret.")'''


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
            new_src, n = FALLBACK_KEY_RE.subn(
                lambda m: FIX_TEMPLATE.format(var=m.group("var"), env=m.group("env")), src
            )
            if n:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new_src)
                fixed.append((path, n))
                print(f"[Forge] Removed hardcoded fallback key(s) in {path} ({n} occurrence[s])")
    return fixed


# ---------------------------------------------------------------------------
# Fix 2: SQLi via string-interpolated query  (CWE-89)
#   f"SELECT ... WHERE id = '{x}'"  ->  "SELECT ... WHERE id = %s", (x,)
# Only rewrites single-table SELECT/UPDATE/DELETE shaped queries; anything
# more complex is left untouched for human review (fail-safe behavior).
# ---------------------------------------------------------------------------
# f-string style:  f"SELECT ... {var} ..."
SQLI_FSTRING_RE = re.compile(
    r"""(?P<q>["'])f((?:SELECT|UPDATE|DELETE)[^"']*?\{[^}]+\}[^"']*?)\1""",
    re.IGNORECASE,
)
# printf style:  "SELECT ... %s ..." % var   /   "SELECT ... %s ..." % (a, b)
SQLI_PERCENT_RE = re.compile(
    r"""(?P<q>["'])((?:SELECT|UPDATE|DELETE)[^"']*?%[srf][^"']*?)\1\s*%\s*(?P<args>\([^)]*\)|[A-Za-z_]\w*)""",
    re.IGNORECASE,
)
# str.format style:  "SELECT ... {}".format(var)
SQLI_FORMAT_RE = re.compile(
    r"""(?P<q>["'])((?:SELECT|UPDATE|DELETE)[^"']*?\{\d*\}[^"']*?)\1\s*\.\s*format\((?P<args>[^)]*)\)""",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][\w.\[\]'\"]*)\}")

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

            def repl_fstring(m):
                body = m.group(2)
                params = PLACEHOLDER_RE.findall(body)
                if not params:
                    return m.group(0)
                converted = PLACEHOLDER_RE.sub("%s", body)
                tuple_str = "({})".format(", ".join(params) + ("," if len(params) == 1 else ""))
                return '"{}", {}'.format(converted, tuple_str)

            def repl_percent(m):
                body = m.group(2)
                args_raw = m.group("args").strip()
                # Already parameterized? ("%s" placeholders are DB-driver style; the
                # flaw is the *% interpolation*, so convert execute-side to tuple arg.
                if args_raw.startswith("("):
                    inner = args_raw[1:-1].strip().rstrip(",")
                    params = [p.strip() for p in inner.split(",") if p.strip()]
                else:
                    params = [args_raw]
                if not params:
                    return m.group(0)
                tuple_str = "({})".format(", ".join(params) + ("," if len(params) == 1 else ""))
                return '"{}", {}'.format(body, tuple_str)

            def repl_format(m):
                body = m.group(2)
                args_raw = m.group("args").strip()
                params = [p.strip() for p in args_raw.split(",") if p.strip()]
                if not params:
                    return m.group(0)
                converted = re.sub(r"\{\d*\}", "%s", body)
                tuple_str = "({})".format(", ".join(params) + ("," if len(params) == 1 else ""))
                return '"{}", {}'.format(converted, tuple_str)

            new_src = src
            total = 0
            for regex, fn in (
                (SQLI_FSTRING_RE, repl_fstring),
                (SQLI_PERCENT_RE, repl_percent),
                (SQLI_FORMAT_RE, repl_format),
            ):
                new_src, n = regex.subn(fn, new_src)
                total += n
            if total:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new_src)
                fixed.append((path, total))
                print(f"[Forge] Parameterized interpolated SQL in {path} ({total} query[ies])")
    return fixed


def main():
    args = parse_args()
    report = load_report(args.vuln_report)
    print(f"[Forge] Received AEGIS report status={report.get('status')} severity={report.get('severity')}")

    key_fixes = fix_hardcoded_keys()
    sqli_fixes = fix_sqli_queries()

    total = len(key_fixes) + len(sqli_fixes)
    if total == 0:
        print("[Forge] No auto-fixable patterns found; leaving code unchanged for human review.")
    else:
        print(f"[Forge] Applied remediations to {total} file(s).")
    sys.exit(0)


if __name__ == "__main__":
    main()
