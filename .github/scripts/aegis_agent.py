# .github/scripts/aegis_agent.py
"""AEGIS — Security & Threat Review Agent (Stage 1 of the Agentic DevSecOps pipeline).

Reads scanner context (Semgrep + trufflehog output) plus the PR diff, asks a
GitHub Models LLM for a logic-flaw-aware review, and exports a `report` output
consumed by the Forge remediation job. Falls back to deterministic heuristic
analysis when the model endpoint is unavailable so the pipeline never stalls.
"""
import argparse
import json
import os
import re
import sys

import requests


def parse_args():
    p = argparse.ArgumentParser(description="AEGIS security review agent")
    p.add_argument("--semgrep", default="semgrep_results.json", help="Path to semgrep JSON output")
    p.add_argument("--secrets", default="secrets_results.json", help="Path to trufflehog JSON output")
    p.add_argument("--pr_diff", default="", help="The PR diff text")
    p.add_argument("--pr_diff_file", default="", help="Path to a file containing the PR diff")
    return p.parse_args()


def read_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = fh.read()
        return data if data.strip() else '{"results": []}'
    except OSError:
        return '{"results": []}'


def read_text_file(path):
    """Plain-text reader for the PR diff; returns '' when missing/empty."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def query_github_models(prompt):
    # GitHub Models provides FREE access to Llama-3.3 and Qwen2.5
    url = "https://models.inference.ai.azure.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.environ.get('GITHUB_MODELS_TOKEN') or os.environ.get('GITHUB_TOKEN', '')}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "Llama-3.3-70B-Instruct",  # Free tier model
        "messages": [
            {"role": "system", "content": "You are AEGIS, a 2026 DevSecOps agent. Analyze code for logical flaws, OWASP Top 10 2025, and supply chain risks. Output strict JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    response = requests.post(url, headers=headers, json=payload, timeout=90)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Deterministic fallback heuristics (used when the LLM endpoint is down)
# Mirrors the two classes tracked in security-policy.md.
# ---------------------------------------------------------------------------
HARDCODED_KEY_RE = re.compile(
    r"""os\.environ\.get\(\s*["'][^"']+["']\s*\)\s*(?:or|\|\|)\s*["'][^"']{8,}["']""",
    re.IGNORECASE,
)
KEY_LITERAL_RE = re.compile(r"""["'](sk-[A-Za-z0-9\-_]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})["']""")
SQLI_RE = re.compile(
    r"""f["']\s*(SELECT|UPDATE|DELETE|INSERT)[^\n]*?\{[^}]+\}[^\n]*?["']""",
    re.IGNORECASE,
)
# Also catch printf-style interpolation: "SELECT ... %s ... " % var  /  .format(...)
SQLI_PERCENT_RE = re.compile(
    r"""["'][^"'\n]*\b(SELECT|UPDATE|DELETE|INSERT)\b[^"'\n]*%[srf][^"'\n]*["']\s*%\s*\(?[A-Za-z_][\w.\[\]()'"]*""",
    re.IGNORECASE,
)
SQLI_FORMAT_RE = re.compile(
    r"""["'][^"'\n]*\b(SELECT|UPDATE|DELETE|INSERT)\b[^"'\n]*\{\d*\}[^"'\n]*["']\s*\.\s*format\s*\(""",
    re.IGNORECASE,
)


def heuristic_scan(diff_text):
    findings = []
    for m in HARDCODED_KEY_RE.finditer(diff_text):
        findings.append({"type": "hardcoded_fallback_api_key", "cwe": "CWE-798", "evidence": m.group(0)[:120]})
    for m in KEY_LITERAL_RE.finditer(diff_text):
        findings.append({"type": "api_key_literal", "cwe": "CWE-798", "evidence": m.group(0)[:120]})
    for m in SQLI_RE.finditer(diff_text):
        findings.append({"type": "sql_injection_logic_flaw", "cwe": "CWE-89", "evidence": m.group(0)[:120]})
    for regex in (SQLI_PERCENT_RE, SQLI_FORMAT_RE):
        for m in regex.finditer(diff_text):
            findings.append({"type": "sql_injection_logic_flaw", "cwe": "CWE-89", "evidence": m.group(0)[:120]})
    # De-duplicate while preserving order
    seen, unique = set(), []
    for f in findings:
        key = (f["type"], f["evidence"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def build_report(result_text, diff_text):
    """Normalize the model output (or heuristics) into the workflow report value."""
    try:
        parsed = json.loads(result_text)
        status = str(parsed.get("status", "UNKNOWN")).upper()
    except (json.JSONDecodeError, TypeError):
        status = "VULNERABLE" if re.search(r"VULNERABLE", result_text or "", re.IGNORECASE) else "CLEAN"

    if status == "CLEAN":
        findings = heuristic_scan(diff_text)
        if findings:
            status = "VULNERABLE"
            result_text = json.dumps(
                {
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "report": "Heuristic fallback flagged: " + "; ".join(f["type"] for f in findings),
                    "findings": findings,
                }
            )
    # Collapse newlines so the value survives GITHUB_OUTPUT / job-output plumbing
    one_line = re.sub(r"\s+", " ", str(result_text)).strip()
    return one_line if one_line else "VULNERABLE: empty report from AEGIS"


def main():
    args = parse_args()
    pr_diff = args.pr_diff or ""
    if args.pr_diff_file:
        pr_diff = read_text_file(args.pr_diff_file) or pr_diff
    semgrep_data = read_file(args.semgrep)
    secrets_data = read_file(args.secrets)

    prompt = f"""
Analyze this PR Diff and scanner output.
Identify business logic flaws that static analysis missed, including hardcoded
fallback API keys (CWE-798) and SQL injection via string-interpolated queries (CWE-89).
If vulnerable, output JSON: {{"status": "VULNERABLE", "report": "...", "severity": "..."}}
If clean, output: {{"status": "CLEAN"}}

PR DIFF: {pr_diff}
SEMGREP: {semgrep_data}
TRUFFLEHOG: {secrets_data}
"""

    try:
        result = query_github_models(prompt)
    except Exception as exc:  # noqa: BLE001 - pipeline must not stall on model outage
        print(f"[Aegis] Model endpoint unavailable ({exc}); falling back to heuristics.", file=sys.stderr)
        findings = heuristic_scan(pr_diff)
        result = json.dumps(
            {
                "status": "VULNERABLE" if findings else "CLEAN",
                "severity": "HIGH" if findings else None,
                "report": "; ".join(f"{f['type']} ({f['cwe']})" for f in findings),
                "findings": findings,
            }
        )

    report_value = build_report(result, pr_diff)
    print(f"[Aegis] report={report_value[:400]}")

    # Set GitHub Actions output for the next job
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
        fh.write(f"report<<EOF_AEGIS\n{report_value}\nEOF_AEGIS\n")


if __name__ == "__main__":
    main()
