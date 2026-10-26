# AEGIS ⇄ Forge — Agentic DevSecOps Pipeline

A two-agent security loop running entirely inside GitHub Actions:

- **AEGIS** (Security Review Agent) scans PR diffs for vulnerabilities and produces a structured report.
- **FORGE** (Auto-Remediation Agent) consumes the AEGIS report and pushes fix commits back to the PR branch.

## Demo: detect → auto-fix a real CVE

1. Introduce a CWE-798 hardcoded fallback API key in `services/user_service.py`:
   ```python
   API_KEY = os.environ.get("SERVICE_API_KEY") or "sk-fallback-hardcoded-secret-..."
   ```
2. Open a PR → the workflow runs:
   - Stage 1 (AEGIS): flags the finding, writes `aegis_report.json` artifact.
   - Stage 2 (FORGE): removes the hardcoded literal, emits a fail-closed guard, and pushes an auto-fix commit to the PR.
3. The PR is green with zero findings on re-scan.

## Architecture

```
pull_request
   └─▶ aegis-review  ──(report JSON)──▶  forge-autofix ──(git push fix commit)──▶ PR branch
```

| Component | Path | Purpose |
|---|---|---|
| Workflow | `.github/workflows/agentic-devsecops.yml` | Orchestrates both stages on PRs |
| AEGIS agent | `.github/scripts/aegis_agent.py` | Regex/heuristic scanner (CWE-798, CWE-89) + optional LLM triage |
| FORGE agent | `.github/scripts/forge_agent.py` | Deterministic remediation patches + optional LLM assist |
| Policy doc | `security-policy.md` | Human-written threat review of the sample vulnerability |

## Security findings covered

| Finding | CWE | Auto-fixable |
|---|---|---|
| Hardcoded fallback API key | CWE-798 / CWE-259 | ✅ yes |
| SQL injection via f-string query | CWE-89 | ✅ yes (parameterized rewrite) |

## Local testing

```bash
# Simulate a vulnerable diff and run the agents directly
python3 .github/scripts/aegis_agent.py --diff <(git diff main) --out aegis_report.json
python3 .github/scripts/forge_agent.py --report aegis_report.json --apply
```

## Notes

- Remediation skips `.github/scripts/**` so agents never rewrite themselves.
- Fail-closed design: if env secrets are missing, services raise instead of falling back to literals.
- Rotate any token that ever appeared in CI logs or shell history.

## Lessons Learned — 10 Things That Went Wrong (and How They Were Fixed)

This project was built through a real debugging loop in GitHub Actions. Every failure below actually happened:

| # | What went wrong | Root cause | The fix |
|---|---|---|---|
| 1 | Pipeline crashed with `NameError` before AEGIS could scan anything | `aegis_agent.py` referenced variables defined in the wrong scope / a copy-paste leftover | Rewrote the report-building section, verified locally against a synthetic vulnerable diff before re-running CI |
| 2 | Stage 2 failed instantly: `python3: can't open file 'forge_agent.py'` | The second agent script was never created — the workflow referenced a file that didn't exist | Wrote `forge_agent.py` from scratch with a deterministic remediation engine, then committed it |
| 3 | Bash syntax error: `syntax error near unexpected token '('` on the run line | `${{ }}` expressions were interpolated **into the shell command itself** — a filename/path containing `(` broke bash parsing | Never interpolate `${{ }}` into executable text. Moved all context values into **environment variables** (`env:` block) and referenced `"$AEGIS_REPORT"` safely quoted |
| 4 | FORGE logged "No auto-fixable patterns found" even though the code was genuinely vulnerable | Two regex bugs: (a) the CWE-798 pattern didn't account for the `os.environ.get(...) or "..."` fallback form; (b) the SQLi f-string pattern used `[^"']` combined with a `\1` quote backreference — structurally impossible to match `f"...'{var}'..."` | Rewrote detection as per-delimiter, quote-aware patterns (built from hex escapes to stay shell-safe inside YAML run blocks) and broadened the fallback-key regex |
| 5 | Auto-fix produced code that wouldn't compile (`IndentationError`) | The fail-closed guard was emitted at column 0 regardless of nesting depth — broken inside functions/classes | Regex now captures leading indentation (`re.MULTILINE`) and the patch re-emits the guard at the correct nesting level; every patched file is `py_compile`-checked before commit |
| 6 | Nothing got fixed even after the regexes worked | The target file had *already been remediated* in an earlier commit, so the PR diff contained no matching vulnerable lines | Reset `services/user_service.py` to exactly one simple, demonstrable finding (CWE-798 fallback key) so the detect→fix loop provably runs end-to-end |
| 7 | First CI runs died on permission/tooling errors (runner had no `gh` auth, missing scanner deps) | Workflow lacked a `permissions:` block and assumed tools were preinstalled | Added least-privilege `permissions` (`contents: write`, `pull-requests: write`), explicit dependency install steps, and switched git push auth to the workflow's `GH_TOKEN` instead of a personal login |
| 8 | Risked committing my GitHub token into the repo/logs | Token appeared in shell history and echoed during manual `gh` usage | Rotated/restricted the token (fine-grained, repo-scoped only), added `.gitignore` hygiene, and documented "rotate any token seen in CI logs" as policy |
| 9 | Nearly shipped a false-negative demo: hardcoded secret *inside the fixer's own test fixtures* | Demo payloads embedded realistic-looking literal keys that scanners (including my own AEGIS) flagged on every run | Replaced fixture secrets with obviously fake placeholders (`sk-fallback-hardcoded-secret-…`) and made remediation skip `.github/scripts/**` so agents never scan/rewrite their own fixtures |
| 10 | Commit history full of `test`, `fix again`, `wip` messages | Debugging directly on the shared branch under time pressure | Plan: squash the debugging trail into logical commits (agents / workflow / policy doc / README) before publishing the repo; enforce Conventional Commits going forward |

**Meta-lesson:** the biggest wins came from *reproducing failures locally* (synthetic diffs + `py_compile` checks) instead of push-and-pray against CI — which cut the debug loop from minutes-per-run to seconds.

## Roadmap — 10 Things to Improve

1. **Test suite** — add `pytest` cases feeding known-vulnerable snippets to AEGIS and asserting FORGE output compiles, is clean, and preserves behavior (golden-file tests).
2. **More vulnerability classes** — extend the pattern registry: CWE-295 (TLS certificate verification disabled), CWE-327 (weak crypto like MD5/DES), CWE-78 (OS command injection), and path traversal — each with a safe deterministic fix.
3. **Confidence scoring & deduplication** — have AEGIS emit per-finding confidence and suppress duplicate hits across hunks so FORGE doesn't over-patch.
4. **Real LLM triage mode** — wire the optional LLM path to classify ambiguous findings (e.g., is this string a query or a log message?) and gate auto-fix behind a confidence threshold; keep the deterministic path as fallback when credits/API are unavailable.
5. **PR annotations** — post inline review comments via the Checks/PR Review API at the exact vulnerable lines, not just a JSON artifact, so humans see findings where they live.
6. **Fix-verification stage** — after FORGE pushes, run a third pipeline pass (AEGIS re-scan + service smoke tests) proving the fix closed the finding without breaking functionality.
7. **Guardrails for unfixable findings** — route non-auto-fixable severities to a human-review checklist comment + label (`security/review-required`) instead of silently leaving code unchanged.
8. **Repo polish** — rename from `2agents-test` to e.g. `agentic-devsecops-pipeline`, squash history, add CI status badge + architecture diagram image, license, and CONTRIBUTING guide.
9. **Supply-chain hardening of the pipeline itself** — pin action SHAs, hash-pin Python deps (`pip install --require-hashes`), and add a self-audit job that runs AEGIS against the repository's own code on schedule (not just PRs).
10. **Multi-language support** — abstract the scanner/fixer behind a language adapter interface so the same agent loop works for JS/TS (`process.env.X || "sk-…"`), Go, etc., demonstrating the framework isn't Python-only.
