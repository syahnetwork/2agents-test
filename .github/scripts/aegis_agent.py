# .github/scripts/aegis_agent.py
import requests, json, os, argparse

def query_github_models(prompt):
    # GitHub Models provides FREE access to Llama-3.3 and Qwen2.5
    url = "https://models.inference.ai.azure.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "Llama-3.3-70B-Instruct", # Free tier model
        "messages": [
            {"role": "system", "content": "You are AEGIS, a 2026 DevSecOps agent. Analyze code for logical flaws, OWASP Top 10 2025, and supply chain risks. Output strict JSON."},
            {"role": "user", "content": prompt}
        ]
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()['choices'][0]['message']['content']

# ... (Argument parsing and file reading omitted for brevity) ...
pr_diff = args.pr_diff
semgrep_data = open('semgrep_results.json').read()

prompt = f"""
Analyze this PR Diff and Semgrep output. 
Identify business logic flaws that static analysis missed.
If vulnerable, output JSON: {{"status": "VULNERABLE", "report": "...", "severity": "..."}}
If clean, output: {{"status": "CLEAN"}}

PR DIFF: {pr_diff}
SEMGREP: {semgrep_data}
"""

result = query_github_models(prompt)
# Set GitHub Actions output for the next job
with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
    print(f"report={result}", file=fh)