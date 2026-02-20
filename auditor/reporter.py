"""
AWS IAM Security Auditor — Report Generator
Outputs findings as Terminal, JSON, or HTML report.
Author: Ankita Dixit | github.com/master-coder1998
"""

import json
import datetime
from pathlib import Path


# ── ANSI Colors ──────────────────────────────────────────────
CRITICAL = "\033[91m\033[1m"
HIGH     = "\033[91m"
MEDIUM   = "\033[93m"
LOW      = "\033[94m"
INFO     = "\033[96m"
GREEN    = "\033[92m"
BOLD     = "\033[1m"
DIM      = "\033[2m"
RESET    = "\033[0m"

SEV_COLOR = {"CRITICAL": CRITICAL, "HIGH": HIGH, "MEDIUM": MEDIUM, "LOW": LOW, "INFO": INFO}
SEV_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
SEV_HTML  = {
    "CRITICAL": "#FF4757",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFA502",
    "LOW":      "#2E86DE",
    "INFO":     "#2ED573",
}

BANNER = f"""
{BOLD}╔══════════════════════════════════════════════════════╗
║         AWS IAM Security Auditor  🔐                 ║
║         Author: Ankita Dixit                         ║
║         github.com/master-coder1998                  ║
╚══════════════════════════════════════════════════════╝{RESET}
"""


def print_terminal_report(results: dict):
    """Pretty-print findings to the terminal."""
    print(BANNER)
    summary = results["summary"]
    total   = results["total_findings"]
    print(f"  Generated : {results['generated_at']}")
    print(f"  Findings  : {BOLD}{total}{RESET}\n")

    # Summary bar
    print(f"  {CRITICAL}CRITICAL: {summary['CRITICAL']}{RESET}  "
          f"{HIGH}HIGH: {summary['HIGH']}{RESET}  "
          f"{MEDIUM}MEDIUM: {summary['MEDIUM']}{RESET}  "
          f"{LOW}LOW: {summary['LOW']}{RESET}  "
          f"{INFO}INFO: {summary['INFO']}{RESET}")
    print(f"\n  {'─'*60}\n")

    for f in results["findings"]:
        sev   = f["severity"]
        color = SEV_COLOR.get(sev, "")
        icon  = SEV_ICON.get(sev, "")
        print(f"  {color}{BOLD}[{sev}]{RESET}  {icon}  {BOLD}{f['title']}{RESET}")
        print(f"  {DIM}Category  : {f['category']}{RESET}")
        print(f"  {DIM}Resource  : {f['resource']}{RESET}")
        print(f"  {DIM}Detail    : {f['detail']}{RESET}")
        print(f"  {GREEN}  → {f['recommendation']}{RESET}")
        print()


def save_json_report(results: dict, output_path: str = "iam_audit_report.json"):
    """Save full results as a JSON file."""
    path = Path(output_path)
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  ✅ JSON report saved → {path.resolve()}")


def save_html_report(results: dict, output_path: str = "iam_audit_report.html"):
    """Save a self-contained styled HTML report."""
    summary = results["summary"]
    findings_html = ""
    for f in results["findings"]:
        sev   = f["severity"]
        color = SEV_HTML.get(sev, "#888")
        icon  = SEV_ICON.get(sev, "")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color};">
          <div class="finding-header">
            <span class="badge" style="background:{color};">{icon} {sev}</span>
            <span class="category">{f['category']}</span>
            <strong>{f['title']}</strong>
          </div>
          <div class="finding-body">
            <p><span class="label">Resource</span> <code>{f['resource']}</code></p>
            <p><span class="label">Detail</span> {f['detail']}</p>
            <p class="rec"><span class="label">Recommendation</span> {f['recommendation']}</p>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS IAM Security Audit Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 40px 20px; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 2rem; color: #60a5fa; margin-bottom: 4px; }}
  .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 32px; }}
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }}
  .stat {{ background: #1e293b; border-radius: 12px; padding: 20px 28px; text-align: center; flex: 1; min-width: 100px; }}
  .stat .num {{ font-size: 2.5rem; font-weight: 700; }}
  .stat .lbl {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .finding {{ background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }}
  .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .category {{ background: #334155; padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; color: #94a3b8; }}
  .finding-header strong {{ color: #f1f5f9; font-size: 1rem; }}
  .finding-body p {{ margin-bottom: 8px; font-size: 0.9rem; color: #cbd5e1; line-height: 1.6; }}
  .label {{ font-weight: 600; color: #7dd3fc; margin-right: 6px; }}
  code {{ background: #0f172a; padding: 2px 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; color: #a5f3fc; }}
  .rec {{ background: #0f2d1e; padding: 10px 14px; border-radius: 8px; color: #86efac !important; }}
  footer {{ text-align: center; margin-top: 48px; color: #475569; font-size: 0.85rem; }}
  a {{ color: #60a5fa; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔐 AWS IAM Security Audit</h1>
  <p class="subtitle">Generated: {results['generated_at']} &nbsp;|&nbsp; Total Findings: {results['total_findings']} &nbsp;|&nbsp; Author: <a href="https://github.com/master-coder1998" target="_blank">Ankita Dixit</a></p>

  <div class="summary">
    <div class="stat"><div class="num" style="color:#FF4757">{summary['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#FF6B35">{summary['HIGH']}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#FFA502">{summary['MEDIUM']}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#2E86DE">{summary['LOW']}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:#2ED573">{summary['INFO']}</div><div class="lbl">Info</div></div>
  </div>

  {findings_html}

  <footer>
    AWS IAM Security Auditor &nbsp;·&nbsp; <a href="https://github.com/master-coder1998/aws-iam-auditor">github.com/master-coder1998/aws-iam-auditor</a>
  </footer>
</div>
</body>
</html>"""

    path = Path(output_path)
    with open(path, "w") as f:
        f.write(html)
    print(f"  ✅ HTML report saved → {path.resolve()}")
