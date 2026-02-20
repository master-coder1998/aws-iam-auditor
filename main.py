#!/usr/bin/env python3
"""
AWS IAM Security Auditor — CLI
Usage: python main.py [options]
Author: Ankita Dixit | github.com/master-coder1998
"""

import argparse
import sys
from auditor.iam_auditor import IAMAuditor
from auditor.reporter import print_terminal_report, save_json_report, save_html_report


def main():
    parser = argparse.ArgumentParser(
        prog="aws-iam-auditor",
        description="🔐 AWS IAM Security Auditor — Scan IAM for misconfigurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Scan default profile, terminal output
  python main.py --profile prod               # Use named AWS CLI profile
  python main.py --format html                # Save HTML report
  python main.py --format json                # Save JSON report
  python main.py --format all                 # Terminal + JSON + HTML
  python main.py --key-age 60                 # Flag keys older than 60 days
  python main.py --inactive-days 60           # Flag users inactive 60+ days
  python main.py --severity CRITICAL HIGH     # Show only CRITICAL and HIGH findings

Author: Ankita Dixit | github.com/master-coder1998
        """
    )

    parser.add_argument("--profile",       default=None,    help="AWS CLI profile name (default: default)")
    parser.add_argument("--region",        default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--format",        default="terminal", choices=["terminal", "json", "html", "all"], help="Output format")
    parser.add_argument("--output-dir",    default=".",     help="Directory to save reports (default: current dir)")
    parser.add_argument("--key-age",       default=90,  type=int, help="Max access key age in days before flagging (default: 90)")
    parser.add_argument("--inactive-days", default=90,  type=int, help="Days of inactivity before flagging users (default: 90)")
    parser.add_argument("--severity",      nargs="+", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Filter output to specific severities")

    args = parser.parse_args()

    print("\n  🔍 Connecting to AWS and running IAM security checks...\n")

    try:
        auditor = IAMAuditor(profile=args.profile, region=args.region)
    except Exception as e:
        print(f"\n  ❌ Could not initialize AWS session: {e}")
        print("  → Ensure AWS credentials are configured (aws configure or env vars).\n")
        sys.exit(1)

    # Override defaults if provided
    auditor.check_access_key_rotation = lambda: IAMAuditor.check_access_key_rotation(auditor, args.key_age)
    auditor.check_inactive_users = lambda: IAMAuditor.check_inactive_users(auditor, args.inactive_days)

    results = auditor.run_all()

    # Apply severity filter
    if args.severity:
        results["findings"] = [f for f in results["findings"] if f["severity"] in args.severity]
        results["total_findings"] = len(results["findings"])

    # Output
    if args.format in ("terminal", "all"):
        print_terminal_report(results)

    if args.format in ("json", "all"):
        save_json_report(results, f"{args.output_dir}/iam_audit_report.json")

    if args.format in ("html", "all"):
        save_html_report(results, f"{args.output_dir}/iam_audit_report.html")

    # Exit code based on severity
    if results["summary"]["CRITICAL"] > 0:
        sys.exit(2)
    elif results["summary"]["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
