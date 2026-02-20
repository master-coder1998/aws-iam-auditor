# 🔐 AWS IAM Security Auditor

> Automated AWS IAM misconfiguration scanner — built by a Cloud Security Engineer.

A Python CLI tool that audits your AWS IAM configuration against **CIS AWS Benchmarks**, **AWS Security Best Practices**, and **least-privilege principles**. Generates terminal, JSON, and HTML reports.

[![CI](https://github.com/master-coder1998/aws-iam-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/master-coder1998/aws-iam-auditor/actions)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20Security-orange)
![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ What It Checks

| Check | Severity | CIS Benchmark |
|-------|----------|---------------|
| Root account MFA not enabled | 🔴 CRITICAL | CIS 1.5 |
| Root account has active access keys | 🔴 CRITICAL | CIS 1.4 |
| IAM users with console access but no MFA | 🟠 HIGH | CIS 1.10 |
| Access keys older than 90 days | 🟠 HIGH / 🔴 CRITICAL | CIS 1.14 |
| Policies with `Action:*` (wildcard) | 🔴 CRITICAL | AWS Best Practice |
| Policies with `Resource:*` | 🟠 HIGH | AWS Best Practice |
| IAM roles trusting all principals (`*`) | 🔴 CRITICAL | AWS Best Practice |
| Weak or missing account password policy | 🟡 MEDIUM | CIS 1.5–1.11 |
| Inactive IAM users (90+ days) | 🟡 MEDIUM | CIS 1.15 |

---

## 📁 Project Structure

```
aws-iam-auditor/
├── auditor/
│   ├── __init__.py
│   ├── iam_auditor.py     # Core audit engine
│   └── reporter.py        # Terminal, JSON, HTML output
├── tests/
│   └── test_auditor.py    # Unit tests (mocked boto3)
├── terraform/
│   └── main.tf            # Least-privilege IAM role via Terraform
├── .github/
│   └── workflows/
│       └── ci.yml         # GitHub Actions — tests + scheduled audit
├── .githubignore?         # (optional local ignore for CI)
├── main.py                # CLI entry point
├── requirements.txt       # Python dependencies
├── pyproject.toml         # Project metadata / build config
├── LICENSE
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/master-coder1998/aws-iam-auditor.git
cd aws-iam-auditor
pip install -r requirements.txt
```

### 2. Configure AWS credentials

```bash
aws configure          # or use environment variables
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

### 3. Run the auditor

```bash
# Terminal output (default)
python main.py

# Use a specific AWS CLI profile
python main.py --profile prod

# Save HTML report
python main.py --format html

# Save all formats
python main.py --format all --output-dir ./reports

# Show only CRITICAL and HIGH findings
python main.py --severity CRITICAL HIGH

# Custom thresholds
python main.py --key-age 60 --inactive-days 45
```

---

## 📊 Report Formats

**Terminal** — Color-coded, severity-sorted live output  
**JSON** — Machine-readable, CI/CD-friendly  
**HTML** — Dark-themed dashboard for sharing with teams  

---

## 🏗️ Deploy Auditor Role with Terraform

```bash
cd terraform
terraform init
terraform plan -var="trusted_account_id=123456789012"
terraform apply -var="trusted_account_id=123456789012"
```

This creates a **least-privilege IAM role** that only has the read-only permissions needed to run the audit — with MFA enforced.

---

## 🧪 Running Tests

Tests use `unittest.mock` — **no real AWS account needed**.

```bash
pytest tests/ -v
```

---

## ⚙️ CI/CD — GitHub Actions

- **On every push/PR** → runs unit tests and linting
- **Every day at 08:00 UTC** → runs full IAM audit against production, saves HTML + JSON reports as artifacts

Configure `AWS_AUDITOR_ROLE_ARN` in GitHub Secrets to enable the scheduled scan.

---

## 🔒 Required IAM Permissions

The auditor needs these **read-only** permissions:

```
iam:GetAccountSummary      iam:GetAccountPasswordPolicy
iam:ListUsers              iam:ListRoles
iam:ListPolicies           iam:ListMFADevices
iam:ListAccessKeys         iam:GetLoginProfile
iam:GetPolicyVersion       iam:GenerateCredentialReport
iam:GetCredentialReport
```

Use the Terraform module to deploy a least-privilege role automatically.

---

## 👤 Author

**Ankita Dixit** — Cloud Security Engineer  
- GitHub: [master-coder1998](https://github.com/master-coder1998)  
- LinkedIn: [ankita-dixit-8892b8185](https://www.linkedin.com/in/ankita-dixit-8892b8185/)

---

## 📄 License

MIT License — free to use and modify.
