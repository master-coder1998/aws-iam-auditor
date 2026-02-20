"""
AWS IAM Security Auditor
Core auditing engine — scans IAM users, roles, policies, and MFA status.
Author: Ankita Dixit | github.com/master-coder1998
"""

import boto3
import json
import datetime
from typing import Optional
from botocore.exceptions import ClientError, NoCredentialsError


class IAMAuditor:
    """
    Audits AWS IAM configuration against security best practices.
    Checks: MFA, unused credentials, overly permissive policies,
    password policy, access key rotation, and root account usage.
    """

    def __init__(self, profile: Optional[str] = None, region: str = "us-east-1"):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = session.client("iam")
        self.findings: list[dict] = []
        self.summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    # ── Internal Helper ──────────────────────────────────────────

    def _add_finding(self, severity: str, category: str, resource: str, title: str, detail: str, recommendation: str):
        self.summary[severity] += 1
        self.findings.append({
            "severity": severity,
            "category": category,
            "resource": resource,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        })

    def _days_since(self, dt) -> int:
        if dt is None:
            return -1
        if isinstance(dt, str):
            dt = datetime.datetime.fromisoformat(dt.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return (now - dt).days

    # ── Check 1: Root Account MFA ────────────────────────────────

    def check_root_mfa(self):
        """Checks if root account has MFA enabled."""
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                self._add_finding(
                    severity="CRITICAL",
                    category="MFA",
                    resource="root",
                    title="Root account MFA is NOT enabled",
                    detail="The AWS root account does not have MFA enabled. Root has unrestricted access to all resources.",
                    recommendation="Enable hardware MFA on the root account immediately. See: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_mfa.html",
                )
            else:
                self._add_finding(
                    severity="INFO",
                    category="MFA",
                    resource="root",
                    title="Root account MFA is enabled",
                    detail="Root account has MFA enabled — good practice.",
                    recommendation="Continue to restrict root usage. Use IAM users for day-to-day operations.",
                )
        except ClientError as e:
            self._add_finding("HIGH", "MFA", "root", "Could not check root MFA", str(e), "Ensure auditor has iam:GetAccountSummary permission.")

    # ── Check 2: Users Without MFA ───────────────────────────────

    def check_users_without_mfa(self):
        """Lists console users who have no MFA device."""
        try:
            users = self.iam.list_users()["Users"]
            for user in users:
                username = user["UserName"]
                # Check if user has console access
                try:
                    self.iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console = False
                    else:
                        continue

                if not has_console:
                    continue

                # Check MFA devices
                mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa_devices:
                    self._add_finding(
                        severity="HIGH",
                        category="MFA",
                        resource=f"iam:user:{username}",
                        title=f"User '{username}' has console access but NO MFA",
                        detail=f"User has password-based console login but no MFA device attached.",
                        recommendation="Enforce MFA via IAM policy condition: aws:MultiFactorAuthPresent. Consider using SCP to enforce org-wide.",
                    )
        except ClientError as e:
            self._add_finding("MEDIUM", "MFA", "users", "Could not enumerate users", str(e), "Ensure auditor has iam:ListUsers and iam:ListMFADevices permissions.")

    # ── Check 3: Access Key Rotation ─────────────────────────────

    def check_access_key_rotation(self, max_age_days: int = 90):
        """Flags access keys older than max_age_days."""
        try:
            users = self.iam.list_users()["Users"]
            for user in users:
                username = user["UserName"]
                keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    age = self._days_since(key["CreateDate"])
                    if age > max_age_days:
                        severity = "CRITICAL" if age > 180 else "HIGH"
                        self._add_finding(
                            severity=severity,
                            category="Credentials",
                            resource=f"iam:user:{username}:key:{key['AccessKeyId']}",
                            title=f"Access key {key['AccessKeyId']} is {age} days old",
                            detail=f"User '{username}' has an active access key created {age} days ago. Keys older than {max_age_days} days violate least-privilege rotation policy.",
                            recommendation="Rotate access keys immediately. Use IAM Credential Report to audit all keys. Automate rotation with AWS Secrets Manager.",
                        )
        except ClientError as e:
            self._add_finding("MEDIUM", "Credentials", "access-keys", "Could not check key rotation", str(e), "Ensure iam:ListAccessKeys permission.")

    # ── Check 4: Inactive Users ───────────────────────────────────

    def check_inactive_users(self, inactive_days: int = 90):
        """Flags users who have not logged in for over inactive_days."""
        try:
            report = self._get_credential_report()
            for row in report:
                username = row.get("user", "")
                if username == "<root_account>":
                    continue
                last_login = row.get("password_last_used", "N/A")
                if last_login in ("N/A", "no_information", ""):
                    self._add_finding(
                        severity="MEDIUM",
                        category="Credentials",
                        resource=f"iam:user:{username}",
                        title=f"User '{username}' has NEVER logged in",
                        detail="This user has a password set but has never used it. May be an orphaned account.",
                        recommendation="Disable or delete unused IAM users. Review user purpose. Implement periodic access reviews.",
                    )
                else:
                    try:
                        age = self._days_since(last_login)
                        if age > inactive_days:
                            self._add_finding(
                                severity="MEDIUM",
                                category="Credentials",
                                resource=f"iam:user:{username}",
                                title=f"User '{username}' inactive for {age} days",
                                detail=f"Last login was {age} days ago ({last_login}).",
                                recommendation="Disable inactive users. Implement automated deprovisioning after 90 days of inactivity.",
                            )
                    except Exception:
                        pass
        except Exception as e:
            self._add_finding("LOW", "Credentials", "users", "Could not check user activity", str(e), "Ensure GenerateCredentialReport permission.")

    # ── Check 5: Wildcard Policies ───────────────────────────────

    def check_wildcard_policies(self):
        """Detects inline and managed policies with Action:* or Resource:*."""
        try:
            # Check customer managed policies
            paginator = self.iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    try:
                        version = self.iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"],
                        )["PolicyVersion"]
                        doc = version["Document"]
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for stmt in statements:
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            effect = stmt.get("Effect", "")
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if effect == "Allow" and "*" in actions:
                                self._add_finding(
                                    severity="CRITICAL",
                                    category="Policy",
                                    resource=f"iam:policy:{policy['PolicyName']}",
                                    title=f"Policy '{policy['PolicyName']}' grants Action:*",
                                    detail=f"This policy allows ALL AWS actions. Violates least-privilege principle. Policy ARN: {policy['Arn']}",
                                    recommendation="Replace wildcard actions with specific service actions (e.g. s3:GetObject). Apply permission boundaries.",
                                )
                            elif effect == "Allow" and "*" in resources and "*" not in actions:
                                self._add_finding(
                                    severity="HIGH",
                                    category="Policy",
                                    resource=f"iam:policy:{policy['PolicyName']}",
                                    title=f"Policy '{policy['PolicyName']}' grants Resource:*",
                                    detail=f"Policy applies to ALL resources. Should be scoped to specific ARNs.",
                                    recommendation="Scope Resource to specific ARNs (e.g. arn:aws:s3:::my-bucket/*). Use ARN conditions.",
                                )
                    except ClientError:
                        continue
        except ClientError as e:
            self._add_finding("MEDIUM", "Policy", "policies", "Could not audit policies", str(e), "Ensure iam:ListPolicies and iam:GetPolicyVersion permissions.")

    # ── Check 6: Password Policy ─────────────────────────────────

    def check_password_policy(self):
        """Validates account password policy against CIS benchmarks."""
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            checks = [
                ("MinimumPasswordLength", 14, "Minimum password length should be >= 14"),
                ("RequireUppercaseCharacters", True, "Require uppercase characters"),
                ("RequireLowercaseCharacters", True, "Require lowercase characters"),
                ("RequireNumbers", True, "Require numbers"),
                ("RequireSymbols", True, "Require symbols"),
                ("MaxPasswordAge", 90, "Max password age should be <= 90 days"),
                ("PasswordReusePrevention", 24, "Prevent reuse of last 24 passwords"),
            ]
            for key, threshold, description in checks:
                val = policy.get(key)
                if val is None:
                    self._add_finding("MEDIUM", "PasswordPolicy", "account", f"Password policy missing: {key}", description, f"Enable '{key}' in account password policy.")
                elif isinstance(threshold, bool) and val != threshold:
                    self._add_finding("MEDIUM", "PasswordPolicy", "account", f"Password policy: {description}", f"'{key}' is set to {val}.", "Update password policy to meet CIS AWS Benchmark 1.5-1.11.")
                elif isinstance(threshold, int) and key == "MaxPasswordAge" and val > threshold:
                    self._add_finding("MEDIUM", "PasswordPolicy", "account", f"Password max age is {val} days", f"Passwords expire every {val} days. CIS recommends <= {threshold}.", "Reduce MaxPasswordAge to 90 days or less.")
                elif isinstance(threshold, int) and key == "MinimumPasswordLength" and val < threshold:
                    self._add_finding("MEDIUM", "PasswordPolicy", "account", f"Password minimum length is {val}", f"CIS recommends >= {threshold} characters.", "Increase MinimumPasswordLength to at least 14.")
                elif isinstance(threshold, int) and key == "PasswordReusePrevention" and val < threshold:
                    self._add_finding("LOW", "PasswordPolicy", "account", f"Password reuse prevention is {val}", f"Only {val} previous passwords blocked. CIS recommends >= {threshold}.", "Set PasswordReusePrevention to 24.")
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                self._add_finding("HIGH", "PasswordPolicy", "account", "No account password policy set", "AWS account has no password policy configured.", "Set a strong password policy meeting CIS AWS Benchmark requirements.")
            else:
                self._add_finding("LOW", "PasswordPolicy", "account", "Could not read password policy", str(e), "Ensure iam:GetAccountPasswordPolicy permission.")

    # ── Check 7: Roles with Overly Broad Trust ───────────────────

    def check_role_trust_policies(self):
        """Detects roles that trust all principals (*) in their trust policy."""
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    doc = role.get("AssumeRolePolicyDocument", {})
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            self._add_finding(
                                severity="CRITICAL",
                                category="RoleTrust",
                                resource=f"iam:role:{role['RoleName']}",
                                title=f"Role '{role['RoleName']}' trusts ALL principals (*)",
                                detail=f"The trust policy allows ANY AWS principal to assume this role. Role ARN: {role['Arn']}",
                                recommendation="Restrict Principal to specific account IDs, services, or role ARNs. Add Condition keys like aws:PrincipalOrgID.",
                            )
        except ClientError as e:
            self._add_finding("MEDIUM", "RoleTrust", "roles", "Could not audit role trust policies", str(e), "Ensure iam:ListRoles permission.")

    # ── Check 8: Root Access Keys ────────────────────────────────

    def check_root_access_keys(self):
        """Checks if root account has active access keys (CIS 1.4)."""
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            root_keys = summary.get("AccountAccessKeysPresent", 0)
            if root_keys > 0:
                self._add_finding(
                    severity="CRITICAL",
                    category="Credentials",
                    resource="root",
                    title="Root account has active access keys",
                    detail=f"Root account has {root_keys} access key(s). Root keys are extremely dangerous — they bypass all SCPs and permission boundaries.",
                    recommendation="Delete root access keys immediately. Use IAM roles with least-privilege for all programmatic access.",
                )
            else:
                self._add_finding("INFO", "Credentials", "root", "Root has no access keys", "Good — root account has no programmatic access keys.", "Maintain this posture.")
        except ClientError as e:
            self._add_finding("HIGH", "Credentials", "root", "Could not check root keys", str(e), "Ensure iam:GetAccountSummary permission.")

    # ── Credential Report ────────────────────────────────────────

    def _get_credential_report(self) -> list[dict]:
        """Generates and parses the IAM credential report CSV."""
        import csv, io, time
        # Generate report
        while True:
            resp = self.iam.generate_credential_report()
            if resp["State"] == "COMPLETE":
                break
            time.sleep(2)
        report = self.iam.get_credential_report()
        content = report["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    # ── Run All Checks ───────────────────────────────────────────

    def run_all(self) -> dict:
        """Run every audit check and return full results."""
        checks = [
            self.check_root_mfa,
            self.check_root_access_keys,
            self.check_users_without_mfa,
            self.check_access_key_rotation,
            self.check_inactive_users,
            self.check_wildcard_policies,
            self.check_password_policy,
            self.check_role_trust_policies,
        ]
        for check in checks:
            try:
                check()
            except Exception as e:
                self._add_finding("LOW", "Auditor", "internal", f"Check failed: {check.__name__}", str(e), "Review auditor permissions.")

        return {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": self.summary,
            "total_findings": len(self.findings),
            "findings": sorted(self.findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
        }
