"""
Tests for AWS IAM Security Auditor
Uses unittest.mock to simulate boto3 responses — no real AWS account needed.
Run: pytest tests/ -v
Author: Ankita Dixit | github.com/master-coder1998
"""

import pytest
from unittest.mock import patch, MagicMock
import datetime

# ── Import auditor ────────────────────────────────────────────
import sys
sys.path.insert(0, ".")
from auditor.iam_auditor import IAMAuditor


def make_auditor():
    """Create an IAMAuditor with a mocked boto3 client."""
    with patch("auditor.iam_auditor.boto3.Session") as mock_session:
        mock_session.return_value.client.return_value = MagicMock()
        auditor = IAMAuditor()
    return auditor


# ── Root MFA ──────────────────────────────────────────────────

class TestRootMFA:
    def test_root_mfa_disabled_is_critical(self):
        auditor = make_auditor()
        auditor.iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        auditor.check_root_mfa()
        assert any(f["severity"] == "CRITICAL" and "MFA" in f["title"] for f in auditor.findings)

    def test_root_mfa_enabled_is_info(self):
        auditor = make_auditor()
        auditor.iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        auditor.check_root_mfa()
        assert any(f["severity"] == "INFO" for f in auditor.findings)


# ── Root Access Keys ──────────────────────────────────────────

class TestRootAccessKeys:
    def test_root_has_keys_is_critical(self):
        auditor = make_auditor()
        auditor.iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 1}}
        auditor.check_root_access_keys()
        assert any(f["severity"] == "CRITICAL" and "access key" in f["title"].lower() for f in auditor.findings)

    def test_root_no_keys_is_info(self):
        auditor = make_auditor()
        auditor.iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 0}}
        auditor.check_root_access_keys()
        assert any(f["severity"] == "INFO" for f in auditor.findings)


# ── Users Without MFA ─────────────────────────────────────────

class TestUsersWithoutMFA:
    def test_console_user_without_mfa_flagged(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
        auditor.iam.get_login_profile.return_value = {"LoginProfile": {}}
        auditor.iam.list_mfa_devices.return_value = {"MFADevices": []}
        auditor.check_users_without_mfa()
        assert any("alice" in f["resource"] and f["severity"] == "HIGH" for f in auditor.findings)

    def test_user_with_mfa_not_flagged(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "bob"}]}
        auditor.iam.get_login_profile.return_value = {"LoginProfile": {}}
        auditor.iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/bob"}]}
        auditor.check_users_without_mfa()
        assert not any("bob" in f["resource"] and f["severity"] == "HIGH" for f in auditor.findings)


# ── Access Key Rotation ───────────────────────────────────────

class TestAccessKeyRotation:
    def _old_key_date(self, days):
        return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)

    def test_key_older_than_90_days_flagged_high(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "charlie"}]}
        auditor.iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": self._old_key_date(100),
        }]}
        auditor.check_access_key_rotation(max_age_days=90)
        assert any("charlie" in f["resource"] and f["severity"] in ("HIGH", "CRITICAL") for f in auditor.findings)

    def test_key_older_than_180_days_flagged_critical(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "dave"}]}
        auditor.iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": self._old_key_date(200),
        }]}
        auditor.check_access_key_rotation(max_age_days=90)
        assert any("dave" in f["resource"] and f["severity"] == "CRITICAL" for f in auditor.findings)

    def test_fresh_key_not_flagged(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "eve"}]}
        auditor.iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Active",
            "CreateDate": self._old_key_date(10),
        }]}
        auditor.check_access_key_rotation(max_age_days=90)
        assert not any("eve" in f["resource"] and f["severity"] in ("HIGH", "CRITICAL") for f in auditor.findings)

    def test_inactive_key_not_flagged(self):
        auditor = make_auditor()
        auditor.iam.list_users.return_value = {"Users": [{"UserName": "frank"}]}
        auditor.iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Status": "Inactive",
            "CreateDate": self._old_key_date(200),
        }]}
        auditor.check_access_key_rotation(max_age_days=90)
        assert not any("frank" in f["resource"] and f["severity"] in ("HIGH", "CRITICAL") for f in auditor.findings)


# ── Wildcard Policies ─────────────────────────────────────────

class TestWildcardPolicies:
    def test_action_wildcard_is_critical(self):
        auditor = make_auditor()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Policies": [{
            "PolicyName": "DangerousPolicy",
            "Arn": "arn:aws:iam::123:policy/DangerousPolicy",
            "DefaultVersionId": "v1",
        }]}]
        auditor.iam.get_paginator.return_value = mock_paginator
        auditor.iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }}}
        auditor.check_wildcard_policies()
        assert any("CRITICAL" == f["severity"] and "Action:*" in f["title"] for f in auditor.findings)

    def test_resource_wildcard_is_high(self):
        auditor = make_auditor()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Policies": [{
            "PolicyName": "BroadPolicy",
            "Arn": "arn:aws:iam::123:policy/BroadPolicy",
            "DefaultVersionId": "v1",
        }]}]
        auditor.iam.get_paginator.return_value = mock_paginator
        auditor.iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }}}
        auditor.check_wildcard_policies()
        assert any("HIGH" == f["severity"] and "Resource:*" in f["title"] for f in auditor.findings)


# ── Password Policy ───────────────────────────────────────────

class TestPasswordPolicy:
    def test_no_password_policy_is_high(self):
        from botocore.exceptions import ClientError
        auditor = make_auditor()
        error = ClientError({"Error": {"Code": "NoSuchEntity", "Message": "No policy"}}, "GetAccountPasswordPolicy")
        auditor.iam.get_account_password_policy.side_effect = error
        auditor.check_password_policy()
        assert any(f["severity"] == "HIGH" and "No account password policy" in f["title"] for f in auditor.findings)

    def test_weak_minimum_length_flagged(self):
        auditor = make_auditor()
        auditor.iam.get_account_password_policy.return_value = {"PasswordPolicy": {
            "MinimumPasswordLength": 6,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        }}
        auditor.check_password_policy()
        assert any("minimum length" in f["title"].lower() for f in auditor.findings)


# ── Role Trust Policies ───────────────────────────────────────

class TestRoleTrust:
    def test_role_trusting_all_is_critical(self):
        auditor = make_auditor()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Roles": [{
            "RoleName": "OpenRole",
            "Arn": "arn:aws:iam::123:role/OpenRole",
            "AssumeRolePolicyDocument": {
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
            }
        }]}]
        auditor.iam.get_paginator.return_value = mock_paginator
        auditor.check_role_trust_policies()
        assert any(f["severity"] == "CRITICAL" and "OpenRole" in f["resource"] for f in auditor.findings)


# ── Summary ───────────────────────────────────────────────────

class TestSummary:
    def test_summary_counts_correctly(self):
        auditor = make_auditor()
        auditor._add_finding("CRITICAL", "Test", "res", "t1", "d1", "r1")
        auditor._add_finding("CRITICAL", "Test", "res", "t2", "d2", "r2")
        auditor._add_finding("HIGH", "Test", "res", "t3", "d3", "r3")
        assert auditor.summary["CRITICAL"] == 2
        assert auditor.summary["HIGH"] == 1

    def test_run_all_returns_sorted_findings(self):
        auditor = make_auditor()
        auditor._add_finding("INFO", "Test", "res", "info finding", "d", "r")
        auditor._add_finding("CRITICAL", "Test", "res", "critical finding", "d", "r")
        # run_all sorts findings
        from unittest.mock import patch
        with patch.object(auditor, "check_root_mfa"), \
             patch.object(auditor, "check_root_access_keys"), \
             patch.object(auditor, "check_users_without_mfa"), \
             patch.object(auditor, "check_access_key_rotation"), \
             patch.object(auditor, "check_inactive_users"), \
             patch.object(auditor, "check_wildcard_policies"), \
             patch.object(auditor, "check_password_policy"), \
             patch.object(auditor, "check_role_trust_policies"):
            results = auditor.run_all()
        assert results["findings"][0]["severity"] == "CRITICAL"
