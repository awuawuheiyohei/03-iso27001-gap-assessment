"""
Evidence Collector Engine - 自动化证据收集插件
收集到的模拟控制项写入 evidence_items 表，并立即计算 SHA-256 摘要（防篡改）
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from ..models.db import get_conn, write_audit


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_sha256(payload_str: str) -> str:
    return hashlib.sha256(payload_str.encode("utf-8")).hexdigest()


def _create_evidence(conn, control_id: str, source_name: str, payload: dict) -> str:
    """创建一条 evidence 并立即计算 SHA-256，返回 evidence_id"""
    raw_json = json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2)
    sha256 = _compute_sha256(raw_json)
    evidence_id = str(uuid.uuid4())
    collected_at = _utcnow_iso()

    conn.execute(
        """INSERT INTO evidence_items
           (evidence_id, control_id, source_name, collected_at, content_payload, sha256_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, control_id, source_name, collected_at, raw_json, sha256)
    )
    conn.commit()

    # 写审计 trail
    write_audit(conn, actor=source_name, action="COLLECT_EVIDENCE",
                entity_type="EvidenceItem", entity_id=evidence_id,
                details={"control_id": control_id, "sha256_prefix": sha256[:12]})

    return evidence_id


def verify_evidence_integrity(conn, evidence_id: str) -> dict:
    """验证 evidence 的 SHA-256 是否被篡改"""
    cur = conn.execute(
        "SELECT sha256_hash, content_payload FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cur.fetchone()
    if not row:
        return {"evidence_id": evidence_id, "valid": False, "reason": "NOT_FOUND"}

    expected_hash = row[0]
    payload = row[1]
    computed = _compute_sha256(payload)
    is_valid = (computed == expected_hash)

    write_audit(conn, actor="system", action="VERIFY_HASH",
                entity_type="EvidenceItem", entity_id=evidence_id,
                details={"valid": is_valid})

    return {
        "evidence_id": evidence_id,
        "valid": is_valid,
        "expected_prefix": expected_hash[:16],
        "computed_prefix": computed[:16],
        "reason": "OK" if is_valid else "HASH_MISMATCH",
    }


def collect_git_branch_protection(conn) -> str:
    """A.8.28 (Secure Coding) + A.8.32 (Change Management) evidence
    模拟从 GitHub API 抓取仓库分支保护配置"""
    data = {
        "service": "GitHub Enterprise Server",
        "repository": "tripbiz-core-booking-engine",
        "branch": "main",
        "branch_protection_rule": {
            "enforce_admins": True,
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
                "required_approving_review_count": 2,
            },
            "required_status_checks": {
                "strict": True,
                "contexts": [
                    "security/semgrep-sast",
                    "security/snyk-sca",
                    "ci/unit-tests-coverage-80%",
                ],
            },
            "required_linear_history": True,
            "allow_force_pushes": False,
            "allow_deletions": False,
            "signed_commit_required": True,
        },
        "inspection_time": _utcnow_iso(),
    }
    # A.8.28 主，关联 A.8.32
    eid1 = _create_evidence(conn, "A.8.28", "GitHub_API_Connector", data)
    eid2 = _create_evidence(conn, "A.8.32", "GitHub_API_Connector", data)
    return eid1  # 主返回


def collect_iam_baseline(conn) -> str:
    """A.5.15 (Access Control) + A.8.5 (Secure Authentication) evidence
    模拟从 Okta / AWS IAM Identity Center 抓取密码 + MFA 配置"""
    data = {
        "idp_provider": "Okta + AWS IAM Identity Center",
        "password_policy": {
            "min_length": 14,
            "require_lowercase": True,
            "require_uppercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "max_age_days": 90,
            "history_restriction_count": 24,
        },
        "mfa_configuration": {
            "enforce_mfa_all_users": True,
            "prompt_frequency": "Every sign-in from new IP or new device",
            "permitted_authenticators": ["FIDO2_WebAuthn", "Okta_Verify_Push_Number_Match"],
            "sms_voice_mfa_allowed": False,
        },
        "inactive_account_deprovisioning": {
            "auto_suspend_after_inactive_days": 45,
        },
        "privileged_access_review": {
            "frequency": "Quarterly UAR",
            "approver": "Asset Owner + IAM Team",
        },
        "audit_timestamp": _utcnow_iso(),
    }
    eid1 = _create_evidence(conn, "A.5.15", "Okta_IAM_API", data)
    eid2 = _create_evidence(conn, "A.8.5", "Okta_IAM_API", data)
    return eid1


def collect_endpoint_posture(conn) -> str:
    """A.8.1 (User Endpoint Devices) evidence
    模拟从 Jamf Pro 抓取 Mac fleet 安全基线"""
    data = {
        "mdm_platform": "Jamf Pro (macOS Fleet)",
        "fleet_size": 1250,
        "security_metrics": {
            "filevault_disk_encryption_rate": "99.8%",
            "gatekeeper_enforced": True,
            "system_firewall_enabled": True,
            "edr_agent_installed": "CrowdStrike Falcon Sensor (Version 7.12)",
            "tamper_protection_enabled": True,
            "os_version_min": "macOS 14.5 (Sonoma)",
            "auto_update_enabled": True,
        },
        "audit_timestamp": _utcnow_iso(),
    }
    return _create_evidence(conn, "A.8.1", "Jamf_MDM_Connector", data)


def collect_cloud_storage_baseline(conn) -> str:
    """A.5.23 (Cloud Services Security) evidence
    模拟从 AWS Config 抓取 S3 + KMS + CloudTrail 状态"""
    data = {
        "cloud_provider": "AWS Global Infrastructure",
        "primary_account_id": "892348123891",
        "s3_account_level_public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "default_encryption": "aws:kms with Customer Managed Keys (CMK)",
        "tls_enforcement": "Bucket Policy denies non-TLS requests",
        "cloudtrail_status": {
            "enabled": True,
            "multi_region": True,
            "log_file_validation": True,
            "s3_data_events": True,
            "retention_days": 365,
        },
        "guardduty_enabled": True,
        "securityhub_enabled": True,
        "audit_timestamp": _utcnow_iso(),
    }
    return _create_evidence(conn, "A.5.23", "AWS_Config_Inspector", data)


def collect_threat_intelligence(conn) -> str:
    """A.5.7 (Threat Intelligence) evidence
    模拟从 MISP / Recorded Future 抓取最新 IOC"""
    data = {
        "source": "MISP + Recorded Future feed",
        "feeds_active": 12,
        "iocs_last_24h": {
            "ipv4": 234,
            "domain": 89,
            "sha256": 567,
            "url": 1024,
        },
        "automated_correlation": {
            "enabled": True,
            "siem_integration": "Splunk Enterprise Security",
            "false_positive_rate": "4.2%",
        },
        "weekly_ioc_digest": "Sent to SOC team every Monday 09:00 UTC",
        "audit_timestamp": _utcnow_iso(),
    }
    return _create_evidence(conn, "A.5.7", "MISP_Threat_Feed", data)


def collect_dlp_status(conn) -> str:
    """A.8.12 (Data Leakage Prevention) evidence
    模拟从 DLP 控制台抓取覆盖率和策略"""
    data = {
        "dlp_vendor": "Microsoft Purview DLP + Endpoint DLP",
        "coverage_metrics": {
            "endpoint_dlp_agent_coverage_pct": 65,  # 当前 65% < 95% 目标 → 对应 NON_COMPLIANT
            "cloud_app_coverage_pct": 88,
            "email_dlp_coverage": True,
        },
        "policies_active": [
            "PII Detection (SSN, credit card, passport)",
            "Source Code Upload to Personal Cloud",
            "Customer PII Email Forwarding",
        ],
        "incidents_last_30_days": {
            "blocked": 234,
            "warned": 89,
            "auto_quarantined": 12,
        },
        "audit_timestamp": _utcnow_iso(),
    }
    return _create_evidence(conn, "A.8.12", "Microsoft_Purview_DLP", data)


# 全部 collector 列表（用于一键采集）
ALL_COLLECTORS = [
    ("collect_git_branch_protection", "GitHub Branch Protection (A.8.28 + A.8.32)", ["A.8.28", "A.8.32"]),
    ("collect_iam_baseline",           "IAM Password & MFA Baseline (A.5.15 + A.8.5)", ["A.5.15", "A.8.5"]),
    ("collect_endpoint_posture",       "Endpoint Posture (A.8.1)", ["A.8.1"]),
    ("collect_cloud_storage_baseline", "Cloud S3 / KMS / CloudTrail (A.5.23)", ["A.5.23"]),
    ("collect_threat_intelligence",   "Threat Intelligence Feed (A.5.7)", ["A.5.7"]),
    ("collect_dlp_status",            "DLP Coverage & Policy (A.8.12)", ["A.8.12"]),
]


def run_all_collectors(conn) -> list:
    """一键采集全部 collector，返回 evidence_id 列表"""
    results = []
    for fn_name, _label, _controls in ALL_COLLECTORS:
        fn_obj = globals()[fn_name]
        eid = fn_obj(conn)
        results.append({"collector": fn_name, "evidence_id": eid})
    return results