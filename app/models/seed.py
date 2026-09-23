"""
Seed 93 ISO 27001:2022 控制项 + 演示状态
- 部分控制项标记为 COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT 用于演示
- 演示数据使用通用行业默认值（非 NDA）
"""
from datetime import datetime, timedelta
from .db import get_conn, init_db
from .iso_controls_catalog import ISO_27001_2022_CONTROLS


# 演示用状态分布（基于真实审计经验：大部分 COMPLIANT，部分 PARTIALLY，少数 NON_COMPLIANT）
DEMO_STATUS_MAP = {
    # 高优先级 / 新控制项 → 更可能 PARTIALLY
    "A.5.7":  ("PARTIALLY_COMPLIANT", "HIGH",     "SOC Team"),
    "A.5.23": ("PARTIALLY_COMPLIANT", "CRITICAL", "Cloud Infrastructure"),
    "A.8.9":  ("PARTIALLY_COMPLIANT", "HIGH",     "DevSecOps"),
    "A.8.12": ("NON_COMPLIANT",       "CRITICAL", "Data Protection"),
    "A.8.16": ("PARTIALLY_COMPLIANT", "HIGH",     "SOC Team"),
    "A.8.23": ("COMPLIANT",           "MEDIUM",   "IT Operations"),
    "A.8.28": ("COMPLIANT",           "HIGH",     "R&D / DevSecOps"),
    "A.5.30": ("PARTIALLY_COMPLIANT", "HIGH",     "BCP Team"),
    # 其他保持 NOT_EVALUATED 待审计师补全
}


def seed_controls(verbose: bool = False) -> dict:
    """seed 93 控制项，返回统计 dict"""
    init_db()
    conn = get_conn()

    # 清空（FK 约束顺序：先删 evidence / caps / controls）
    conn.execute("DELETE FROM evidence_items")
    conn.execute("DELETE FROM corrective_action_plans")
    conn.execute("DELETE FROM audit_trail")
    conn.execute("DELETE FROM iso_controls")

    inserted = 0
    for control_id, theme, title, description, is_new in ISO_27001_2022_CONTROLS:
        if control_id in DEMO_STATUS_MAP:
            status, risk, owner = DEMO_STATUS_MAP[control_id]
        else:
            status, risk, owner = "NOT_EVALUATED", "MEDIUM", "IT Security"

        soa_just = (
            f"Applicable for global SaaS operations and B2B client commitments. "
            f"Control '{title}' is in scope per information security risk assessment."
        )

        conn.execute(
            """INSERT INTO iso_controls
               (control_id, theme, title, description, is_applicable, soa_justification,
                status, risk_rating, owner, is_new_2022)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (control_id, theme, title, description, 1, soa_just, status, risk, owner, int(is_new))
        )
        inserted += 1

    conn.commit()
    conn.close()

    if verbose:
        print(f"[+] Seeded {inserted} controls")

    return {
        "total": inserted,
        "compliant": sum(1 for cid in DEMO_STATUS_MAP.values() if cid[0] == "COMPLIANT"),
        "partial": sum(1 for cid in DEMO_STATUS_MAP.values() if cid[0] == "PARTIALLY_COMPLIANT"),
        "non_compliant": sum(1 for cid in DEMO_STATUS_MAP.values() if cid[0] == "NON_COMPLIANT"),
        "not_evaluated": inserted - len(DEMO_STATUS_MAP),
    }


def seed_demo_caps(verbose: bool = False) -> int:
    """Seed 3 个示范 CAP（含 SLA）"""
    conn = get_conn()

    # 防止重复
    conn.execute("DELETE FROM corrective_action_plans")

    today = datetime.utcnow()
    caps = [
        # NON_COMPLIANT + < 7 天 = 红色 SLA
        {
            "control_id": "A.8.12",
            "gap": "Endpoint DLP agent coverage at 65% (target 95%); Safari upload inspection disabled.",
            "action": "Roll out Jamf policy to all remote engineers + enable cloud storage blocking rules.",
            "owner": "Alex Zhang (Data Security)",
            "due_days": 5,
            "status": "IN_PROGRESS",
        },
        # PARTIALLY_COMPLIANT + < 30 天 = 黄色 SLA
        {
            "control_id": "A.5.7",
            "gap": "Threat intel feed configured but no automated IOC-to-SIOKE correlation.",
            "action": "Integrate MISP feed with SIEM via SOAR playbook; weekly IOC digest.",
            "owner": "Sam Lee (SOC Team)",
            "due_days": 21,
            "status": "OPEN",
        },
        # PARTIALLY_COMPLIANT + 已 RESOLVED
        {
            "control_id": "A.8.28",
            "gap": "SAST scanning not blocking PR merges on critical severity findings.",
            "action": "Enable Semgrep 'block on high' rule + Slack alert channel.",
            "owner": "Priya Wang (R&D DevSecOps)",
            "due_days": -7,  # 7 天前已完成
            "status": "RESOLVED",
        },
    ]

    import uuid
    inserted = 0
    for c in caps:
        cap_id = str(uuid.uuid4())
        due_date = (today + timedelta(days=c["due_days"])).strftime("%Y-%m-%d")
        resolved_at = (today + timedelta(days=c["due_days"])).isoformat() if c["due_days"] < 0 else None

        conn.execute(
            """INSERT INTO corrective_action_plans
               (cap_id, control_id, gap_description, remediation_action,
                assigned_owner, due_date, status, created_at, resolved_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cap_id, c["control_id"], c["gap"], c["action"],
             c["owner"], due_date, c["status"], today.isoformat(), resolved_at)
        )
        inserted += 1

    conn.commit()
    conn.close()
    if verbose:
        print(f"[+] Seeded {inserted} CAPs")
    return inserted


def seed_all(verbose: bool = False) -> dict:
    """一键 seed 所有演示数据"""
    init_db()
    stats = seed_controls(verbose=verbose)
    caps_n = seed_demo_caps(verbose=verbose)
    return {**stats, "caps": caps_n}


if __name__ == "__main__":
    stats = seed_all(verbose=True)
    print(f"\n[+] Seed summary: {stats}")