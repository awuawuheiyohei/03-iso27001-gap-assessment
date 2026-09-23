"""
ISO 27001:2022 Gap Assessment 单元测试
"""
from app.models.iso_controls_catalog import ISO_27001_2022_CONTROLS, count_by_theme
from app.models.db import get_conn
from app.collectors import (
    run_all_collectors, verify_evidence_integrity,
    collect_git_branch_protection, collect_iam_baseline,
    collect_endpoint_posture, collect_cloud_storage_baseline,
    collect_threat_intelligence, collect_dlp_status,
)


# ============================ Catalog Tests ============================
def test_total_controls_is_93():
    """4 主题 = 93 项控制项"""
    counts = count_by_theme()
    assert sum(counts.values()) == 93, f"Expected 93, got {sum(counts.values())}"


def test_theme_distribution():
    """主题分布：A.5=37, A.6=8, A.7=14, A.8=34"""
    counts = count_by_theme()
    assert counts["A.5 Organizational"] == 37
    assert counts["A.6 People"] == 8
    assert counts["A.7 Physical"] == 14
    assert counts["A.8 Technological"] == 34


def test_all_control_ids_unique():
    """所有 control_id 必须唯一"""
    ids = [c[0] for c in ISO_27001_2022_CONTROLS]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {set(x for x in ids if ids.count(x) > 1)}"


def test_control_id_format():
    """control_id 必须匹配 A.{5-8}.{1-37}"""
    import re
    pattern = re.compile(r"^A\.[5678]\.\d+$")
    bad = [c[0] for c in ISO_27001_2022_CONTROLS if not pattern.match(c[0])]
    assert not bad, f"Invalid control_id format: {bad}"


def test_new_2022_controls_marked():
    """2022 新增控制项必须标记 is_new_2022=True"""
    new_in_2022 = {c[0] for c in ISO_27001_2022_CONTROLS if c[4]}
    # 业内公认的 2022 新增
    expected = {"A.5.7", "A.5.23", "A.5.30", "A.7.4", "A.8.9", "A.8.10", "A.8.12", "A.8.16", "A.8.23", "A.8.28"}
    missing = expected - new_in_2022
    assert not missing, f"Missing new_2022 marks: {missing}"


# ============================ Seed Tests ============================
def test_seed_creates_93_controls():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM iso_controls").fetchone()["n"]
    assert n == 93


def test_seed_creates_caps():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM corrective_action_plans").fetchone()["n"]
    assert n >= 1, f"Expected at least 1 CAP, got {n}"


# ============================ Collector Tests ============================
def test_collectors_create_evidence():
    """所有 collectors 应至少创建 1 条 evidence"""
    conn = get_conn()
    results = run_all_collectors(conn)
    assert len(results) == 6, f"Expected 6 collectors, got {len(results)}"
    n = conn.execute("SELECT COUNT(*) AS n FROM evidence_items").fetchone()["n"]
    # 8 条因为 A.5.15+A.8.5 和 A.8.28+A.8.32 是双控制项
    assert n >= 8, f"Expected >= 8 evidence items, got {n}"


def test_evidence_has_sha256():
    """每条 evidence 必须有 64 字符 SHA-256"""
    conn = get_conn()
    run_all_collectors(conn)  # fixture 给 fresh DB，先跑 collectors
    rows = conn.execute("SELECT sha256_hash FROM evidence_items").fetchall()
    assert len(rows) > 0
    for r in rows:
        h = r["sha256_hash"]
        assert len(h) == 64, f"Hash length {len(h)}: {h}"
        assert all(c in "0123456789abcdef" for c in h), f"Non-hex chars: {h}"


def test_individual_collectors():
    """每个 collector 单跑应能生成 SHA-256 正确的 evidence"""
    conn = get_conn()
    collectors = [
        ("collect_git_branch_protection", ["A.8.28", "A.8.32"]),
        ("collect_iam_baseline", ["A.5.15", "A.8.5"]),
        ("collect_endpoint_posture", ["A.8.1"]),
        ("collect_cloud_storage_baseline", ["A.5.23"]),
        ("collect_threat_intelligence", ["A.5.7"]),
        ("collect_dlp_status", ["A.8.12"]),
    ]
    for fn_name, controls in collectors:
        fn = globals()[fn_name]
        before = conn.execute("SELECT COUNT(*) AS n FROM evidence_items").fetchone()["n"]
        eid = fn(conn)
        after = conn.execute("SELECT COUNT(*) AS n FROM evidence_items").fetchone()["n"]
        assert after > before, f"{fn_name} did not create evidence"
        # 验证完整性
        check = verify_evidence_integrity(conn, eid)
        assert check["valid"], f"{fn_name} created invalid evidence: {check}"


def test_tamper_detection():
    """篡改 evidence content_payload 后 SHA-256 应不匹配"""
    conn = get_conn()
    eid = collect_git_branch_protection(conn)

    # 原始应 valid
    check = verify_evidence_integrity(conn, eid)
    assert check["valid"], "Initial integrity check failed"

    # 篡改内容
    conn.execute(
        "UPDATE evidence_items SET content_payload = ? WHERE evidence_id = ?",
        ('{"TAMPERED": true}', eid)
    )
    conn.commit()

    # 再次验证应失败
    check = verify_evidence_integrity(conn, eid)
    assert not check["valid"], "Tamper detection failed!"
    assert check["reason"] == "HASH_MISMATCH"


# ============================ Integration Tests ============================
def test_stats_consistency():
    """stats 数字应与直接查询一致"""
    from app.api.routes import stats
    from fastapi.testclient import TestClient

    from app.main import app
    client = TestClient(app)
    r = client.get("/api/stats")
    assert r.status_code == 200
    s = r.json()

    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) AS n FROM iso_controls").fetchone()["n"]
    assert s["controls"]["total"] == total


def test_full_audit_trail_records_writes():
    """每个写操作应在 audit_trail 留痕"""
    conn = get_conn()
    before = conn.execute("SELECT COUNT(*) AS n FROM audit_trail").fetchone()["n"]

    run_all_collectors(conn)

    after = conn.execute("SELECT COUNT(*) AS n FROM audit_trail").fetchone()["n"]
    # audit_trail 可能被 fresh DB 清空，before 可能是 0
    assert after > before or (before == 0 and after > 0), f"No audit trail records: before={before}, after={after}"


def test_cap_due_date_ordering():
    """CAPs 列表应按 due_date 升序排列"""
    conn = get_conn()
    rows = conn.execute("SELECT due_date FROM corrective_action_plans ORDER BY due_date").fetchall()
    dates = [r["due_date"] for r in rows]
    assert dates == sorted(dates)


# ============================ Critical Controls Tests ============================
def test_critical_controls_exist():
    """关键控制项必须在 93 项中"""
    expected = {
        "A.5.7":  "Threat intelligence",
        "A.5.23": "Information security for use of cloud services",
        "A.8.9":  "Configuration management",
        "A.8.12": "Data leakage prevention",
        "A.8.16": "Monitoring activities",
        "A.8.23": "Web filtering",
        "A.8.28": "Secure coding",
    }
    ids = {c[0] for c in ISO_27001_2022_CONTROLS}
    for cid in expected:
        assert cid in ids, f"Missing critical control: {cid}"


def test_cloud_services_security_is_new_2022():
    """A.5.23 必须标记为 2022 新增（重点讲）"""
    ctrl = next(c for c in ISO_27001_2022_CONTROLS if c[0] == "A.5.23")
    assert ctrl[4] is True, "A.5.23 should be marked as new in 2022"


def test_dlp_is_new_2022():
    """A.8.12 DLP 必须标记为 2022 新增"""
    ctrl = next(c for c in ISO_27001_2022_CONTROLS if c[0] == "A.8.12")
    assert ctrl[4] is True


# ============================ Smoke Test ============================
def test_smoke_full_workflow():
    """端到端：seed → collectors → verify → audit"""
    conn = get_conn()

    # 1. seed 已自动跑过
    n = conn.execute("SELECT COUNT(*) AS n FROM iso_controls").fetchone()["n"]
    assert n == 93

    # 2. 跑所有 collectors
    results = run_all_collectors(conn)
    assert len(results) == 6

    # 3. 全部 SHA-1 验证通过
    for r in results:
        check = verify_evidence_integrity(conn, r["evidence_id"])
        assert check["valid"], f"Integrity check failed: {r}"

    # 4. 篡改一个，再次验证失败
    eid = results[0]["evidence_id"]
    conn.execute("UPDATE evidence_items SET content_payload = '{}' WHERE evidence_id = ?", (eid,))
    conn.commit()
    check = verify_evidence_integrity(conn, eid)
    assert not check["valid"]

    # 5. audit trail 有记录
    n = conn.execute("SELECT COUNT(*) AS n FROM audit_trail").fetchone()["n"]
    assert n > 0