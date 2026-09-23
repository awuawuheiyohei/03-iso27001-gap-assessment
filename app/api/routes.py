"""
FastAPI 路由
"""
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..models.db import get_conn, row_to_dict, rows_to_dicts, write_audit
from ..models.seed import seed_all, seed_controls, seed_demo_caps
from ..collectors import (
    run_all_collectors, verify_evidence_integrity,
    collect_git_branch_protection, collect_iam_baseline, collect_endpoint_posture,
    collect_cloud_storage_baseline, collect_threat_intelligence, collect_dlp_status,
)


router = APIRouter()


# ============================ Health ============================
@router.get("/health")
async def health():
    return {"status": "ok", "service": "iso27001-gap-assessment", "version": "1.0.0"}


# ============================ Stats / Dashboard 概览 ============================
@router.get("/stats")
async def stats():
    """Dashboard 顶部 KPI"""
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) AS n FROM iso_controls").fetchone()["n"]
    applicable = conn.execute("SELECT COUNT(*) AS n FROM iso_controls WHERE is_applicable=1").fetchone()["n"]
    compliant = conn.execute("SELECT COUNT(*) AS n FROM iso_controls WHERE status='COMPLIANT'").fetchone()["n"]
    partial = conn.execute("SELECT COUNT(*) AS n FROM iso_controls WHERE status='PARTIALLY_COMPLIANT'").fetchone()["n"]
    non = conn.execute("SELECT COUNT(*) AS n FROM iso_controls WHERE status='NON_COMPLIANT'").fetchone()["n"]
    not_eval = conn.execute("SELECT COUNT(*) AS n FROM iso_controls WHERE status='NOT_EVALUATED'").fetchone()["n"]
    gaps = partial + non

    # CAP 状态
    caps_open = conn.execute("SELECT COUNT(*) AS n FROM corrective_action_plans WHERE status IN ('OPEN','IN_PROGRESS')").fetchone()["n"]
    caps_total = conn.execute("SELECT COUNT(*) AS n FROM corrective_action_plans").fetchone()["n"]
    caps_overdue = 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    caps_due_rows = conn.execute(
        """SELECT cap_id, due_date, status FROM corrective_action_plans
           WHERE status IN ('OPEN','IN_PROGRESS') AND due_date < ?""", (today,)
    ).fetchall()
    caps_overdue = len(caps_due_rows)

    evidence_n = conn.execute("SELECT COUNT(*) AS n FROM evidence_items").fetchone()["n"]
    audit_n = conn.execute("SELECT COUNT(*) AS n FROM audit_trail").fetchone()["n"]

    return {
        "controls": {
            "total": total,
            "applicable": applicable,
            "compliant": compliant,
            "partially_compliant": partial,
            "non_compliant": non,
            "not_evaluated": not_eval,
            "gaps": gaps,
            "compliance_pct": round(compliant / applicable * 100, 1) if applicable else 0,
        },
        "caps": {
            "total": caps_total,
            "open_or_in_progress": caps_open,
            "overdue": caps_overdue,
        },
        "evidence_count": evidence_n,
        "audit_trail_count": audit_n,
    }


# ============================ SoA / Controls ============================
@router.get("/controls")
async def list_controls(
    theme: Optional[str] = None,
    status: Optional[str] = None,
    is_new_2022: Optional[bool] = None,
    search: Optional[str] = None,
):
    """列出 93 控制项（可按 theme / status / is_new_2022 / 关键字过滤）"""
    conn = get_conn()
    query = "SELECT * FROM iso_controls WHERE 1=1"
    params = []
    if theme:
        query += " AND theme = ?"
        params.append(theme)
    if status:
        query += " AND status = ?"
        params.append(status)
    if is_new_2022 is not None:
        query += " AND is_new_2022 = ?"
        params.append(1 if is_new_2022 else 0)
    if search:
        query += " AND (control_id LIKE ? OR title LIKE ? OR description LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])
    query += " ORDER BY control_id"

    rows = conn.execute(query, params).fetchall()
    return rows_to_dicts(rows)


@router.get("/controls/{control_id}")
async def get_control(control_id: str):
    """单条控制项详情 + 关联 evidence + CAP"""
    cur = conn = get_conn()
    row = conn.execute("SELECT * FROM iso_controls WHERE control_id=?", (control_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    ctrl = row_to_dict(row)
    # 关联 evidence
    ev_rows = conn.execute(
        "SELECT evidence_id, source_name, collected_at, sha256_hash FROM evidence_items WHERE control_id=? ORDER BY collected_at DESC",
        (control_id,)
    ).fetchall()
    ctrl["evidences"] = rows_to_dicts(ev_rows)
    # 关联 CAP
    cap_rows = conn.execute(
        "SELECT * FROM corrective_action_plans WHERE control_id=? ORDER BY due_date ASC",
        (control_id,)
    ).fetchall()
    caps = rows_to_dicts(cap_rows)
    # 计算 days_remaining
    today = datetime.now(timezone.utc).date()
    for c in caps:
        try:
            d = datetime.fromisoformat(c["due_date"]).date()
            c["days_remaining"] = (d - today).days
            c["sla_color"] = "red" if c["days_remaining"] < 7 else ("yellow" if c["days_remaining"] < 30 else "green")
        except Exception:
            c["days_remaining"] = None
            c["sla_color"] = "gray"
    ctrl["caps"] = caps
    return ctrl


class ControlUpdate(BaseModel):
    status: Optional[str] = None
    risk_rating: Optional[str] = None
    owner: Optional[str] = None
    is_applicable: Optional[bool] = None
    soa_justification: Optional[str] = None


@router.put("/controls/{control_id}")
async def update_control(control_id: str, body: ControlUpdate, actor: str = "user"):
    """更新控制项状态 / 风险 / 责任人 / 适用性 / SoA 说明"""
    conn = get_conn()
    row = conn.execute("SELECT * FROM iso_controls WHERE control_id=?", (control_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")

    updates = []
    params = []
    if body.status is not None:
        updates.append("status = ?")
        params.append(body.status)
    if body.risk_rating is not None:
        updates.append("risk_rating = ?")
        params.append(body.risk_rating)
    if body.owner is not None:
        updates.append("owner = ?")
        params.append(body.owner)
    if body.is_applicable is not None:
        updates.append("is_applicable = ?")
        params.append(1 if body.is_applicable else 0)
    if body.soa_justification is not None:
        updates.append("soa_justification = ?")
        params.append(body.soa_justification)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = ?")
    params.append(datetime.now(timezone.utc).isoformat())
    params.append(control_id)

    conn.execute(f"UPDATE iso_controls SET {', '.join(updates)} WHERE control_id=?", params)
    conn.commit()
    write_audit(conn, actor=actor, action="UPDATE_CONTROL",
                entity_type="ISOControl", entity_id=control_id,
                details=body.dict(exclude_none=True))

    # 返回最新
    row = conn.execute("SELECT * FROM iso_controls WHERE control_id=?", (control_id,)).fetchone()
    return row_to_dict(row)


# ============================ Evidence ============================
@router.get("/evidence")
async def list_evidence(
    control_id: Optional[str] = None,
    source_name: Optional[str] = None,
    limit: int = Query(default=100, le=500),
):
    conn = get_conn()
    query = "SELECT * FROM evidence_items WHERE 1=1"
    params = []
    if control_id:
        query += " AND control_id=?"
        params.append(control_id)
    if source_name:
        query += " AND source_name=?"
        params.append(source_name)
    query += " ORDER BY collected_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    results = rows_to_dicts(rows)
    # 自动附带完整性 check
    for r in results:
        payload = r["content_payload"]
        import hashlib
        computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        r["integrity_valid"] = (computed == r["sha256_hash"])
    return results


@router.get("/evidence/{evidence_id}")
async def get_evidence(evidence_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM evidence_items WHERE evidence_id=?", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")
    result = row_to_dict(row)
    result["integrity_valid"] = True  # 默认，未篡改
    import hashlib
    computed = hashlib.sha256(result["content_payload"].encode("utf-8")).hexdigest()
    result["integrity_valid"] = (computed == result["sha256_hash"])
    return result


@router.post("/evidence/{evidence_id}/verify")
async def verify_evidence(evidence_id: str):
    conn = get_conn()
    return verify_evidence_integrity(conn, evidence_id)


# ============================ Collectors ============================
@router.post("/collectors/run-all")
async def collectors_run_all(actor: str = "dashboard_user"):
    conn = get_conn()
    write_audit(conn, actor=actor, action="RUN_ALL_COLLECTORS")
    results = run_all_collectors(conn)
    return {"collected": len(results), "items": results}


@router.post("/collectors/{collector_name}")
async def collectors_run_one(collector_name: str, actor: str = "dashboard_user"):
    conn = get_conn()
    fn_map = {
        "git_branch_protection": collect_git_branch_protection,
        "iam_baseline": collect_iam_baseline,
        "endpoint_posture": collect_endpoint_posture,
        "cloud_storage_baseline": collect_cloud_storage_baseline,
        "threat_intelligence": collect_threat_intelligence,
        "dlp_status": collect_dlp_status,
    }
    fn = fn_map.get(collector_name)
    if not fn:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_name}")
    write_audit(conn, actor=actor, action="RUN_COLLECTOR", entity_type=collector_name)
    eid = fn(conn)
    return {"evidence_id": eid, "collector": collector_name}


# ============================ CAP ============================
@router.get("/caps")
async def list_caps(status: Optional[str] = None):
    conn = get_conn()
    query = "SELECT * FROM corrective_action_plans WHERE 1=1"
    params = []
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY due_date ASC"
    rows = conn.execute(query, params).fetchall()
    results = rows_to_dicts(rows)
    today = datetime.now(timezone.utc).date()
    for c in results:
        try:
            d = datetime.fromisoformat(c["due_date"]).date()
            c["days_remaining"] = (d - today).days
            c["sla_color"] = "red" if c["days_remaining"] < 7 else ("yellow" if c["days_remaining"] < 30 else "green")
        except Exception:
            c["days_remaining"] = None
            c["sla_color"] = "gray"
        if c["status"] in ("OPEN", "IN_PROGRESS") and c.get("days_remaining") is not None and c["days_remaining"] < 0:
            c["overdue"] = True
        else:
            c["overdue"] = False
    return results


class CAPCreate(BaseModel):
    control_id: str
    gap_description: str
    remediation_action: str
    assigned_owner: str
    due_date: str  # YYYY-MM-DD


@router.post("/caps")
async def create_cap(body: CAPCreate, actor: str = "user"):
    import uuid
    conn = get_conn()
    # 验证 control_id 存在
    exists = conn.execute("SELECT 1 FROM iso_controls WHERE control_id=?", (body.control_id,)).fetchone()
    if not exists:
        raise HTTPException(status_code=400, detail=f"Unknown control_id: {body.control_id}")

    cap_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO corrective_action_plans
           (cap_id, control_id, gap_description, remediation_action, assigned_owner, due_date, status)
           VALUES (?, ?, ?, ?, ?, ?, 'OPEN')""",
        (cap_id, body.control_id, body.gap_description, body.remediation_action,
         body.assigned_owner, body.due_date)
    )
    conn.commit()
    write_audit(conn, actor=actor, action="CREATE_CAP", entity_type="CAP", entity_id=cap_id,
                details={"control_id": body.control_id})
    row = conn.execute("SELECT * FROM corrective_action_plans WHERE cap_id=?", (cap_id,)).fetchone()
    return row_to_dict(row)


class CAPUpdate(BaseModel):
    status: Optional[str] = None
    remediation_action: Optional[str] = None
    assigned_owner: Optional[str] = None
    due_date: Optional[str] = None


@router.put("/caps/{cap_id}")
async def update_cap(cap_id: str, body: CAPUpdate, actor: str = "user"):
    conn = get_conn()
    row = conn.execute("SELECT * FROM corrective_action_plans WHERE cap_id=?", (cap_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="CAP not found")

    updates, params = [], []
    if body.status is not None:
        updates.append("status = ?")
        params.append(body.status)
        if body.status == "RESOLVED":
            updates.append("resolved_at = ?")
            params.append(datetime.now(timezone.utc).isoformat())
    if body.remediation_action is not None:
        updates.append("remediation_action = ?")
        params.append(body.remediation_action)
    if body.assigned_owner is not None:
        updates.append("assigned_owner = ?")
        params.append(body.assigned_owner)
    if body.due_date is not None:
        updates.append("due_date = ?")
        params.append(body.due_date)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    params.append(cap_id)
    conn.execute(f"UPDATE corrective_action_plans SET {', '.join(updates)} WHERE cap_id=?", params)
    conn.commit()
    write_audit(conn, actor=actor, action="UPDATE_CAP", entity_type="CAP", entity_id=cap_id,
                details=body.dict(exclude_none=True))

    row = conn.execute("SELECT * FROM corrective_action_plans WHERE cap_id=?", (cap_id,)).fetchone()
    return row_to_dict(row)


# ============================ Audit / Auditor Pack ============================
@router.get("/audit/soa-export")
async def audit_soa_export(format: str = Query("json", pattern="^(json|csv)$")):
    """一键导出 SoA 给审计师"""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM iso_controls ORDER BY control_id").fetchall()
    results = rows_to_dicts(rows)
    write_audit(conn, actor="dashboard_user", action="EXPORT_SOA",
                details={"format": format, "count": len(results)})
    if format == "csv":
        from fastapi.responses import StreamingResponse
        import io, csv
        output = io.StringIO()
        if results:
            w = csv.DictWriter(output, fieldnames=results[0].keys())
            w.writeheader()
            for r in results:
                w.writerow(r)
        return StreamingResponse(iter([output.getvalue()]),
                                  media_type="text/csv",
                                  headers={"Content-Disposition": "attachment; filename=soa_export.csv"})
    return {"format": "json", "controls": results, "exported_at": datetime.now(timezone.utc).isoformat()}


@router.get("/audit/evidence-summary")
async def audit_evidence_summary():
    conn = get_conn()
    rows = conn.execute("""
        SELECT control_id, COUNT(*) AS n,
               MAX(collected_at) AS latest_collected_at,
               SUBSTR(MAX(sha256_hash), 1, 16) AS sample_hash_prefix
        FROM evidence_items GROUP BY control_id ORDER BY control_id
    """).fetchall()
    return {"evidence": rows_to_dicts(rows), "generated_at": datetime.now(timezone.utc).isoformat()}


@router.get("/audit/trail")
async def audit_trail(limit: int = Query(default=50, le=500)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audit_trail ORDER BY audit_id DESC LIMIT ?", (limit,)).fetchall()
    return rows_to_dicts(rows)


# ============================ Admin: Seed / Reset ============================
@router.post("/admin/seed")
async def admin_seed(actor: str = "admin"):
    """重置 + seed 全部演示数据"""
    stats = seed_all(verbose=False)
    write_audit(get_conn(), actor=actor, action="RESET_AND_SEED", details=stats)
    return {"status": "ok", "seeded": stats}


@router.post("/admin/reset")
async def admin_reset(actor: str = "admin"):
    """清空全部数据（谨慎）"""
    conn = get_conn()
    conn.execute("DELETE FROM audit_trail")
    conn.execute("DELETE FROM corrective_action_plans")
    conn.execute("DELETE FROM evidence_items")
    conn.execute("DELETE FROM iso_controls")
    conn.commit()
    write_audit(conn, actor=actor, action="RESET_ALL")
    return {"status": "reset"}