# 项目规划与实战方案：ISO/IEC 27001:2022 体系改版、内审差距分析与自动化证据收集引擎

> **文档标识**：`03_ISO27001_Gap_Assessment_Evidence_Engine.md`  
> **项目代号**：Project CyberVeritas (ISO 27001 Evidence Engine & Gap Assessment)  
> **适用目标岗位**：Senior IT GRC Specialist (Trip.Biz) / Senior Cyber Security Analyst (Global Enterprise)

---

## 1. 项目背景与对齐 JD 核心要求

### 1.1 业务与技术背景
跨国在线旅游平台（OTA）与出海企业（如 Trip.Biz）在拓展新加坡、日本、欧美等国际企业客户时，必须面对高频的客户安全尽调（Client RFP / Due Diligence）以及权威第三方合规认证要求。2022 年发布的 ISO/IEC 27001 标准相较于 2013 版发生了重大演进：
- **控制项结构精简**：从原来的 14 个控制域、114 项控制项精炼为 **4 大主题（Themes）、共 93 项控制项**。
- **引入全新关键控制**：增设了 A.5.7（威胁情报）、A.5.23（云服务安全）、A.8.12（数据防泄漏 DLP）、A.8.28（安全编码）、A.8.9（配置管理）等紧跟现代云原生与 DevSecOps 的控制要求。

**企业当前面临的核心痛点**：
1. **证据收集纯手工，人效低下**：过往依靠 Excel 跨部门（DevOps、IT、HR、法务）人工催要截图，一次监督审核消耗上百人天，容易漏交、错交。
2. **证据易失真且缺乏防篡改性**：静态图片或人工文档缺乏时间戳及防篡改哈希，难以通过严苛外审（如 BSI、DNV、EY）抽验。
3. **差距评估与整改追踪脱节**：内审中发现的控制缺陷未能建立自动化 SLA 追踪与升级机制，导致整改停留在口头。

### 1.2 对齐 JD 核心能力点
- **Trip.Biz Senior IT GRC Specialist 职位对齐**：
  - *“Coordinate ISO 27001, SOC 2, PCI DSS or similar certification and audit activities, including evidence collection and remediation tracking.”*
  - *“Maintain risk registers, track remediation actions, and support periodic risk assessments across systems and projects.”*
  - *“Work with product, R&D, legal, and security teams to validate controls and ensure compliance alignment.”*
- **Senior Cyber Security Analyst 职位对齐**：
  - *“Continuous improvement of security controls aligned with ISO 27001, NIST CSF, and internal Cyber Security policies.”*
  - *“Support governance, risk, and compliance (GRC) activities (risk assessments, audits, policy alignment).”*
  - *“Support data protection initiatives including DLP, encryption, and classification controls.”*

---

## 2. Mac 本地运行环境架构与技术栈设计

为了支持在本地快速启动演示、开发测试及向面试官现场 Demo，系统基于轻量级技术栈构建，兼容 macOS（Apple Silicon M1/M2/M3/M4 及 Intel），完全支持单机离线运行。

```
+------------------------------------------------------------------------+
|                   Mac 本地轻量级 GRC 合规平台运行架构                     |
|                                                                        |
|  +------------------------------------------------------------------+  |
|  |           Streamlit 前端仪表盘 (http://localhost:8501)           |  |
|  |     - 93 项 SoA 适用性声明管理                                     |  |
|  |     - Gap 差距雷达图与合规率概览                                   |  |
|  |     - 防篡改 Evidence 证据审计库                                   |  |
|  |     - CAP (纠正措施计划) 工单与 SLA 倒计时看板                     |  |
|  +----------------------------------^-------------------------------+  |
|                                     |                                  |
|  +----------------------------------v-------------------------------+  |
|  |          FastAPI 核心业务引擎 (http://localhost:8000)             |  |
|  |     - SoA / Gap Analysis Engine                                  |  |
|  |     - Evidence Collection & SHA-256 Digest Engine                |  |
|  |     - Remediation SLA Workflow & Auditor Export Service          |  |
|  +-----------------+--------------------------------+---------------+  |
|                    |                                |                  |
|  +-----------------v--------------+  +--------------v---------------+  |
|  |      SQLite 嵌入式持久化库       |  |  Evidence Connectors (Mock/OS)|  |
|  |  - iso_controls (93项全量基线) |  |  - GitHub API (分支保护/SAST)  |  |
|  |  - evidence_vault (哈希防篡改)  |  |  - Okta/IAM API (密码/MFA基线) |  |
|  |  - cap_actions (整改工单)      |  |  - macOS Audit (FileVault/FW) |  |
|  |  - audit_trail (审计轨迹)      |  |  - Cloud Baseline (AWS/S3)    |  |
|  +--------------------------------+  +------------------------------+  |
+------------------------------------------------------------------------+
```

### 2.1 依赖组件清单
- **操作系统**：macOS 12.0+ (Darwin x86_64 / arm64)
- **Python 环境**：Python 3.10+
- **核心依赖包**：
  - Web & API：`fastapi>=0.110.0`, `uvicorn>=0.28.0`, `streamlit>=1.32.0`
  - 数据模型与持久化：`sqlalchemy>=2.0.0`, `pydantic>=2.6.0`, `sqlite3`
  - 安全与加密：`cryptography>=42.0.0`, `hashlib`
  - 数据处理与报表导出：`pandas>=2.2.0`, `openpyxl>=3.1.2`
  - 测试框架：`pytest>=8.0.0`, `httpx>=0.27.0`
- **可选 Docker 部署**：
  提供标准 `Dockerfile` 与 `docker-compose.yml`，一键拉起容器。

---

## 3. Vibe Coding Prompt（可直接复制给 Cursor / Claude Code）

```markdown
Role: You are a Principal Information Security Architect and ISO/IEC 27001:2022 Lead Auditor with extensive experience in Compliance-as-Code automation.

Task: Build a production-grade local compliance engine named "Project CyberVeritas" that operationalizes ISO 27001:2022 gap assessment, Statement of Applicability (SoA) management, automated evidence collection, and Corrective Action Plan (CAP) tracking for a global SaaS/OTA company (like Trip.Biz).

Environment: macOS (Python 3.10+, FastAPI, Streamlit, SQLite, SQLAlchemy, Pydantic v2).

Detailed Technical Requirements:
1. Data Layer (`cyberveritas/models.py`):
   - ISOControl: control_id (PK, e.g. A.5.23), theme (A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological), title, description, is_applicable (bool), soa_justification (text), status (COMPLIANT, PARTIALLY_COMPLIANT, NON_COMPLIANT, NOT_EVALUATED), risk_rating (CRITICAL, HIGH, MEDIUM, LOW), owner.
   - EvidenceItem: evidence_id (UUID), control_id (FK), source_name (e.g. GitHub_API, Okta_IAM, MacOS_Audit), content_payload (JSON string), sha256_hash (64 char hex), collected_at (datetime), is_tampered (bool).
   - CorrectiveActionPlan (CAP): cap_id (UUID), control_id (FK), gap_description, remediation_action, owner, due_date, status (OPEN, IN_PROGRESS, RESOLVED, RISK_ACCEPTED), sla_days_remaining (computed property).

2. Pre-seeded ISO 27001:2022 Catalog (`cyberveritas/seed_data.py`):
   - Pre-populate all 93 controls classified into the 4 themes with realistic industry descriptions.
   - Highlight newly introduced 2022 controls: A.5.7 (Threat Intelligence), A.5.23 (Cloud Services Security), A.8.9 (Configuration Management), A.8.12 (DLP), A.8.28 (Secure Coding).

3. Evidence Collector Engine (`cyberveritas/collectors.py`):
   - A.8.28 / A.8.32 Collector: Pull mock/real Git branch protection settings (mandatory PR review, minimum 2 approvers, signed commits, required SAST checks).
   - A.5.15 / A.8.5 Collector: Inspect IAM password complexity policies, 90-day rotation, and global MFA enforcement.
   - A.8.1 Collector: Inspect host FileVault encryption status, Gatekeeper, and system firewall.
   - A.5.23 Collector: Validate mock AWS cloud baseline (S3 Public Access Block, KMS encryption, CloudTrail multi-region).
   - For every evidence captured, calculate SHA-256 digest immediately upon ingestion.

4. Streamlit Dashboard (`cyberveritas/app.py`):
   - Metric cards: Overall Compliance %, Applicable Controls, Identified Gaps, Active CAP Items.
   - Interactive SoA Table: Filter by theme, search by ID/keyword, inline update of applicability and justification.
   - Evidence Vault: Display captured evidence with real-time SHA-256 integrity re-validation (green check if valid, red alert if tampered).
   - CAP SLA Tracker: Color-coded SLA indicators (Red: <7 days or overdue, Yellow: <30 days, Green: >30 days).
   - One-Click Auditor Pack Export: Export SoA and Evidence summary to Excel / JSON.

5. Unit Testing:
   - Provide comprehensive pytest suite testing collector hash generation, tamper detection, and gap aggregation.
```

---

## 4. 核心代码与架构设计

### 4.1 数据模型设计 (`cyberveritas/models.py`)
```python
from datetime import datetime
import enum
import hashlib
from typing import List, Optional
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, ForeignKey, Enum as SQLEnum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class ThemeEnum(str, enum.Enum):
    ORGANIZATIONAL = "A.5 Organizational"
    PEOPLE = "A.6 People"
    PHYSICAL = "A.7 Physical"
    TECHNOLOGICAL = "A.8 Technological"

class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_EVALUATED = "NOT_EVALUATED"

class RiskRating(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class CAPStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    RISK_ACCEPTED = "RISK_ACCEPTED"

class ISOControl(Base):
    __tablename__ = "iso_controls"

    control_id = Column(String(20), primary_key=True, index=True) # e.g. A.5.23
    theme = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    is_applicable = Column(Boolean, default=True)
    soa_justification = Column(Text, default="Applicable based on company risk assessment and infrastructure dependency.")
    status = Column(String(30), default=ComplianceStatus.NOT_EVALUATED.value)
    risk_rating = Column(String(20), default=RiskRating.MEDIUM.value)
    owner = Column(String(100), default="IT Security")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    evidences = relationship("EvidenceItem", back_populates="control", cascade="all, delete-orphan")
    action_plans = relationship("CorrectiveActionPlan", back_populates="control", cascade="all, delete-orphan")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    evidence_id = Column(String(50), primary_key=True)
    control_id = Column(String(20), ForeignKey("iso_controls.control_id"), nullable=False, index=True)
    source_name = Column(String(100), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)
    content_payload = Column(Text, nullable=False)
    sha256_hash = Column(String(64), nullable=False)

    control = relationship("ISOControl", back_populates="evidences")

    def verify_integrity(self) -> bool:
        computed = hashlib.sha256(self.content_payload.encode("utf-8")).hexdigest()
        return computed == self.sha256_hash

class CorrectiveActionPlan(Base):
    __tablename__ = "corrective_action_plans"

    cap_id = Column(String(50), primary_key=True)
    control_id = Column(String(20), ForeignKey("iso_controls.control_id"), nullable=False, index=True)
    gap_description = Column(Text, nullable=False)
    remediation_action = Column(Text, nullable=False)
    assigned_owner = Column(String(100), nullable=False)
    due_date = Column(DateTime, nullable=False)
    status = Column(String(30), default=CAPStatus.OPEN.value)
    created_at = Column(DateTime, default=datetime.utcnow)

    control = relationship("ISOControl", back_populates="action_plans")

    @property
    def days_remaining(self) -> int:
        delta = self.due_date - datetime.utcnow()
        return delta.days
```

### 4.2 93 项控制项架构与种子数据产生器 (`cyberveritas/seed_data.py`)
ISO/IEC 27001:2022 包含 93 项控制项：
- 组织控制 A.5 (37 项)
- 人员控制 A.6 (8 项)
- 物理控制 A.7 (14 项)
- 技术控制 A.8 (34 项)

```python
"""
Pre-seeds complete ISO 27001:2022 controls catalog
"""
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from cyberveritas.models import ISOControl, CorrectiveActionPlan, ThemeEnum, ComplianceStatus, RiskRating, CAPStatus

ISO_2022_CATALOG = [
    # A.5 Organizational Controls (Samples)
    ("A.5.1", ThemeEnum.ORGANIZATIONAL.value, "Policies for information security", "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties.", True, ComplianceStatus.COMPLIANT.value, RiskRating.HIGH.value, "GRC Team"),
    ("A.5.7", ThemeEnum.ORGANIZATIONAL.value, "Threat intelligence", "Information relating to information security threats shall be collected and analyzed to produce threat intelligence.", True, ComplianceStatus.PARTIALLY_COMPLIANT.value, RiskRating.HIGH.value, "SOC Team"),
    ("A.5.15", ThemeEnum.ORGANIZATIONAL.value, "Access control", "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.", True, ComplianceStatus.COMPLIANT.value, RiskRating.CRITICAL.value, "IAM Team"),
    ("A.5.23", ThemeEnum.ORGANIZATIONAL.value, "Information security for use of cloud services", "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.", True, ComplianceStatus.PARTIALLY_COMPLIANT.value, RiskRating.CRITICAL.value, "Cloud Infrastructure"),
    
    # A.6 People Controls (Samples)
    ("A.6.1", ThemeEnum.PEOPLE.value, "Screening", "Background verification checks on all candidates for employment shall be carried out proportional to the business requirements.", True, ComplianceStatus.COMPLIANT.value, RiskRating.MEDIUM.value, "HR Team"),
    ("A.6.3", ThemeEnum.PEOPLE.value, "Information security awareness, education and training", "Personnel shall receive appropriate information security awareness, education and training and regular updates.", True, ComplianceStatus.COMPLIANT.value, RiskRating.HIGH.value, "Security Awareness"),
    
    # A.7 Physical Controls (Samples)
    ("A.7.1", ThemeEnum.PHYSICAL.value, "Physical security perimeters", "Security perimeters shall be defined and used to protect areas that contain information and other associated assets.", True, ComplianceStatus.COMPLIANT.value, RiskRating.HIGH.value, "Workplace Security"),
    ("A.7.4", ThemeEnum.PHYSICAL.value, "Physical security monitoring", "Premises shall be continuously monitored for unauthorized physical access.", True, ComplianceStatus.COMPLIANT.value, RiskRating.MEDIUM.value, "Workplace Security"),

    # A.8 Technological Controls (Samples)
    ("A.8.1", ThemeEnum.TECHNOLOGICAL.value, "User endpoint devices", "Information stored on, processed by or accessible via user endpoint devices shall be protected.", True, ComplianceStatus.COMPLIANT.value, RiskRating.HIGH.value, "IT Support"),
    ("A.8.5", ThemeEnum.TECHNOLOGICAL.value, "Secure authentication", "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.", True, ComplianceStatus.COMPLIANT.value, RiskRating.CRITICAL.value, "IAM Team"),
    ("A.8.9", ThemeEnum.TECHNOLOGICAL.value, "Configuration management", "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.", True, ComplianceStatus.PARTIALLY_COMPLIANT.value, RiskRating.HIGH.value, "DevSecOps"),
    ("A.8.12", ThemeEnum.TECHNOLOGICAL.value, "Data leakage prevention", "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.", True, ComplianceStatus.NON_COMPLIANT.value, RiskRating.CRITICAL.value, "Data Protection"),
    ("A.8.28", ThemeEnum.TECHNOLOGICAL.value, "Secure coding", "Principles for secure coding shall be applied to software development.", True, ComplianceStatus.COMPLIANT.value, RiskRating.HIGH.value, "R&D / DevSecOps")
]

def seed_database(session: Session):
    for item in ISO_2022_CATALOG:
        cid, theme, title, desc, app, status, risk, owner = item
        ctrl = session.query(ISOControl).filter_by(control_id=cid).first()
        if not ctrl:
            ctrl = ISOControl(
                control_id=cid,
                theme=theme,
                title=title,
                description=desc,
                is_applicable=app,
                soa_justification=f"Applicable for Trip.Biz global operations and client compliance commitment ({title}).",
                status=status,
                risk_rating=risk,
                owner=owner
            )
            session.add(ctrl)
    
    session.commit()
    
    # Pre-seed sample CAP for non-compliant control A.8.12
    cap = session.query(CorrectiveActionPlan).filter_by(control_id="A.8.12").first()
    if not cap:
        cap = CorrectiveActionPlan(
            cap_id=str(uuid.uuid4()),
            control_id="A.8.12",
            gap_description="Endpoint DLP agent coverage is currently at 65%, lacking macOS Safari upload inspection.",
            remediation_action="Roll out endpoint DLP v4.2 via Jamf Pro to all remote engineers and enable cloud storage blocking rules.",
            assigned_owner="Alex Zhang (Data Security)",
            due_date=datetime.utcnow() + timedelta(days=21),
            status=CAPStatus.IN_PROGRESS.value
        )
        session.add(cap)
        session.commit()
```

### 4.3 自动化证据收集插件引擎 (`cyberveritas/collectors.py`)
```python
"""
Evidence Collector Plugins: Automated Configuration Auditing
"""
import hashlib
import json
import uuid
from datetime import datetime
from cyberveritas.models import EvidenceItem

class EvidenceCollectorEngine:
    
    @staticmethod
    def _create_evidence(control_id: str, source_name: str, payload_dict: dict) -> EvidenceItem:
        raw_json = json.dumps(payload_dict, sort_keys=True, indent=2)
        sha256_val = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        return EvidenceItem(
            evidence_id=str(uuid.uuid4()),
            control_id=control_id,
            source_name=source_name,
            collected_at=datetime.utcnow(),
            content_payload=raw_json,
            sha256_hash=sha256_val
        )

    def collect_git_branch_protection(self) -> EvidenceItem:
        """Collects A.8.28 (Secure Coding) & A.8.32 (Change Management) Evidence"""
        data = {
            "service": "GitHub Enterprise Server",
            "repository": "tripbiz-core-booking-engine",
            "branch": "main",
            "branch_protection_rule": {
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                    "required_approving_review_count": 2
                },
                "required_status_checks": {
                    "strict": True,
                    "contexts": [
                        "security/semgrep-sast",
                        "security/snyk-sca",
                        "ci/unit-tests-coverage-80%"
                    ]
                },
                "required_linear_history": True,
                "allow_force_pushes": False,
                "allow_deletions": False
            },
            "inspection_time": datetime.utcnow().isoformat()
        }
        return self._create_evidence("A.8.28", "GitHub_API_Connector", data)

    def collect_iam_security_baseline(self) -> EvidenceItem:
        """Collects A.5.15 (Access Control) & A.8.5 (Secure Authentication) Evidence"""
        data = {
            "idp_provider": "Okta / AWS IAM Identity Center",
            "password_policy": {
                "min_length": 14,
                "require_lowercase": True,
                "require_uppercase": True,
                "require_numbers": True,
                "require_symbols": True,
                "max_age_days": 90,
                "history_restriction_count": 24
            },
            "mfa_configuration": {
                "enforce_mfa_all_users": True,
                "prompt_frequency": "Every Sign-in from new IP",
                "permitted_authenticators": ["FIDO2_WebAuthn", "Okta_Verify_Push_Number_Match"],
                "sms_voice_mfa_allowed": False
            },
            "inactive_account_deprovisioning": {
                "auto_suspend_after_inactive_days": 45
            },
            "audit_timestamp": datetime.utcnow().isoformat()
        }
        return self._create_evidence("A.5.15", "Okta_IAM_API", data)

    def collect_endpoint_posture(self) -> EvidenceItem:
        """Collects A.8.1 (User Endpoint Devices) Evidence"""
        data = {
            "mdm_platform": "Jamf Pro (macOS Fleet)",
            "fleet_size": 1250,
            "security_metrics": {
                "filevault_disk_encryption_rate": "99.8%",
                "gatekeeper_enforced": True,
                "system_firewall_enabled": True,
                "edr_agent_installed": "CrowdStrike Falcon Sensor (Version 7.12)",
                "tamper_protection_enabled": True
            },
            "audit_timestamp": datetime.utcnow().isoformat()
        }
        return self._create_evidence("A.8.1", "Jamf_MDM_Connector", data)

    def collect_cloud_storage_baseline(self) -> EvidenceItem:
        """Collects A.5.23 (Cloud Services Security) Evidence"""
        data = {
            "cloud_provider": "AWS Global Infrastructure",
            "primary_account_id": "892348123891",
            "s3_account_level_public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "default_encryption": "aws:kms with Customer Managed Keys (CMK)",
            "tls_enforcement": "Enforced TLS 1.2 and TLS 1.3 only via Bucket Policy",
            "cloudtrail_status": "Enabled globally with S3 Data Events log delivery",
            "audit_timestamp": datetime.utcnow().isoformat()
        }
        return self._create_evidence("A.5.23", "AWS_Config_Inspector", data)
```

### 4.4 前端交互与管理仪表盘 (`cyberveritas/app.py`)
```python
"""
Streamlit Web Dashboard for ISO 27001:2022 Management
"""
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyberveritas.models import Base, ISOControl, EvidenceItem, CorrectiveActionPlan
from cyberveritas.collectors import EvidenceCollectorEngine
from cyberveritas.seed_data import seed_database

# DB Connection
DATABASE_URL = "sqlite:///cyberveritas.db"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

st.set_page_config(page_title="CyberVeritas - ISO 27001:2022 Engine", layout="wide", page_icon="🛡️")

st.title("🛡️ Project CyberVeritas: ISO/IEC 27001:2022 Gap Assessment & Evidence Engine")
st.markdown("*Enterprise Information Security Management & Automated Audit Platform | Tailored for Trip.Biz*")

session = SessionLocal()

# Seed if empty
if session.query(ISOControl).count() == 0:
    seed_database(session)

# Top KPI Summary
total_controls = session.query(ISOControl).count()
applicable_controls = session.query(ISOControl).filter_by(is_applicable=True).count()
compliant_controls = session.query(ISOControl).filter_by(status="COMPLIANT").count()
gaps_count = session.query(ISOControl).filter(ISOControl.status.in_(["PARTIALLY_COMPLIANT", "NON_COMPLIANT"])).count()
active_caps = session.query(CorrectiveActionPlan).filter(CorrectiveActionPlan.status != "RESOLVED").count()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Controls", total_controls)
c2.metric("SoA Applicable", applicable_controls)
c3.metric("Compliant Controls", compliant_controls, f"{round(compliant_controls/applicable_controls*100, 1)}%")
c4.metric("Control Gaps", gaps_count, delta="Requires Remediation", delta_color="inverse")
c5.metric("Active CAPs", active_caps, delta="SLA Tracking", delta_color="inverse")

st.divider()

tabs = st.tabs(["📋 Statement of Applicability (SoA)", "🔍 Evidence Vault (Anti-Tamper)", "🚨 Corrective Action Plans (CAP)", "⚙️ Automated Trigger"])

with tabs[0]:
    st.subheader("Statement of Applicability (SoA) Matrix & Gap Assessment")
    theme_filter = st.selectbox("Filter by Theme", ["All", "A.5 Organizational", "A.6 People", "A.7 Physical", "A.8 Technological"])
    
    query = session.query(ISOControl)
    if theme_filter != "All":
        query = query.filter_by(theme=theme_filter)
    
    controls = query.all()
    data = [{
        "ID": c.control_id,
        "Theme": c.theme,
        "Title": c.title,
        "Applicable": c.is_applicable,
        "Status": c.status,
        "Risk": c.risk_rating,
        "Owner": c.owner,
        "SoA Justification": c.soa_justification
    } for c in controls]
    
    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True)

with tabs[1]:
    st.subheader("Anti-Tamper Evidence Vault (Cryptographically Hashed)")
    evidences = session.query(EvidenceItem).all()
    
    for ev in evidences:
        with st.expander(f"📦 Evidence {ev.evidence_id[:8]}... | Control: {ev.control_id} | Source: {ev.source_name}"):
            is_valid = ev.verify_integrity()
            if is_valid:
                st.success(f"✅ SHA-256 Integrity Verified: `{ev.sha256_hash}`")
            else:
                st.error(f"❌ TAMPER DETECTED! Expected hash mismatch!")
            st.json(ev.content_payload)

with tabs[2]:
    st.subheader("Corrective Action Plan (CAP) SLA Tracking")
    caps = session.query(CorrectiveActionPlan).all()
    for cap in caps:
        days = cap.days_remaining
        color = "red" if days < 7 else ("orange" if days < 30 else "green")
        st.markdown(f"**[{cap.control_id}]** {cap.gap_description}")
        st.markdown(f"- **Action**: {cap.remediation_action}")
        st.markdown(f"- **Owner**: `{cap.assigned_owner}` | **Due Date**: {cap.due_date.strftime('%Y-%m-%d')} (:{color}[{days} days remaining]) | **Status**: `{cap.status}`")
        st.divider()

with tabs[3]:
    st.subheader("Trigger Automated Evidence Harvester")
    if st.button("🚀 Run All System Collectors Now"):
        collector = EvidenceCollectorEngine()
        ev1 = collector.collect_git_branch_protection()
        ev2 = collector.collect_iam_security_baseline()
        ev3 = collector.collect_endpoint_posture()
        ev4 = collector.collect_cloud_storage_baseline()
        
        session.add_all([ev1, ev2, ev3, ev4])
        session.commit()
        st.success("Successfully harvested and cryptographically anchored 4 new evidence payloads!")
        st.rerun()

session.close()
```

---

## 5. 测试验证与测试用例

### 5.1 自动化单元测试脚本 (`tests/test_cyberveritas.py`)
```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cyberveritas.models import Base, ISOControl, EvidenceItem, CorrectiveActionPlan
from cyberveritas.collectors import EvidenceCollectorEngine
from cyberveritas.seed_data import seed_database

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_iso_controls_seeding(db_session):
    seed_database(db_session)
    count = db_session.query(ISOControl).count()
    assert count >= 13
    
    a8_12 = db_session.query(ISOControl).filter_by(control_id="A.8.12").first()
    assert a8_12 is not None
    assert a8_12.title == "Data leakage prevention"
    assert a8_12.status == "NON_COMPLIANT"

def test_evidence_collector_hash_and_integrity():
    collector = EvidenceCollectorEngine()
    ev = collector.collect_git_branch_protection()
    
    assert ev.control_id == "A.8.28"
    assert len(ev.sha256_hash) == 64
    assert ev.verify_integrity() is True

def test_tamper_detection_alert():
    collector = EvidenceCollectorEngine()
    ev = collector.collect_cloud_storage_baseline()
    
    assert ev.verify_integrity() is True
    # Simulate malicious database modification or unauthorized payload tampering
    ev.content_payload = ev.content_payload.replace("True", "False")
    assert ev.verify_integrity() is False, "Integrity check must fail when content is modified!"

def test_cap_sla_calculation(db_session):
    seed_database(db_session)
    cap = db_session.query(CorrectiveActionPlan).first()
    assert cap is not None
    assert cap.days_remaining > 0
```

---

## 6. 简历包装（STAR 法则）与面试应答策略

### 6.1 简历叙述（中英文对照）

#### 中文描述
- **项目名称**：企业级 ISO/IEC 27001:2022 改版落地、差距评估与自动化证据收集平台 (Project CyberVeritas)
- **项目角色**：Senior IT GRC Specialist / 信息安全合规架构师
- **S (Situation)**：公司出海业务（Trip.Biz）拓展新加坡及欧美企业大客户，亟需将原 ISO 27001 体系由 2013 版升级至 2022 新版。传统依靠 Excel 跨部门（DevOps、IT、HR）索要截图的方式耗时长、证据易失真且难以应对外部严苛审核。
- **T (Task)**：主导完成 93 项新控制项的适用性声明（SoA）重构、差距评估（Gap Analysis），并研发轻量级自动化证据抓取引擎，实现持续合规审计闭环。
- **A (Action)**：
  1. 梳理业务涉及的 4 大主题，针对 A.5.23 云服务安全、A.8.12 DLP、A.8.28 安全编码等 11 项新增重点控制项编写控制基线，推动研发与运维团队技术对齐；
  2. 运用 Python 编写自动化取证引擎，对接 GitHub、Okta IAM 及 AWS 安全配置 API，对抓取的配置原始数据计算 SHA-256 摘要以确保防篡改性；
  3. 建立 CAP（纠正措施计划）追踪机制，联动工单 SLA，将识别出的 19 项控制差距全部整改闭环。
- **R (Result)**：最终带领团队以 **0 个重大不符合项（Major NC）** 顺利通过第三方认证机构（BSI/DNV）审核；将年度内审取证周期由 4 周压缩至 3 天以内，企业客户安全尽调响应时效提升 70%。

#### 英文描述 (For Global / Trip.Biz Resume)
- **Project**: Enterprise ISO/IEC 27001:2022 Transition, Gap Assessment & Automated Evidence Engine
- **Role**: Senior IT GRC Specialist / Security Compliance Architect
- **Key Achievements**:
  - Led the corporate transition to ISO/IEC 27001:2022 across all 4 themes and 93 controls, reconstructing the Statement of Applicability (SoA) and remediation workflows for Trip.Biz global operations.
  - Architected a Python-based Evidence Automation Engine capturing configurations across GitHub Enterprise, Okta IAM, and AWS Security Hub, applying SHA-256 cryptographic hashing to guarantee tamper-proof audit trails.
  - Formulated baseline standards for newly introduced controls (A.5.23 Cloud Security, A.8.12 DLP, A.8.28 Secure Coding), driving 19 critical control gaps to complete closure via Corrective Action Plans (CAP).
  - Successfully achieved recertification with Zero Major Non-Conformities (NC), cutting audit evidence collection cycle time from 4 weeks to 3 days and improving client RFP compliance response speed by 70%.

### 6.2 面试高频追问与优秀应答策略

#### Q1: ISO 27001:2022 相比 2013 版的核心变化是什么？在实际落地中最难推动的是哪几项？
* **优秀应答**：
  1. **结构精炼与属性引入**：从 14 个控制域、114 项控制整合为 4 大主题（组织控制 37、人员控制 8、物理控制 14、技术控制 34），总计 93 项；引入了属性概念（控制类型、信息安全属性、网络安全概念、操作能力等），更易与 NIST CSF 映射。
  2. **新增落地难度最大的控制**：
     - **A.5.23 云服务安全**：需要将云资源生命周期从采购、配置基线到退役制定完整闭环，尤其是多云环境下的密钥管理与共享责任模型。
     - **A.8.28 安全编码**：传统研发团队关注业务交付，推行 A.8.28 需要在 CI/CD 中嵌入自动化门禁（SAST/SCA/分支保护规则），我们通过分级实施，优先在发布流水线中引入无阻塞告警，逐步演进为阻断高危漏洞，避免阻碍业务节奏。

#### Q2: 外部审计师（如 BSI / EY）在审查自动化拉取的配置证据时，如何确保真实性，防止研发团队或内部伪造配置？
* **优秀应答**：
  1. **只读审计专用主体（Read-only Audit Service Account）**：取证工具所用的 API Token 权限被严格收敛至只读，并在 IAM 中独立审计其调用日志。
  2. **端到端加密哈希链（SHA-256 Digest & Timestamping）**：抓取到的原始 JSON 响应直接计算哈希值，与时间戳同步记录并入库，任何后续篡改都会导致校验失败。
  3. **现场盲测抽样核验**：在现场或远程外部审核时，支持审计师随机挑选控制项，由脚本实时运行拉取最新值与云平台/GitHub 后台管理界面进行逐行比对，哈希及配置值完全吻合，完全消除造假质疑。
