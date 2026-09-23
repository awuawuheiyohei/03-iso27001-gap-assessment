# ISO 27001:2022 Gap Assessment Evidence Engine

> **一句话**：FastAPI + 93 控制项映射 + 自动化证据收集（SHA-256 防篡改）+ CAP 整改追踪
> 对齐 **Senior IT GRC Specialist** / **Senior Cyber Security Analyst** 岗位核心能力。

---

## ✨ 状态

**v1.0 端到端已上线**（2026-09-23）— FastAPI + SQLite + Vanilla JS Dashboard + 18/18 单测通过。

---

## 🎯 解决什么问题

**典型场景**：Trip.Biz / 出海 SaaS 公司面对新加坡、日本、欧美客户 RFP 安全尽调 + BSI/DNV/EY 第三方审计。

**痛点**：
1. **证据收集纯手工**：Excel 跨部门催截图，1 次监督审核消耗上百人天
2. **证据易失真**：静态图片/人工文档无时间戳 + 防篡改哈希，外审抽验难
3. **差距评估与整改脱节**：口头整改无 SLA 追踪

**本项目交付**：
- ✅ 93 项 ISO 27001:2022 控制项（4 主题 / 10 大类）— SoA Matrix
- ✅ 6 类自动 Connector：GitHub Branch Protection / IAM Baseline / Endpoint Posture / AWS Cloud / Threat Intel / DLP
- ✅ **SHA-256 防篡改证据库**：每条 evidence 立即 hash，verify_ud 可独立验证
- ✅ CAP 工单 + SLA 倒计时（🔴 <7d / 🟡 <30d / 🟢 >30d）
- ✅ 一键审计师导出包（SoA JSON + CSV + Evidence Summary + Audit Trail）

---

## 📁 项目结构

```
03-iso27001-gap-assessment/
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py            # 兼容层（init_db/call_llm/strip_thinking）
│   ├── main.py                # FastAPI 入口（端口 5030）
│   ├── schema.sql             # SQLite schema（4 张表）
│   ├── models/
│   │   ├── __init__.py
│   │   ├── db.py              # SQLite 连接 + audit_trail
│   │   ├── iso_controls_catalog.py  # 93 项控制项目录
│   │   └── seed.py            # seed 93 控制项 + 3 个示范 CAP
│   ├── collectors/
│   │   ├── __init__.py
│   │   └── engine.py          # 6 个 collector + verify_evidence_integrity
│   └── api/
│       ├── __init__.py
│       └── routes.py          # 全部 REST 端点
├── static/
│   └── index.html             # Dashboard UI（4 tab）
├── tests/
│   ├── conftest.py
│   └── test_iso27001.py       # 18 个测试
├── data/                      # SQLite DB 运行时生成
└── docs/
    └── PRD.md                 # 完整需求文档
```

---

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/03-iso27001-gap-assessment

# 系统 Python 3.11+ （已装 fastapi/uvicorn）
python3 main.py serve
# → http://localhost:5030  (Dashboard)
# → http://localhost:5030/docs  (Swagger API)
# → http://localhost:5030/api/stats  (JSON stats)
```

**首次启动**会自动建库 + seed 93 控制项 + 3 个示范 CAP。

---

## 📊 Dashboard 4 个 Tab

| Tab | 内容 |
|---|---|
| 📋 **SoA Matrix** | 93 项控制项表格（按 theme/status/关键字/2022 新增过滤） |
| 🔍 **Evidence Vault** | 8 条 SHA-256 防篡改证据；每个可验证 + 篡改检测 |
| 🚨 **CAP SLA** | 3 个整改工单 + SLA 颜色（🔴 / 🟡 / 🟢）+ 新建 CAP |
| ⚙️ **Collectors** | 6 个 connector 手动/批量运行 |
| 📤 **Auditor Pack** | 一键导出 SoA JSON/CSV + Evidence Summary + Audit Trail |

---

## 🔬 6 类 Connector（演示）

| Connector | 关联控制项 | 模拟数据来源 |
|---|---|---|
| `git_branch_protection` | A.8.28 + A.8.32 | GitHub Enterprise API（PR review / SAST / 签名） |
| `iam_baseline` | A.5.15 + A.8.5 | Okta + AWS IAM（密码 14 位 / MFA 强制 / 季度 UAR） |
| `endpoint_posture` | A.8.1 | Jamf Pro MDM（FileVault 99.8% / EDR / 防火墙） |
| `cloud_storage_baseline` | A.5.23 | AWS Config（S3 公开访问阻止 / KMS / CloudTrail） |
| `threat_intelligence` | A.5.7 | MISP + Recorded Future IOC feed |
| `dlp_status` | A.8.12 | Microsoft Purview DLP（端点覆盖率 + 策略） |

---

## 🛡️ 防篡改证据库设计

**每条 evidence 都有 SHA-256 摘要**：
- 入库时立即计算 `sha256(json)` 
- 任何后续修改都会让 `verify_integrity()` 失败
- 审计师可独立重算验证（无需信任数据库）

**Demo**：在 Dashboard "Evidence Vault" 标签 → 篡改任一 payload → "手动验证"按钮返回 `HASH_MISMATCH` 红色告警。

---

## 🧪 测试

```bash
python3 -m pytest tests/ -v
# 18 passed in 0.19s
```

**覆盖范围**：
- ✅ 93 项总数 + 4 主题分布（37/8/14/34）
- ✅ 2022 新增控制项标记（A.5.7 / A.5.23 / A.8.9 / A.8.12 / A.8.28 等 10 项）
- ✅ SHA-256 格式（64 字符 hex）+ 篡改检测
- ✅ 6 个 collector 全部跑通
- ✅ CAPs 按 due_date 排序
- ✅ Stats 与直接 DB 查询一致
- ✅ 端到端 smoke：seed → collectors → 篡改 → 验证失败 → audit trail

---

## 🌐 REST API 摘要

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET | `/api/stats` | KPI 概览 |
| GET | `/api/controls` | 列出 93 控制项（按 theme/status/keyword 过滤） |
| GET | `/api/controls/{id}` | 单条控制项 + 关联 evidence + CAP |
| PUT | `/api/controls/{id}` | 更新状态/风险/责任人 |
| GET | `/api/evidence` | 列出 evidence（含 integrity_valid） |
| POST | `/api/evidence/{id}/verify` | 触发完整性验证 |
| POST | `/api/collectors/run-all` | 一键采集全部 6 个 connector |
| POST | `/api/collectors/{name}` | 跑单个 connector |
| GET | `/api/caps` | 列出 CAP（含 SLA 颜色 + 倒计时） |
| POST | `/api/caps` | 新建 CAP |
| PUT | `/api/caps/{id}` | 更新 CAP 状态/到期日 |
| GET | `/api/audit/soa-export?format=csv` | SoA 导出 CSV |
| GET | `/api/audit/evidence-summary` | Evidence 汇总 |
| GET | `/api/audit/trail` | 审计 trail（最近 50 条） |

完整 Swagger：`http://localhost:5030/docs`

---

## 🎤 面试讲法

**故事 1 · 为什么用 FastAPI + SQLite 而不是 PostgreSQL？**
> "演示场景 vs 生产场景的取舍：
> - 演示：clone → pip install → uvicorn → 5 分钟看到效果
> - 生产：会切到 PostgreSQL，加 SOAR / SIEM 实时管道
> 
> 架构洁癖 > 过度工程。每个 repo 至少能 clone 后跑起来。"

**故事 2 · 防篡改证据库为什么用 SHA-256？**
> "外审（如 BSI、DNV、EY）抽验证据时，会要求我们证明：'这份文件 3 个月前就是这个样子'。
> 
> **SHA-256 摘要链**让审计师可以独立重算验证 —— 不需要信任我的数据库。
> 任何中间人篡改（包括我自己后来手贱改了）都会让 `verify_integrity()` 返回 `HASH_MISMATCH`。
> 
> 这是 ISO 27001 A.5.28 'Collection of evidence' 的最小可行实现。"

**故事 3 · 2022 新增 6 项关键控制为什么重要？**
> "ISO/IEC 27001:2022 相对 2013 版新增 6 项关键控制，本项目全部覆盖：
> - **A.5.7 Threat intelligence** —— 反映 2022 后威胁情报成为合规项
> - **A.5.23 Cloud services security** —— 云时代租户责任划分
> - **A.8.9 Configuration management** —— 防止配置漂移
> - **A.8.12 Data leakage prevention** —— DLP 写入硬性合规
> - **A.8.16 Monitoring activities** —— 替代旧的 A.12.4
> - **A.8.28 Secure coding** —— DevSecOps 必备"

---

## 📜 License

MIT — 自由使用、修改、二次分发。

## 📝 PRD 来源

本项目基于 `Interview/Security_and_GRC_14_Projects_Plan/03_ISO27001_Gap_Assessment_Evidence_Engine.md` 完整规划（来自 14 项目集中规划）。