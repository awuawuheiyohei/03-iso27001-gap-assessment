"""
数据库访问层 - SQLite 封装
"""
import sqlite3
import json
import os
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "iso27001.db"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def get_conn() -> sqlite3.Connection:
    """获取 SQLite 连接（每次新连接，行字典 + 外键启用）"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(verbose: bool = False) -> sqlite3.Connection:
    """初始化数据库：应用 schema + seed 93 控制项"""
    conn = get_conn()
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    conn.commit()
    if verbose:
        print(f"[+] DB initialized at {DB_PATH}")
    return conn


def row_to_dict(row: sqlite3.Row) -> dict:
    """sqlite3.Row → dict"""
    return {k: row[k] for k in row.keys()} if row else {}


def rows_to_dicts(rows) -> list:
    return [row_to_dict(r) for r in rows]


def write_audit(conn, actor: str, action: str, entity_type: str = None,
                entity_id: str = None, details: dict = None) -> None:
    """记录审计 trail"""
    conn.execute(
        """INSERT INTO audit_trail (actor, action, entity_type, entity_id, details)
           VALUES (?, ?, ?, ?, ?)""",
        (actor, action, entity_type, entity_id, json.dumps(details or {}, ensure_ascii=False))
    )
    conn.commit()


if __name__ == "__main__":
    init_db(verbose=True)
    conn = get_conn()
    cur = conn.execute("SELECT COUNT(*) AS n FROM iso_controls")
    print(f"[+] Controls: {cur.fetchone()['n']}")