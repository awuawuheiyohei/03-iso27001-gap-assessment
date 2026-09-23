"""
Test fixtures - 每个测试启动前用临时 DB
"""
import os
import sys
import tempfile
from pathlib import Path

# 加项目根到 PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 用临时 DB 路径覆盖（避免污染真实 db）
TEST_DB = tempfile.mktemp(suffix=".db")
os.environ["ISO27001_TEST_DB"] = TEST_DB

import pytest
from app.models.db import DB_PATH, init_db
from app.models.seed import seed_all


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    """每个测试 fresh"""
    # 重定向 DB_PATH
    import app.models.db as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", Path(TEST_DB))
    monkeypatch.setattr(db_mod, "DATA_DIR", Path(tempfile.mkdtemp()))
    # seed
    init_db()
    seed_all(verbose=False)
    yield
    # cleanup
    try:
        Path(TEST_DB).unlink()
    except FileNotFoundError:
        pass