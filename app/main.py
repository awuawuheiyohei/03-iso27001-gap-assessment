"""ISO 27001:2022 Gap Assessment Evidence Engine - FastAPI 入口（端口 5030）"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .api import router

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="ISO 27001:2022 Gap Assessment Evidence Engine",
    description="Project CyberVeritas — 93 控制项 + 防篡改证据库 + CAP 整改追踪",
    version="1.0.0",
)


@app.on_event("startup")
def _startup():
    """应用启动时自动 seed（首次启动建库 + 种子数据）"""
    from .models import seed_all, get_conn
    seed_all(verbose=False)
    # 触发 schema 应用后写一条启动 audit
    from datetime import datetime, timezone
    conn = get_conn()
    conn.execute(
        """INSERT INTO audit_trail (actor, action, details) VALUES (?, ?, ?)""",
        ("system", "STARTUP", json_str := '{"version": "1.0.0"}')
    )
    conn.commit()


app.include_router(router, prefix="/api")


# ============================ 前端 Dashboard ============================
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    """默认进 Dashboard"""
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "ISO 27001 Gap Assessment Evidence Engine", "docs": "/docs"}


@app.get("/dashboard")
def dashboard_alias():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Dashboard not yet built"}


def run():
    import uvicorn
    import os
    port = int(os.environ.get("WEB_PORT", "5030"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()