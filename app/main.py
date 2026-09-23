"""ISO 27001:2022 Gap Assessment Evidence Engine - FastAPI 入口（端口 5030）"""

from fastapi import FastAPI

app = FastAPI(title="ISO 27001:2022 Gap Assessment Evidence Engine", version="0.1.0")


@app.on_event("startup")
def _startup():
    from . import init_db
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "iso27001-gap-assessment", "version": "0.1.0"}


def run():
    import uvicorn
    import os
    port = int(os.environ.get("WEB_PORT", "5030"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
