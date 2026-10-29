"""FastAPI 入口 + worker 线程启动 + 鉴权 + 启动恢复"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.audit import audit_middleware
from app.auth import AUTH_ENABLED, AUTH_TOKEN, auth_middleware, login_page, logger, setup_logging
from app.db import SessionLocal, init_db
from app.intel_worker import start_intel_thread
from app.queue_worker import recover_pending_tasks, start_worker
from app.routes import (api_agent, api_audit, api_auth, api_config, api_engines,
                        api_intel, api_tasks, api_variant, api_verified, pages)
from app.secrets import migrate_plaintext


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        with SessionLocal() as db:
            migrate_plaintext(db)
    except Exception as e:
        logger.warning(f"配置密钥迁移失败（不影响启动）: {e}")
    start_worker()
    start_intel_thread()
    n = recover_pending_tasks()
    if n:
        logger.info(f"已恢复 {n} 个中断任务重新入队")
    if not AUTH_ENABLED:
        logger.warning("未配置 AUTH_TOKEN 环境变量，服务未启用鉴权！建议设置后仅本机/内网使用")
    elif not AUTH_TOKEN:
        logger.warning("未配置 admin AUTH_TOKEN，登录页与管理操作不可用；仅只读令牌生效")
    yield


setup_logging()
app = FastAPI(title="源码自动化审计平台", lifespan=lifespan)

# 全局鉴权中间件（PUBLIC_PATHS 除外）
app.middleware("http")(auth_middleware)
# 审计中间件需在鉴权外层，才能记录 401 尝试；不记录请求体
app.middleware("http")(audit_middleware)
# 登录页：GET 渲染账号密码表单（?token= 兼容令牌直登），POST 校验登录
app.api_route("/login", methods=["GET", "POST"])(login_page)

app.include_router(pages.router)
app.include_router(api_auth.router)
app.include_router(api_audit.router)
app.include_router(api_engines.router)
app.include_router(api_config.router)
app.include_router(api_tasks.router)
app.include_router(api_variant.router)
app.include_router(api_intel.router)
app.include_router(api_agent.router)
app.include_router(api_verified.router)

BASE_DIR = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
