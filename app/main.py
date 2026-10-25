"""FastAPI 入口 + worker 线程启动 + 鉴权 + 启动恢复"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.auth import AUTH_TOKEN, auth_middleware, login_page, logger, setup_logging
from app.db import init_db
from app.queue_worker import recover_pending_tasks, start_worker
from app.routes import api_config, api_tasks, pages


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_worker()
    n = recover_pending_tasks()
    if n:
        logger.info(f"已恢复 {n} 个中断任务重新入队")
    if not AUTH_TOKEN:
        logger.warning("未配置 AUTH_TOKEN 环境变量，服务未启用鉴权！建议设置后仅本机/内网使用")
    yield


setup_logging()
app = FastAPI(title="源码自动化审计平台", lifespan=lifespan)

# 全局鉴权中间件（PUBLIC_PATHS 除外）
app.middleware("http")(auth_middleware)
# 登录页：GET 渲染账号密码表单（?token= 兼容令牌直登），POST 校验登录
app.api_route("/login", methods=["GET", "POST"])(login_page)

app.include_router(pages.router)
app.include_router(api_config.router)
app.include_router(api_tasks.router)

BASE_DIR = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
