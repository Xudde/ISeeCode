"""鉴权与日志基础设施
- AUTH_TOKEN 环境变量：配置后所有 /api/* 与页面需携带 Token（Authorization: Bearer <token> 或 ?token= 或 cookie）
- 未配置 AUTH_TOKEN 时启动警告（建议仅内网/127.0.0.1 部署）
- 统一 logging：控制台 + data/server.log
"""
import logging
import os
import sys

from fastapi import Request
from fastapi.responses import RedirectResponse, JSONResponse

from app.config import DATA_DIR

logger = logging.getLogger("audit-platform")

AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "").strip()

# 允许匿名访问的路径
PUBLIC_PATHS = {"/login", "/static"}


def setup_logging() -> None:
    """初始化日志：控制台 + 文件双写"""
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    if not logger.handlers:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(fmt)
        logger.addHandler(console)
        try:
            fh = logging.FileHandler(DATA_DIR / "server.log", encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except Exception:
            pass


def _check_token(request: Request) -> bool:
    """校验请求携带的 Token（Header / Query / Cookie 任一即可）"""
    if not AUTH_TOKEN:
        return True  # 未启用鉴权
    auth = request.headers.get("Authorization", "")
    if auth == f"Bearer {AUTH_TOKEN}":
        return True
    if request.query_params.get("token") == AUTH_TOKEN:
        return True
    if request.cookies.get("auth_token") == AUTH_TOKEN:
        return True
    return False


async def auth_middleware(request: Request, call_next):
    """全局鉴权中间件"""
    path = request.url.path
    is_public = any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS)
    if not is_public and not _check_token(request):
        # 页面请求跳登录，API 请求返回 401
        if path.startswith("/api/"):
            return JSONResponse({"detail": "未认证：请在请求头携带 Authorization: Bearer <token>"}, status_code=401)
        return RedirectResponse("/login", status_code=302)
    return await call_next(request)


async def login_page(request: Request):
    """极简登录页：校验 Token 后写 cookie"""
    from fastapi.responses import HTMLResponse
    token = request.query_params.get("token", "") or (await request.body()).decode() if request.method == "POST" else request.query_params.get("token", "")
    # 简化：统一用 GET /login?token=xxx
    token = request.query_params.get("token", "")
    if AUTH_TOKEN and token == AUTH_TOKEN:
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie("auth_token", token, httponly=True, samesite="lax")
        return resp
    hint = "请通过 /login?token=<AUTH_TOKEN> 登录" if AUTH_TOKEN else "服务未启用鉴权（未配置 AUTH_TOKEN）"
    return HTMLResponse(f"<html><body><h3>源码自动化审计平台登录</h3><p>{hint}</p></body></html>")
