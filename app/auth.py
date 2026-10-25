"""鉴权与日志基础设施
- AUTH_TOKEN 环境变量：配置后所有 /api/* 与页面需登录（账号密码 / Bearer token / cookie 任一）
- 账号密码登录：AUTH_USER / AUTH_PASS 环境变量（start.sh 中配置），POST /login 表单登录写 cookie
- 未配置 AUTH_TOKEN 时启动警告（建议仅内网/127.0.0.1 部署）
- 统一 logging：控制台 + data/server.log
"""
import asyncio
import logging
import os
import sys

from fastapi import Request
from fastapi.responses import RedirectResponse, JSONResponse

from app.config import DATA_DIR

logger = logging.getLogger("audit-platform")

AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "").strip()
AUTH_USER = os.environ.get("AUTH_USER", "Xudde").strip()
AUTH_PASS = os.environ.get("AUTH_PASS", "123456")

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


_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 · 源码自动化审计平台</title>
<script>
(function () {
  var t = null;
  try { t = localStorage.getItem('sap-theme'); } catch (e) {}
  if (t !== 'light' && t !== 'dark') {
    t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
</script>
<link rel="stylesheet" href="/static/style.css?v=5">
<style>
body { display: grid; place-items: center; min-height: 100vh; padding: 20px; }
.login-card {
  width: 384px; max-width: 100%;
  background: var(--card-grad);
  border: 1px solid var(--line); border-radius: 14px;
  padding: 36px 34px 30px; box-shadow: var(--shadow);
}
.login-logo {
  width: 54px; height: 54px; border-radius: 14px; margin: 0 auto 14px;
  background: var(--logo-grad); border: 1px solid color-mix(in srgb, var(--accent) 35%, transparent);
  display: grid; place-items: center;
}
.login-logo svg { width: 26px; height: 26px; stroke: var(--accent); }
.login-title { text-align: center; font-size: 18px; font-weight: 700; }
.login-sub { text-align: center; font-size: 12px; color: var(--text-faint); margin: 4px 0 22px; font-family: var(--mono); }
.login-err {
  display: {ERRSHOW}; color: var(--red); font-size: 12.5px;
  background: color-mix(in srgb, var(--red) 9%, transparent);
  border: 1px solid color-mix(in srgb, var(--red) 35%, transparent);
  border-radius: 8px; padding: 8px 12px; margin-bottom: 14px; text-align: center;
}
.login-card label { display: block; font-size: 12.5px; color: var(--text-dim); margin: 14px 0 6px; }
.btn-login {
  width: 100%; margin-top: 24px; justify-content: center; padding: 10px 0;
  font-size: 14px; border-radius: 9px;
}
.login-foot { text-align: center; font-size: 11.5px; color: var(--text-faint); margin-top: 20px; }
</style>
</head>
<body>
  <form class="login-card" method="post" action="/login" autocomplete="off">
    <div class="login-logo">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
    </div>
    <div class="login-title">源码自动化审计平台</div>
    <div class="login-sub">Source Audit Platform</div>
    <div class="login-err">{ERR}</div>
    <label for="username">用户名</label>
    <input type="text" id="username" name="username" required autofocus autocomplete="username">
    <label for="password">密码</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">
    <button type="submit" class="btn btn-primary btn-login">登 录</button>
    <div class="login-foot">内网系统 · 请使用平台分配的账号登录</div>
  </form>
</body>
</html>
"""


def _render_login(err: str = "") -> str:
    return _LOGIN_PAGE.replace("{ERR}", err or "用户名或密码错误").replace("{ERRSHOW}", "block" if err else "none")


async def login_page(request: Request):
    """登录页：GET 渲染表单（?token= 兼容令牌直登）；POST 校验账号密码写 cookie"""
    from fastapi.responses import HTMLResponse

    def _ok():
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("auth_token", AUTH_TOKEN, httponly=True, samesite="lax")
        return resp

    # 已登录直接回首页
    if AUTH_TOKEN and _check_token(request):
        return RedirectResponse("/", status_code=302)

    if request.method == "POST":
        try:
            form = await request.form()
        except Exception:
            form = {}
        user = str(form.get("username") or "")
        pwd = str(form.get("password") or "")
        if AUTH_USER and user == AUTH_USER and pwd == AUTH_PASS:
            return _ok()
        await asyncio.sleep(1.2)  # 失败延时，增加爆破成本
        logger.warning(f"登录失败：用户名 {user!r} 来自 {request.client.host if request.client else '?'}")
        return HTMLResponse(_render_login("用户名或密码错误"), status_code=401)

    # GET：令牌直登兼容（API/脚本场景）
    token = request.query_params.get("token", "")
    if AUTH_TOKEN and token == AUTH_TOKEN:
        return _ok()
    return HTMLResponse(_render_login())
