# -*- coding: utf-8 -*-
"""操作审计（阶段 7）：记录变更类 API 与登录动作，不记录请求体/密钥。
独立会话写入，失败只告警，不影响主流程。"""
import asyncio
import json
import logging
import re
import time

from app.db import SessionLocal
from app.models import AuditEvent

logger = logging.getLogger("audit")

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

_ACTIONS = [
    ("POST", r"^/login$", "auth.login"),
    ("POST", r"^/api/tasks$", "task.create"),
    ("POST", r"^/api/tasks/\d+/resume$", "task.resume"),
    ("POST", r"^/api/tasks/\d+/cancel$", "task.cancel"),
    ("POST", r"^/api/tasks/\d+/agent-exec$", "agent.exec"),
    ("POST", r"^/api/tasks/\d+/agent-request$", "agent.request"),
    ("POST", r"^/api/tasks/\d+/chains/generate$", "chain.generate"),
    ("POST", r"^/api/tasks/\d+/chains/\d+/verify$", "chain.verify"),
    ("POST", r"^/api/tasks/\d+/tool-scan$", "tool.scan"),
    ("POST", r"^/api/tasks/\d+/authz-probe$", "authz.probe"),
    ("DELETE", r"^/api/tasks/\d+$", "task.delete"),
    ("POST", r"^/api/config$", "config.update"),
    ("POST", r"^/api/variant/scan$", "variant.scan"),
    ("POST", r"^/api/intel/run$", "intel.run"),
    ("POST", r"^/api/intel/watchlist$", "intel.watchlist.add"),
    ("DELETE", r"^/api/intel/watchlist/\d+$", "intel.watchlist.delete"),
    ("POST", r"^/api/agent/next$", "agent.next"),
    ("POST", r"^/api/agent/progress$", "agent.progress"),
    ("POST", r"^/api/agent/heartbeat$", "agent.heartbeat"),
    ("POST", r"^/api/agent/complete$", "agent.complete"),
    ("POST", r"^/api/agent/release$", "agent.release"),
]
_COMPILED = [(m, re.compile(p), a) for m, p, a in _ACTIONS]


def classify(method: str, path: str) -> tuple[str, str]:
    method = (method or "").upper()
    for m, rx, action in _COMPILED:
        if m == method and rx.match(path):
            target = ""
            mt = re.search(r"/api/tasks/(\d+)", path)
            if mt:
                target = f"task:{mt.group(1)}"
            else:
                mw = re.search(r"/api/intel/watchlist/(\d+)", path)
                if mw:
                    target = f"watchlist:{mw.group(1)}"
            return action, target
    return f"{method.lower()} {path}"[:64], ""


def record(action: str, *, target: str = "", method: str = "", path: str = "",
           status: int = 0, actor: str = "", ip: str = "", duration_ms: int = 0,
           detail=None) -> None:
    try:
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail, ensure_ascii=False, default=str)
        with SessionLocal() as db:
            db.add(AuditEvent(
                action=(action or "")[:64], target=(target or "")[:64],
                method=(method or "")[:8], path=(path or "")[:512],
                status=int(status or 0), actor=(actor or "")[:16],
                ip=(ip or "")[:64], duration_ms=int(duration_ms or 0),
                detail=(detail or "")[:4000],
            ))
            db.commit()
    except Exception as e:
        logger.warning(f"审计写入失败: {e}")


async def audit_middleware(request, call_next):
    start = time.perf_counter()
    path = request.url.path
    watched = request.method in MUTATING and (path.startswith("/api/") or path == "/login")
    try:
        response = await call_next(request)
    except Exception:
        if watched:
            _emit(request, 500, int((time.perf_counter() - start) * 1000))
        raise
    if watched:
        _emit(request, response.status_code, int((time.perf_counter() - start) * 1000))
    return response


def _emit(request, status: int, duration: int) -> None:
    action, target = classify(request.method, request.url.path)
    actor = getattr(request.state, "role", "")
    if not actor:
        actor = "token" if request.headers.get("authorization") else (
            "agent-token" if request.query_params.get("token") else (
                "cookie" if request.cookies.get("auth_token") else "anonymous"))
    ip = request.client.host if request.client else ""
    args = dict(target=target, method=request.method, path=request.url.path,
                status=status, actor=actor, ip=ip, duration_ms=duration)
    try:
        asyncio.get_running_loop().create_task(
            asyncio.to_thread(record, action, **args))
    except RuntimeError:
        record(action, **args)
