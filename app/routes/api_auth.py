# -*- coding: utf-8 -*-
"""阶段 7 v4：返回当前令牌角色（admin/auditor/viewer/open）。"""
from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/me")
def me(request: Request):
    role = getattr(request.state, "role", "")
    return {"role": role, "authenticated": bool(role and role != "open")}
