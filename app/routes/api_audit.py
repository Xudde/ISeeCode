# -*- coding: utf-8 -*-
"""阶段 7：操作审计查询（只读）。"""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import AuditEvent

router = APIRouter(prefix="/api/audit", tags=["audit"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _item(r: AuditEvent) -> dict:
    detail = r.detail or ""
    if detail:
        try:
            detail = json.loads(detail)
        except (TypeError, ValueError):
            pass
    return {
        "id": r.id, "ts": r.ts.isoformat(timespec="seconds") if r.ts else "",
        "action": r.action, "target": r.target, "method": r.method,
        "path": r.path, "status": r.status, "actor": r.actor, "ip": r.ip,
        "duration_ms": r.duration_ms, "detail": detail,
    }


@router.get("/events")
def list_events(limit: int = 100, action: str = "", target: str = "",
                db: Session = Depends(get_db)):
    limit = max(1, min(int(limit or 100), 500))
    q = db.query(AuditEvent)
    if action:
        q = q.filter(AuditEvent.action == action)
    if target:
        q = q.filter(AuditEvent.target == target)
    total = q.count()
    rows = q.order_by(AuditEvent.id.desc()).limit(limit).all()
    return {"total": total, "items": [_item(r) for r in rows]}


@router.get("/summary")
def summary(hours: int = 24, db: Session = Depends(get_db)):
    hours = max(1, min(int(hours or 24), 720))
    since = datetime.now() - timedelta(hours=hours)
    rows = (db.query(AuditEvent.action, func.count(AuditEvent.id))
            .filter(AuditEvent.ts >= since)
            .group_by(AuditEvent.action)
            .order_by(func.count(AuditEvent.id).desc()).all())
    return {"hours": hours, "items": [{"action": a, "count": c} for a, c in rows]}
