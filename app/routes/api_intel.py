# -*- coding: utf-8 -*-
"""情报闭环 API（阶段 5）：watchlist 管理、OSV 事件查询、手动运行。"""
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.intel_worker import run_intel
from app.models import IntelEvent, Watchlist
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/intel", tags=["intel"])


def _entry_out(w: Watchlist) -> dict:
    return {"id": w.id, "kind": w.kind, "target": w.target,
            "ecosystem": w.ecosystem, "repo": w.repo,
            "auto_scan": bool(w.auto_scan), "notify": bool(w.notify),
            "active": bool(w.active),
            "created_at": w.created_at.isoformat(sep=" ", timespec="seconds")
            if w.created_at else ""}


@router.get("/watchlist")
def list_watchlist(db: Session = Depends(get_db)):
    rows = db.query(Watchlist).order_by(Watchlist.id.desc()).all()
    return {"items": [_entry_out(w) for w in rows]}


@router.post("/watchlist")
def add_watchlist(data: dict = Body(...), db: Session = Depends(get_db)):
    target = str(data.get("target") or "").strip()
    eco = str(data.get("ecosystem") or "").strip()
    repo = str(data.get("repo") or "").strip()
    kind = str(data.get("kind") or "package").strip()
    if not target or not eco:
        raise HTTPException(status_code=400, detail="target 和 ecosystem 不能为空")
    exists = db.query(Watchlist).filter(
        Watchlist.target == target, Watchlist.ecosystem == eco).first()
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"已在 watchlist（#{exists.id}）")
    w = Watchlist(kind=kind[:16], target=target[:200], ecosystem=eco[:32],
                  repo=repo[:200], auto_scan=bool(data.get("auto_scan")),
                  notify=bool(data.get("notify", True)))
    db.add(w)
    db.commit()
    db.refresh(w)
    return {"ok": True, "id": w.id}


@router.delete("/watchlist/{item_id}")
def delete_watchlist(item_id: int, db: Session = Depends(get_db)):
    w = db.get(Watchlist, item_id)
    if w is None:
        raise HTTPException(status_code=404, detail="watchlist 项不存在")
    db.delete(w)
    db.commit()
    return {"ok": True, "id": item_id}


@router.get("/events")
def list_events(limit: int = 50, q: str = "", db: Session = Depends(get_db)):
    limit = max(1, min(int(limit or 50), 200))
    query = db.query(IntelEvent)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (IntelEvent.cve.like(like)) | (IntelEvent.package.like(like)) |
            (IntelEvent.advisory_id.like(like)) | (IntelEvent.summary.like(like)))
    rows = query.order_by(IntelEvent.id.desc()).limit(limit).all()
    return {"items": [{
        "id": e.id, "source": e.source, "advisory_id": e.advisory_id,
        "cve": e.cve, "package": e.package, "ecosystem": e.ecosystem,
        "severity": e.severity, "summary": e.summary, "fixed": e.fixed,
        "repo": e.repo, "target": e.target, "published": e.published,
        "task_id": e.task_id,
        "created_at": e.created_at.isoformat(sep=" ", timespec="seconds")
        if e.created_at else "",
    } for e in rows]}


@router.post("/run")
def run_now(data: dict = Body(default={}), db: Session = Depends(get_db)):
    auto = bool(data.get("auto_task", False))
    res = run_intel(db, log_fn=lambda m: None, auto_task=auto)
    return {"ok": True, **res}
