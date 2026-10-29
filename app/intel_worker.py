# -*- coding: utf-8 -*-
"""情报闭环 v1（阶段 5）：watchlist → OSV 增量 → 事件库 → Webhook → 可选自动建任务。"""
import hashlib
import json
import os
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, time as dtime
from pathlib import Path

from app.config import UPLOAD_DIR
from app.db import SessionLocal
from app.models import Config, IntelEvent, Task, Watchlist
from app.queue_worker import enqueue
from app.secrets import decrypt

OSV_API = "https://api.osv.dev/v1/query"
MAX_EVENTS_PER_RUN = 200
MAX_AUTO_TASKS_PER_RUN = 2


def _log(fn, msg):
    (fn or (lambda m: None))(msg)


def _cfg(db, key: str, default: str = "") -> str:
    row = db.get(Config, key)
    return decrypt(row.value) if row else default


def _set_cfg(db, key: str, value: str) -> None:
    row = db.get(Config, key)
    if row is None:
        db.add(Config(key=key, value=value))
    else:
        row.value = value


def _osv_query(name: str, ecosystem: str) -> dict:
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(OSV_API, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "iseecode-intel"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())


def _cve_of(v: dict) -> str:
    for a in (v.get("aliases") or []):
        if str(a).startswith("CVE-"):
            return a
    return str(v.get("id") or "")


def _fixed(v: dict) -> str:
    for aff in (v.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def _severity(v: dict) -> str:
    sev = str((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
            "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(sev, "UNKNOWN")


def _send_webhook(url: str, text: str, kind: str = "wecom") -> bool:
    if not url:
        return False
    kind = (kind or "wecom").lower()
    if kind == "feishu":
        payload = {"msg_type": "text", "content": {"text": text}}
    elif kind == "generic":
        payload = {"text": text}
    else:
        payload = {"msgtype": "text", "text": {"content": text}}
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _latest_release(repo: str) -> str:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        p = subprocess.run(["curl", "-sS", "-L", "--max-time", "25",
                            "-H", "User-Agent: iseecode-intel", url],
                           capture_output=True, timeout=30)
        if p.returncode != 0:
            return ""
        data = json.loads(p.stdout.decode("utf-8", "replace") or "{}")
        return str(data.get("tag_name") or "")
    except Exception:
        return ""


def _auto_task(db, entry: Watchlist, log_fn) -> int | None:
    """下载 watchlist 仓库的最新 release 源码并建 poc 任务（best-effort）。"""
    repo = (entry.repo or "").strip().strip("/")
    if not repo:
        return None
    tag = _latest_release(repo)
    if not tag:
        _log(log_fn, f"自动建任务跳过：{repo} 没有 release")
        return None
    url = f"https://codeload.github.com/{repo}/zip/refs/tags/{tag}"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    tmp = UPLOAD_DIR / f".intel_{int(time.time())}.zip"
    try:
        p = subprocess.run(["curl", "-L", "-sS", "--max-time", "300", "-o", str(tmp), url],
                           capture_output=True, timeout=320)
        if p.returncode != 0 or not tmp.exists() or tmp.stat().st_size < 1000:
            _log(log_fn, f"自动建任务失败：{repo} 下载失败")
            tmp.unlink(missing_ok=True)
            return None
        h = hashlib.sha256(tmp.read_bytes()).hexdigest()
        dup = db.query(Task).filter(Task.file_hash == h).first()
        if dup is not None:
            tmp.unlink(missing_ok=True)
            _log(log_fn, f"自动建任务跳过：{repo}@{tag} 已存在任务 #{dup.id}")
            return dup.id
        name = f"{repo.replace('/', '_')}_{tag}_poc.zip"
        dest = UPLOAD_DIR / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{name}"
        tmp.replace(dest)
        t = Task(filename=name, file_hash=h, upload_path=str(dest),
                 workspace_path=str(dest), project_type="web", audit_mode="poc")
        db.add(t)
        db.commit()
        db.refresh(t)
        enqueue(t.id)
        _log(log_fn, f"自动建任务：{repo}@{tag} -> #{t.id}")
        return t.id
    except Exception as e:
        tmp.unlink(missing_ok=True)
        _log(log_fn, f"自动建任务异常 {repo}: {e}")
        return None


def run_intel(db, log_fn=None, auto_task: bool = True) -> dict:
    entries = db.query(Watchlist).filter(Watchlist.active.is_(True)).all()
    if not entries:
        return {"entries": 0, "new_events": 0, "tasks": 0, "errors": 0,
                "note": "watchlist 为空"}
    created, tasks, errors, lines = 0, 0, 0, []
    webhook_url = _cfg(db, "intel_webhook_url")
    webhook_kind = _cfg(db, "intel_webhook_type", "wecom")
    notify = False
    for entry in entries:
        if created >= MAX_EVENTS_PER_RUN:
            break
        name = (entry.target or "").strip()
        eco = (entry.ecosystem or "").strip()
        if not name or not eco:
            continue
        try:
            data = _osv_query(name, eco)
        except Exception as e:
            errors += 1
            _log(log_fn, f"OSV 查询失败 {name}/{eco}: {e}")
            continue
        for v in (data.get("vulns") or []):
            if created >= MAX_EVENTS_PER_RUN:
                break
            aid = str(v.get("id") or "")
            if not aid:
                continue
            key = f"osv:{aid}:{name}:{eco}"
            if db.query(IntelEvent).filter(IntelEvent.event_key == key).first() is not None:
                continue
            cve = _cve_of(v)
            ev = IntelEvent(
                source="osv", event_key=key, advisory_id=aid, cve=cve,
                package=name, ecosystem=eco, severity=_severity(v),
                summary=str(v.get("summary") or v.get("details") or "")[:4000],
                fixed=_fixed(v), repo=(entry.repo or "")[:200],
                target=(entry.target or "")[:200],
                published=str(v.get("published") or v.get("modified") or "")[:32],
            )
            db.add(ev)
            created += 1
            notify = notify or bool(entry.notify)
            lines.append(f"- {cve or aid} | {name} ({eco}) | {ev.severity} | "
                         f"{ev.summary[:100]}")
            if auto_task and entry.auto_scan and entry.repo and tasks < MAX_AUTO_TASKS_PER_RUN:
                tid = _auto_task(db, entry, log_fn)
                if tid:
                    ev.task_id = tid
                    tasks += 1
        db.commit()
    if created:
        _set_cfg(db, "intel_last_run", datetime.now().isoformat(sep=" ", timespec="seconds"))
        db.commit()
    if created and notify and webhook_url:
        text = f"ISeeCode 情报：新增 {created} 条\n" + "\n".join(lines[:20])
        ok = _send_webhook(webhook_url, text, webhook_kind)
        _log(log_fn, f"Webhook {'成功' if ok else '失败'}")
    return {"entries": len(entries), "new_events": created, "tasks": tasks,
            "errors": errors, "lines": lines[:20]}


def _parse_hhmm(value: str, default: dtime) -> dtime:
    try:
        h, m = str(value or "").split(":", 1)
        return dtime(int(h), int(m))
    except Exception:
        return default


def _scheduler_loop():
    while True:
        try:
            db = SessionLocal()
            try:
                enabled = _cfg(db, "intel_enabled", "0") == "1"
                run_at = _parse_hhmm(_cfg(db, "intel_run_time", "21:30"), dtime(21, 30))
                last = _cfg(db, "intel_last_run", "")
                now = datetime.now()
                due = enabled and now.time() >= run_at and not last.startswith(now.strftime("%Y-%m-%d"))
                if due:
                    res = run_intel(db, log_fn=lambda m: print(f"[intel] {m}", flush=True))
                    print(f"[intel] run result: {res}", flush=True)
            finally:
                db.close()
        except Exception as e:
            print(f"[intel] scheduler error: {e}", flush=True)
        time.sleep(300)


def start_intel_thread() -> threading.Thread:
    t = threading.Thread(target=_scheduler_loop, name="intel-worker", daemon=True)
    t.start()
    return t
