# -*- coding: utf-8 -*-
"""阶段 2：补丁差分 / 同源变体扫描 API。

POST /api/variant/scan
{
  "task_id": 92,                 // 目标源码任务（已完成、工作区存在）
  "cve": "CVE-2026-43947",       // 可选，仅用于标注
  "repo": "frangoteam/FUXA",     // 可选；与 base/head 或 commit 一起从 GitHub 拉 diff
  "base": "v1.3.0", "head": "v1.3.1",
  "commit": "",                  // 或指定修复 commit
  "patch": "",                   // 也可直接传 unified diff 文本
  "severity": "WARNING",
  "max_findings": 30
}
"""
import json
import urllib.error

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models import PatchFeature, Task, Vulnerability
from app.routes.api_config import get_db
from app.skills import patch_diff

router = APIRouter(prefix="/api/variant", tags=["variant"])


@router.post("/scan")
def variant_scan(data: dict = Body(...), db: Session = Depends(get_db)):
    try:
        task_id = int(data.get("task_id") or 0)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="task_id 无效")
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    ws = task.workspace_path or ""
    patch = str(data.get("patch") or "")
    repo = str(data.get("repo") or "")
    base = str(data.get("base") or "")
    head = str(data.get("head") or "")
    commit = str(data.get("commit") or "")
    if not patch and not repo:
        raise HTTPException(status_code=400, detail="需要 patch 文本，或 repo + (base/head 或 commit)")
    cve = str(data.get("cve") or "")[:64]
    severity = str(data.get("severity") or "WARNING").upper()[:16]
    try:
        max_findings = max(1, min(int(data.get("max_findings") or 30), 100))
    except (TypeError, ValueError):
        max_findings = 30
    try:
        result = patch_diff.analyze(ws, patch_text=patch, repo=repo, base=base,
                                    head=head, commit=commit, cve=cve,
                                    severity=severity, max_findings=max_findings)
    except (TimeoutError, urllib.error.URLError) as e:
        raise HTTPException(status_code=504,
                            detail=f"GitHub diff 获取超时/网络受限：{e}；请改用 patch 文本")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"补丁获取/分析失败: {e}")
    created = 0
    for f in result.get("findings") or []:
        exists = db.query(Vulnerability).filter(
            Vulnerability.task_id == task_id,
            Vulnerability.file_path == f["file_path"],
            Vulnerability.line == f["line"],
            Vulnerability.rule_id == f["rule_id"]).first()
        if exists is not None:
            continue
        db.add(Vulnerability(
            task_id=task_id, source="variant", rule_id=f["rule_id"][:128],
            title=f["title"][:128], severity=f["severity"],
            file_path=f["file_path"][:512], line=f["line"],
            code_snippet=f["code_snippet"][:1600],
            precondition=f["precondition"][:512],
            verify_result="同源变体候选（静态）：需人工确认可达性与过滤差异",
        ))
        created += 1
    db.add(PatchFeature(
        task_id=task_id, cve=cve, repo=repo[:200],
        commit_ref=(commit or (f"{base}...{head}" if base or head else ""))[:200],
        features_json=patch_diff.features_json(result.get("features") or {}),
        findings_count=len(result.get("findings") or []),
    ))
    db.commit()
    return {"ok": True, "task_id": task_id, "created": created,
            "summary": result.get("summary") or {},
            "features": {k: (result.get("features") or {}).get(k)
                         for k in ("sinks", "checks", "files", "stats")},
            "sample": (result.get("findings") or [])[:10]}
