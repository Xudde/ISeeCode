# -*- coding: utf-8 -*-
"""外部 AI 自动化深挖：任务领取租约、checkpoint、完成回写。"""
import json
import re
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.models import AgentRun, ExploitChain, Task, Vulnerability
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/agent", tags=["agent"])
LEASE_MINUTES = 15
MAX_CHECKPOINT = 100_000
STAGES = {"triage", "exploit", "verify", "judge", "done"}


def _iso(dt) -> str | None:
    return dt.isoformat(sep=" ", timespec="seconds") if dt else None


def _latest_runs(db: Session) -> dict[int, AgentRun]:
    latest = {}
    for r in db.query(AgentRun).order_by(AgentRun.id.desc()).all():
        latest.setdefault(r.task_id, r)
    return latest


def _pack_url(request: Request, task_id: int) -> str:
    return str(request.base_url).rstrip("/") + f"/api/tasks/{task_id}/agent-pack"


def _run_payload(request: Request, task: Task, run: AgentRun,
                 checkpoint: str = "", resumed: bool = False) -> dict:
    cid = getattr(task, "sandbox_cid", None)
    running = False
    if cid:
        try:
            from app.skills import sandbox as sandbox_skill
            running = sandbox_skill.is_running(cid)
        except Exception:
            running = False
    runtime_ready = bool(cid) and running
    if not cid:
        runtime_note = ("无沙箱：只允许读 pack 内 source/ 和报告，禁止遍历当前工作目录；"
                        "标记 static_only 并结束，等待人工起沙箱")
    elif not running:
        runtime_note = ("沙箱容器已退出（保留容器已过期/被清理），runtime_ready=false；"
                        "只读 pack 内 source/ 和报告，或让用户重新部署沙箱后再动态验证")
    else:
        runtime_note = "有沙箱，可用 environment.json 的 agent_token 动态验证"
    return {
        "run_id": run.id,
        "task_id": task.id,
        "task": {"filename": task.filename, "tech_stack": task.tech_stack,
                 "audit_mode": task.audit_mode, "project_type": task.project_type},
        "pack_url": _pack_url(request, task.id),
        "pack_auth": "Authorization: Bearer <PLATFORM_TOKEN>",
        "runtime_ready": runtime_ready,
        "sandbox_state": ("running" if runtime_ready else ("exited" if cid else "none")),
        "runtime_note": runtime_note,
        "stage": run.stage or "",
        "checkpoint": checkpoint or run.checkpoint or "",
        "lease_until": _iso(run.lease_until),
        "last_activity": _iso(run.updated_at),
        "lease_minutes": LEASE_MINUTES,
        "server_time": _iso(datetime.now()),
        "heartbeat_api": f"/api/agent/runs/{run.id}/heartbeat",
        "resumed": resumed,
        "state_api": {
            "progress": "/api/agent/runs/{run_id}/progress",
            "complete": "/api/agent/runs/{run_id}/complete",
        },
    }


@router.get("/next")
def agent_next(request: Request, session: str = "", mode: str = "dynamic",
               db: Session = Depends(get_db)):
    """领取下一个未完成深挖任务；mode=dynamic 只领有沙箱的任务；
    mode=static 只领无沙箱静态任务（可多窗口并行）；mode=all 两者都领。"""
    if not session:
        session = "sess_" + uuid.uuid4().hex[:12]
    now = datetime.now()
    latest = _latest_runs(db)

    # 1) 先恢复租约已过期的 running 会话（保留 checkpoint）
    for tid, run in sorted(latest.items(), key=lambda kv: kv[1].id):
        if run.status == "running" and run.lease_until and run.lease_until < now:
            task = db.get(Task, tid)
            if task is None:
                continue
            cid = getattr(task, "sandbox_cid", None)
            if mode == "dynamic" and not cid:
                continue
            if mode == "static" and cid:
                continue
            run.session_key = session
            run.lease_until = now + timedelta(minutes=LEASE_MINUTES)
            db.commit()
            return {"status": "ok", **_run_payload(request, task, run, run.checkpoint, True)}

    # 2) 已完成任务中，挑选从未深挖/未被完成的任务；跳过仍在租约内的会话
    counts = {}
    for tid, in db.query(Vulnerability.task_id).all():
        counts[tid] = counts.get(tid, 0) + 1
    tasks = db.query(Task).filter(Task.status == "completed").order_by(Task.id.asc()).all()
    busy_until = None
    busy_run = None
    for task in tasks:
        run = latest.get(task.id)
        cid = getattr(task, "sandbox_cid", None)
        if run is not None:
            if run.status == "completed":
                continue
            if run.status == "blocked":
                continue
            if run.status == "running":
                if mode == "static":
                    # 静态并发：跳过已有会话的任务，但不阻塞其他静态任务
                    continue
                if mode == "dynamic" and not cid:
                    continue
                if busy_run is None or run.lease_until > busy_run.lease_until:
                    busy_run = run
                busy_until = max(busy_until, run.lease_until) if busy_until else run.lease_until
                continue
        if counts.get(task.id, 0) <= 0:
            continue
        if mode == "dynamic" and not cid:
            continue
        if mode == "static" and cid:
            continue
        run = AgentRun(task_id=task.id, session_key=session, status="running",
                       lease_until=now + timedelta(minutes=LEASE_MINUTES),
                       checkpoint="")
        db.add(run)
        db.commit()
        db.refresh(run)
        return {"status": "ok", **_run_payload(request, task, run)}

    if mode == "static":
        busy_until = None  # 静态任务允许并行，不返回 busy
    return {"status": "busy" if busy_until else "idle",
            "message": "没有待深挖任务" if not busy_until else "当前任务租约未到期",
            "next_at": _iso(busy_until), "session": session,
            "active_run": ({"run_id": busy_run.id, "task_id": busy_run.task_id,
                            "last_activity": _iso(busy_run.updated_at),
                            "lease_until": _iso(busy_run.lease_until)}
                           if busy_run else None),
            "server_time": _iso(datetime.now()),
            "dynamic_pending": sum(1 for t in tasks if getattr(t, "sandbox_cid", None)
                                   and (latest.get(t.id) is None or
                                        latest.get(t.id).status not in ("completed",))),
            "static_pending": sum(1 for t in tasks if not getattr(t, "sandbox_cid", None)
                                  and (latest.get(t.id) is None or
                                       latest.get(t.id).status not in ("completed",)))}


@router.post("/runs/{run_id}/progress")
def agent_progress(run_id: int, data: dict = Body(default={}),
                   db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status == "completed":
        return {"ok": True, "status": "completed"}
    run.checkpoint = str(data.get("checkpoint") or run.checkpoint or "")[:MAX_CHECKPOINT]
    if data.get("stage") in STAGES:
        run.stage = data["stage"]
    if data.get("status") in ("running", "blocked"):
        run.status = data["status"]
    if run.status == "running":
        run.lease_until = datetime.now() + timedelta(minutes=LEASE_MINUTES)
    db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status,
            "stage": run.stage or "", "lease_until": _iso(run.lease_until),
            "checkpoint": run.checkpoint}


def _extract_result(checkpoint: str) -> dict | None:
    text = checkpoint or ""
    for needle in ("RESULT_JSON", '{"task_id"', '{"findings"'):
        i = text.find(needle)
        if i < 0:
            continue
        j = text.find("{", i)
        if j < 0:
            continue
        try:
            data, _ = json.JSONDecoder().raw_decode(text[j:])
            if isinstance(data, dict) and isinstance(data.get("findings"), list):
                return data
        except (ValueError, TypeError):
            continue
    return None


def _norm_verdict(finding: dict) -> str:
    raw = str(finding.get("ai_verdict") or finding.get("status") or "").lower()
    if raw in ("verified", "real", "true"):
        return "verified"
    if raw in ("false_positive", "false-positive", "fp", "false"):
        return "false_positive"
    return "unverified"


def _create_external_row(db: Session, run: AgentRun, f: dict, verdict: str,
                         fp: str, line: int) -> Vulnerability:
    """深挖结论在平台没有对应扫描记录时，新建 source=agent-external 条目，
    避免 AI 验真/误报结果被静默丢弃（阶段 0.1）。"""
    rid = str(f.get("rule_id") or "").strip() or "agent-reported"
    evidence = str(f.get("evidence") or "")
    row = Vulnerability(
        task_id=run.task_id,
        source="agent-external",
        rule_id=rid[:128],
        title=(str(f.get("title") or "").strip()[:128] or None),
        severity=str(f.get("severity") or "WARNING").upper()[:16],
        file_path=fp[:512],
        line=line,
        code_snippet=(str(f.get("code_snippet") or evidence))[:2000],
        precondition=(str(f.get("precondition") or "")[:512] or None),
        poc_payload=(str(f.get("payload") or "")[:2000] or None),
        agent_status=verdict,
        agent_confidence=(str(f.get("confidence") or "")[:8] or None),
        agent_reason=(str(f.get("reason") or f.get("impact") or "")[:2000] or None),
        agent_evidence=(evidence[:6000] or None),
        analyzed_at=datetime.now(),
    )
    if verdict == "verified":
        row.poc_verified = True
        row.verify_result = (evidence or str(f.get("response") or ""))[:2000] or None
    db.add(row)
    db.flush()
    return row


def _store_chain(db: Session, run: AgentRun, f: dict) -> int:
    """阶段 0.8：把 findings[].chain 落库为利用链节点图。"""
    chain = f.get("chain")
    if not isinstance(chain, dict):
        return 0
    nodes = chain.get("nodes") or []
    if not isinstance(nodes, list) or not nodes:
        return 0
    title = str(chain.get("title") or f.get("title") or "利用链")[:200]
    exists = db.query(ExploitChain).filter(
        ExploitChain.task_id == run.task_id, ExploitChain.title == title).first()
    if exists is not None:
        return 0
    db.add(ExploitChain(
        task_id=run.task_id, run_id=run.id, title=title,
        nodes_json=json.dumps(nodes, ensure_ascii=False)[:20000],
        edges_json=json.dumps(chain.get("edges") or [], ensure_ascii=False)[:8000],
        verified=bool(chain.get("verified")),
    ))
    db.flush()
    return 1


def _ingest_result(db: Session, run: AgentRun, checkpoint: str) -> dict:
    data = _extract_result(checkpoint)
    if not data:
        return {"parsed": False, "ingested": 0, "updated": 0, "created": 0,
                "note": "未找到 RESULT_JSON，仅保存 checkpoint"}
    updated = 0
    created = 0
    created_chains = 0
    counts = {"verified": 0, "false_positive": 0, "unverified": 0}
    seen = set()
    for f in (data.get("findings") or []):
        if not isinstance(f, dict):
            continue
        verdict = _norm_verdict(f)
        created_chains += _store_chain(db, run, f)
        vid = f.get("cand_id") or f.get("vuln_id")
        if not vid:
            m = re.search(r"\[(\d+)\]", str(f.get("title") or ""))
            if m:
                vid = int(m.group(1))
        fp = str(f.get("file") or "").lstrip("./")
        try:
            line = int(f.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        row = None
        if vid:
            try:
                row = db.get(Vulnerability, int(vid))
                if row is not None and row.task_id != run.task_id:
                    row = None
            except (TypeError, ValueError):
                row = None
        if row is None and fp:
            rows = db.query(Vulnerability).filter(
                Vulnerability.task_id == run.task_id,
                Vulnerability.file_path == fp,
                Vulnerability.line == line).all()
            if len(rows) == 1:
                row = rows[0]
        # 平台没有对应扫描行时，按 (file,line,rule_id) 去重后新建；
        # 只落 verified / false_positive，unverified 未命中不制造噪声。
        if row is None and fp and verdict in ("verified", "false_positive"):
            rid = str(f.get("rule_id") or "").strip() or "agent-reported"
            row = db.query(Vulnerability).filter(
                Vulnerability.task_id == run.task_id,
                Vulnerability.file_path == fp,
                Vulnerability.line == line,
                Vulnerability.rule_id == rid[:128]).first()
            if row is None:
                row = _create_external_row(db, run, f, verdict, fp, line)
                created += 1
        if row is None or row.id in seen:
            continue
        seen.add(row.id)
        row.agent_status = verdict
        row.agent_confidence = str(f.get("confidence") or "")[:8] or row.agent_confidence
        reason = f.get("reason") or f.get("impact") or f.get("summary") or ""
        if reason:
            row.agent_reason = str(reason)[:2000]
        evidence = f.get("evidence") or ""
        extra = []
        if f.get("request"):
            extra.append("REQUEST: " + str(f["request"])[:3000])
        if f.get("response"):
            extra.append("RESPONSE: " + str(f["response"])[:3000])
        if f.get("repro_steps"):
            extra.append("REPRO: " + json.dumps(f["repro_steps"], ensure_ascii=False)[:2000])
        row.agent_evidence = ("\n".join([str(evidence)] + extra))[:6000]
        row.analyzed_at = datetime.now()
        if verdict == "verified":
            row.poc_verified = True
            if f.get("payload"):
                row.poc_payload = str(f["payload"])[:2000]
            row.verify_result = (str(evidence) or str(f.get("response") or ""))[:2000]
        counts[verdict] += 1
        updated += 1
    db.commit()
    return {"parsed": True, "ingested": len(data.get("findings") or []),
            "updated": updated, "created": created, "created_chains": created_chains,
            "counts": counts, "summary": data.get("summary") or {}}


@router.post("/runs/{run_id}/complete")
def agent_complete(run_id: int, data: dict = Body(default={}),
                   db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    checkpoint = str(data.get("checkpoint") or run.checkpoint or "").strip()
    if len(checkpoint) < 50:
        raise HTTPException(status_code=400,
                            detail="checkpoint 太短：完成前必须留下候选结论/证据摘要，防止掉线被误记完成")
    run.status = "completed"
    run.stage = "done"
    run.lease_until = None
    run.checkpoint = checkpoint[:MAX_CHECKPOINT]
    db.commit()
    ingested = _ingest_result(db, run, checkpoint)
    return {"ok": True, "run_id": run.id, "task_id": run.task_id,
            "status": "completed", "stage": run.stage, "ingest": ingested}


@router.post("/runs/{run_id}/heartbeat")
def agent_heartbeat(run_id: int, data: dict = Body(default={}),
                    db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status != "running":
        return {"ok": False, "status": run.status}
    run.lease_until = datetime.now() + timedelta(minutes=LEASE_MINUTES)
    if data.get("stage") in STAGES:
        run.stage = data["stage"]
    if data.get("checkpoint"):
        run.checkpoint = str(data["checkpoint"])[:20000]
    db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status,
            "stage": run.stage or "",
            "last_activity": _iso(run.updated_at), "lease_until": _iso(run.lease_until)}


@router.post("/runs/{run_id}/release")
def agent_release(run_id: int, data: dict = Body(default={}),
                  db: Session = Depends(get_db)):
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    if run.status != "completed":
        run.status = "expired"
        run.lease_until = None
        run.checkpoint = str(data.get("checkpoint") or run.checkpoint or "")[:MAX_CHECKPOINT]
        db.commit()
    return {"ok": True, "run_id": run.id, "status": run.status}


@router.get("/state")
def agent_state(db: Session = Depends(get_db)):
    latest = _latest_runs(db)
    tasks = db.query(Task).filter(Task.status == "completed").order_by(Task.id.desc()).all()
    out = []
    for t in tasks:
        r = latest.get(t.id)
        out.append({"task_id": t.id, "filename": t.filename,
                    "deep_status": r.status if r else "pending",
                    "stage": (r.stage or "") if r else "",
                    "run_id": r.id if r else None,
                    "lease_until": _iso(r.lease_until) if r else None,
                    "checkpoint": (r.checkpoint or "")[:300] if r else ""})
    return {"items": out[:80]}


@router.get("/prompt")
def agent_prompt(request: Request, style: str = "long"):
    base = str(request.base_url).rstrip("/")
    if style == "short":
        return {"prompt": f"""# Zcode 单候选短会话（窗口只有 10–24 分钟）

你是平台的深挖 worker。一个窗口只处理一个候选，不要读整个仓库。

1. 领任务（先动态，失败再静态）：
   TOKEN="${{PLATFORM_TOKEN:-$(cat ./.iseecode_agent_token 2>/dev/null || cat /tmp/isee_token 2>/dev/null || true)}}"
   test -n "$TOKEN" || {{ echo "missing .iseecode_agent_token / /tmp/isee_token"; exit 1; }}
   curl -s -H "Authorization: Bearer $TOKEN" '{base}/api/agent/next?mode=dynamic&session=zcode-$RANDOM'
   若 status != ok，再执行同一条命令但把 mode=dynamic 换成 mode=static；两个都不是 ok 就结束。
2. 下载 pack_url 并解压；读 environment.json 和 checkpoint。
3. 只处理 1 个候选：
   - runtime_ready=true：用 environment.json 的 agent_token 调 /api/tasks/<id>/agent-request 或 agent-exec，
     记录请求/响应/回显；成功则输出 chain JSON（entry→source→transform→sink→verify）。
   - runtime_ready=false：只读 pack 内 source/ 与报告做静态复核，**不要声称动态复现**，
     chain 的 verified 写 false，不要把静态猜测写成 verified。
4. 把结果写 progress（body 带 stage：triage/exploit/verify/judge）：
   POST {base}/api/agent/runs/<run_id>/progress
   body 里带 checkpoint（含 chain JSON）。
5. 若候选已处理完或时间到：POST /complete（checkpoint 至少 50 字符，含 RESULT_JSON 摘要）。
   不要遍历工作目录，不要联网查 PoC/CVE 利用代码，不要使用宿主 root/SSH 密码。
""", "base_url": base, "style": "short"}
    text = f"""# Zcode 夜间自动深挖 Worker v2（每窗口一个任务，10–24 分钟）

你是平台的自动化深挖 worker。每个新窗口只做一个任务，目标是“证实/排除候选 + 同攻击面找新漏洞 + 输出利用链”，不是全仓库重扫。不要等待用户确认，不要联网搜索 CVE/PoC/公开利用代码。

## 0. 时间预算

- 一个窗口 10–24 分钟，只做 1 个任务；每处理完一个候选就写 progress。
- 时间不够或窗口即将断开：把已完成结论和 chain JSON 写进 checkpoint，结束；下一个窗口会续跑。
- 不要为了“做完”而编造；没证据就写 unverified / blocked。

## 0.5 四阶段（每次 progress 必须带 stage）

按 `triage → exploit → verify → judge` 推进，不要跳阶段：
- **triage**：读包与清单，选 1–2 个高价值候选；记录候选、入口、为什么可疑、下一步。
- **exploit**：追 source→sink，构造 payload/利用链；把计划写进 checkpoint（stage=exploit）。
- **verify**：动态任务用沙箱 agent-request/exec；静态任务只做静态复核并标 blocked；记录请求/响应/回显（stage=verify）。
- **judge**：复核结论、定级、输出 RESULT_JSON（含 chain）；stage=judge，然后调用 /complete（平台会把 stage 置 done）。
- 静态任务没有沙箱：verify 阶段写“blocked/仅静态”，**不要伪造动态复现**。

## 1. 领取任务（动态优先，空闲领静态积压）

TOKEN 在项目根目录 `.iseecode_agent_token`（平台 AUTH_TOKEN，不是宿主 root）：
```bash
TOKEN="${{PLATFORM_TOKEN:-$(cat ./.iseecode_agent_token 2>/dev/null || cat /tmp/isee_token 2>/dev/null || true)}}"
test -n "$TOKEN" || {{ echo "missing .iseecode_agent_token / /tmp/isee_token"; exit 1; }}
curl -s -H "Authorization: Bearer $TOKEN" '{base}/api/agent/next?mode=dynamic&session=zcode-$RANDOM'
```
- status=ok：记下 run_id/task_id/pack_url/checkpoint。
- status=idle 或 busy：再执行同一条命令，但 `mode=dynamic` 换成 `mode=static`，领取 50+ 个静态积压任务之一。
- 两个都 idle/busy：直接结束本窗口。
- 静态任务没有沙箱：runtime_ready=false，只做静态深审，**不要声称动态复现**。

## 2. 下载并读深挖包

```bash
curl -s -H "Authorization: Bearer $TOKEN" -o /tmp/pack.zip "<pack_url>"
unzip -o /tmp/pack.zip -d /tmp/pack
```
先读 `README_AGENT.md`、`evidence.json`、`hotlist.md`、`authz_inventory.md`、`codeql_flows.md`（如果有）、`report.md`、`environment.json`。checkpoint 非空时接着上次候选继续，不要从头重跑。

## 3. 审计方法（source→sink，按优先级）

1. 从路由/控制器找入口：方法、路径、参数、鉴权中间件、预期角色。
2. 对每个候选追 source（用户可控参数）→ 传播/过滤 → sink（exec/eval/反序列化/文件/模板/SQL/HTTP 客户端）。
3. 优先顺序：未授权/越权/IDOR → RCE/命令执行 → 文件读写/上传/遍历 → SSRF/XXE/反序列化 → SQLi/XSS/模板注入。
4. CodeQL 路径（`codeql_flows.md`）优先当起点：它给的是 source→sink 的跨函数路径；逐跳核对代码是否真的可达、是否有过滤。
5. 每个候选最多 2 个假设；连续 2 次没有新证据就记录原因换下一个，不要重复同一条路。
6. 动态任务：用 `environment.json` 的 agent_token 调 `/api/tasks/<id>/agent-request` / `agent-exec`（container-only）。沙箱不可用时记录 blocked，继续做静态复核，不要反复重试。
7. 静态任务：只读 pack 内 `source/`、报告和清单；禁止遍历当前工作目录；所有结论必须落 `文件:行` 并引用真实代码。

## 4. 利用链输出（重要）

复现成功（拿到命令回显/敏感数据/越权响应）时必须输出 chain JSON，平台会落库并画节点图：

```json
{{"chain": {{
  "title": "一句话描述链",
  "verified": true,
  "nodes": [
    {{"id": "entry", "type": "entry", "label": "POST /api/x", "evidence": "匿名可达/鉴权情况"}},
    {{"id": "src", "type": "source", "label": "参数 user 可控", "file": "相对路径", "line": 0, "code": "实际代码行", "evidence": "请求示例"}},
    {{"id": "tr", "type": "transform", "label": "拼接/过滤", "file": "相对路径", "line": 0, "code": "实际代码行", "evidence": "传播说明"}},
    {{"id": "sink", "type": "sink", "label": "exec/eval/文件操作", "file": "相对路径", "line": 0, "code": "实际代码行", "evidence": "触发原因"}},
    {{"id": "ver", "type": "verify", "label": "回显 uid=0 / 读到敏感数据", "evidence": "请求/响应摘要"}}
  ],
  "edges": [{{"from": "entry", "to": "src"}}, {{"from": "src", "to": "tr"}}, {{"from": "tr", "to": "sink"}}, {{"from": "sink", "to": "ver"}}]
}}}}
```
- 只有拿到动态证据才写 `verified: true`；静态任务或未复现写 `verified: false`，不要伪造 verify 节点。
- 每个节点的 file/line 必须真实存在；不知道就留空并标 unverified。

## 5. 写回与完成

每完成一个候选：
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{{"checkpoint":"第 N 个：结论...\\nchain: {{...}}","stage":"verify","status":"running"}}' \\
  '{base}/api/agent/runs/<run_id>/progress'
```
全部候选处理完（或时间到）：
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{{"checkpoint":"RESULT_JSON {{...}} 最终摘要：verified/false_positive/unverified 数量与关键发现","stage":"judge"}}' \\
  '{base}/api/agent/runs/<run_id>/complete'
```
checkpoint 至少 50 字符；`RESULT_JSON` 里的 findings 按平台 `result_schema.json`，成功链附 `chain`。

## 5.5 链验证 API（阶段 3 v2）

平台已提供沙箱链验证；找到 payload 后优先用它拿动态证据：
```bash
# 1) 取链 id
curl -s -H "Authorization: Bearer $TOKEN" '{base}/api/tasks/<task_id>/chains'
# 2) 指定请求验证
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{{"method":"GET","path":"/read","params":{{"file":"/etc/passwd"}},"expect_contains":"root:","expect_status":200,"note":"file read"}}' \
  '{base}/api/tasks/<task_id>/chains/<chain_id>/verify'
```
- 成功返回 `verified=true`，平台把链标绿并写入“动态复现”库；
- 文件读取类链可直接 POST `{{}}` 使用内置 `/etc/passwd` 模板；
- 其他类型必须给 method/path/params/expect_*，不要用“能访问”冒充“已复现”。

## 6. 禁止事项

- 不使用宿主 root/SSH 密码；只用任务级 agent_token。
- 不联网查 CVE/PoC/公开利用代码；不引用网上 exp。
- 不编造文件、行号、请求或响应；不把静态猜测写成 verified。
- 不重复失败路径，不遍历整个仓库，不批量导出真实数据。
"""
    return {"prompt": text, "base_url": base}
