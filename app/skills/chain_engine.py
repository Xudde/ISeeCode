# -*- coding: utf-8 -*-
"""利用链引擎 v1（阶段 3）：把“鉴权语义入口”与“sink 候选”按模板拼成链。

只生成静态链候选（verified=false），节点包含 entry/source/sink/verify；
动态验证仍由 AI/沙箱完成，成功后才写 verified=true。
"""
import json
import re

from app.models import AuthzEndpoint, ExploitChain, Vulnerability

PUBLIC_HINTS = ("login", "logout", "register", "signup", "health", "ready",
                "metrics", "swagger", "openapi", "docs", "static", "favicon",
                "public", "captcha")
# (类别, sink 正则, 路径提示, 节点标题)
CATEGORIES = [
    ("code_exec", re.compile(r"(exec|eval|command|rce|deserial|template|code injection|dynamic method|unvalidated dynamic|反序列化|命令执行|代码执行)", re.I),
     ("run", "exec", "command", "script", "shell", "cmd", "upload", "config", "plugin", "task"),
     "未授权入口 → 代码执行 sink"),
    ("file_read", re.compile(r"(traversal|path injection|lfi|file read|readfile|任意文件|目录遍历|文件读取)", re.I),
     ("read", "file", "download", "export", "report", "backup", "template", "upload", "import"),
     "未授权入口 → 文件读取/遍历 sink"),
    ("ssrf", re.compile(r"(ssrf|server-side request|请求伪造)", re.I),
     ("fetch", "url", "proxy", "webhook", "remote", "image", "avatar", "import", "upload"),
     "未授权入口 → SSRF sink"),
    ("upload", re.compile(r"(upload|file write|writefile|unzip|extract|文件上传|任意写)", re.I),
     ("upload", "attachment", "media", "file", "import"),
     "未授权入口 → 文件上传/写入 sink"),
    ("idor", re.compile(r"(idor|越权|unauthorized access|broken access)", re.I),
     ("{id}", "user", "order", "account", "admin", "profile", "record"),
     "越权入口 → 数据访问 sink"),
]


def _entry_score(e: AuthzEndpoint) -> int:
    low = (e.path or "").lower()
    score = 0
    if e.labels == "anonymous":
        score += 5
    elif e.labels == "conditional":
        score += 3
    if any(h in low for h in ("admin", "config", "system", "manage", "upload",
                              "file", "export", "download", "exec", "run",
                              "script", "command", "user", "order")):
        score += 3
    if any(h in low for h in PUBLIC_HINTS):
        score -= 5
    if e.confidence == "high":
        score += 1
    return score


def _pick_entry(entries: list[AuthzEndpoint], hints: tuple) -> AuthzEndpoint | None:
    scored = []
    primary, secondary = hints[:4], hints[4:]
    for e in entries:
        low = (e.path or "").lower()
        s = _entry_score(e)
        if any(h in low for h in primary):
            s += 8
        elif any(h in low for h in secondary):
            s += 1
        scored.append((s, e))
    scored.sort(key=lambda x: (-x[0], x[1].id))
    return scored[0][1] if scored and scored[0][0] > 0 else None


def _pick_sink(vulns: list[Vulnerability], pattern: re.Pattern) -> Vulnerability | None:
    hits = []
    for v in vulns:
        rid = (v.rule_id or "").lower()
        if rid.startswith(("giants:self-cve", "giants:trivy", "giants:gitleaks")):
            continue  # 依赖/配置/CVE 命中不是代码 sink
        if not v.file_path or int(v.line or 0) <= 0:
            continue
        blob = f"{v.rule_id or ''} {v.title or ''} {v.code_snippet or ''}"[:2000]
        if pattern.search(blob):
            hits.append(v)
    if not hits:
        return None
    rank = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "WARNING": 2, "MEDIUM": 2, "INFO": 3, "LOW": 4}
    hits.sort(key=lambda v: (rank.get((v.severity or "").upper(), 5), -v.id))
    return hits[0]


def generate_and_store(db, task_id: int, max_chains: int = 5) -> int:
    entries = db.query(AuthzEndpoint).filter(
        AuthzEndpoint.task_id == task_id,
        AuthzEndpoint.labels.in_(("anonymous", "conditional"))).all()
    vulns = [v for v in db.query(Vulnerability).filter(
        Vulnerability.task_id == task_id).all()
        if (v.agent_status or "") != "false_positive"]
    if not entries or not vulns:
        return 0
    created = 0
    for name, pat, hints, label in CATEGORIES:
        if created >= max_chains:
            break
        sink = _pick_sink(vulns, pat)
        if sink is None:
            continue
        entry = _pick_entry(entries, hints)
        if entry is None:
            continue
        title = f"{label}：{entry.method} {entry.path}"[:200]
        exists = db.query(ExploitChain).filter(
            ExploitChain.task_id == task_id, ExploitChain.title == title).first()
        if exists is not None:
            continue
        nodes = [
            {"id": "entry", "type": "entry",
             "label": f"{entry.method} {entry.path}",
             "file": entry.evidence_file, "line": entry.evidence_line,
             "evidence": f"鉴权标签={entry.labels}（{entry.confidence}）；{entry.note[:160]}"},
            {"id": "src", "type": "source", "label": "HTTP 参数/路径参数（待确认可控）",
             "evidence": "由入口进入；具体参数名需结合源码/请求确认"},
            {"id": "sink", "type": "sink", "label": (sink.title or sink.rule_id or "危险 sink")[:120],
             "file": sink.file_path, "line": sink.line,
             "code": (sink.code_snippet or "")[:200],
             "evidence": f"{sink.rule_id}；severity={sink.severity}"},
            {"id": "ver", "type": "verify", "label": "待动态验证",
             "evidence": "静态链候选：需在沙箱/AI 深挖中验证参数可控与触发条件"},
        ]
        edges = [{"from": "entry", "to": "src"}, {"from": "src", "to": "sink"},
                 {"from": "sink", "to": "ver"}]
        db.add(ExploitChain(task_id=task_id, title=title,
                            nodes_json=json.dumps(nodes, ensure_ascii=False),
                            edges_json=json.dumps(edges, ensure_ascii=False),
                            verified=False))
        created += 1
    if created:
        db.commit()
    return created


def _sandbox_handle(task):
    from app.skills import sandbox as sb
    if not getattr(task, "sandbox_cid", None) or not sb.is_running(task.sandbox_cid):
        raise RuntimeError("沙箱未运行或已退出")
    import docker
    client = docker.from_env()
    container = client.containers.get(task.sandbox_cid)
    if not getattr(task, "sandbox_port", None):
        raise RuntimeError("任务没有 sandbox_port")
    return sb.SandboxHandle(client, container, None, int(task.sandbox_port))


def auto_specs(chain: ExploitChain, port: int = 5000) -> list:
    """按链标题生成自动验证尝试（file_read/SSRF/upload/code_exec）。"""
    try:
        nodes = json.loads(chain.nodes_json or "[]")
    except Exception:
        nodes = []
    entry = next((n for n in nodes if n.get("type") == "entry"), None) or {}
    label = str(entry.get("label") or "")
    method = "POST" if label.upper().startswith("POST ") else "GET"
    path = label.split(" ", 1)[-1] if " " in label else label
    if path and not path.startswith("/"):
        path = "/" + path
    title = chain.title or ""
    marker = f"POC_MARKER_{chain.id}"
    base = {"method": method, "path": path}
    if "文件读取" in title:
        return [{**base, "params": {"file": "/etc/passwd"},
                 "expect_contains": "root:", "expect_status": 200,
                 "note": "文件读取模板：file=/etc/passwd"}]
    if "SSRF" in title or "ssrf" in title.lower():
        specs = []
        for k in ("url", "target", "src", "host", "uri", "endpoint", "feed"):
            specs.append({**base, "params": {k: f"http://127.0.0.1:{port}/"},
                          "expect_status": 200,
                          "note": f"SSRF 自引用模板 via {k}"})
        return specs
    if "文件上传" in title:
        return [{**base, "method": "POST",
                 "upload": {"field": f, "filename": "poc.txt", "content": marker},
                 "expect_contains": marker, "note": f"upload field={f}"}
                for f in ("file", "upload", "attachment", "files")]
    if "代码执行" in title:
        specs = []
        for key in ("cmd", "command", "code", "exec", "input", "payload", "script"):
            specs.append({**base, "params": {key: f"echo {marker}"},
                          "expect_contains": marker, "note": f"code_exec {key}"})
            specs.append({**base, "params": {key: f"; echo {marker}"},
                          "expect_contains": marker, "note": f"code_exec inject {key}"})
        return specs[:8]
    return []


def auto_spec(chain: ExploitChain) -> dict | None:
    specs = auto_specs(chain)
    return specs[0] if specs else None


def verify_chain(db, task, chain: ExploitChain, spec: dict | None = None) -> dict:
    """在任务沙箱内发一次 HTTP 请求验证链；成功后写 exploit_chains.verified 与动态复现漏洞。"""
    nodes = json.loads(chain.nodes_json or "[]")
    edges = json.loads(chain.edges_json or "[]")
    entry = next((n for n in nodes if n.get("type") == "entry"), None) or {}
    spec = spec or auto_spec(chain) or {}
    method = str(spec.get("method") or entry.get("method") or "GET").upper()
    path = str(spec.get("path") or (str(entry.get("label") or "").split(" ", 1)[-1]))
    if not path.startswith("/"):
        path = "/" + path
    params = spec.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    handle = _sandbox_handle(task)
    if "SSRF" in (chain.title or "") and not spec.get("expect_contains"):
        try:
            _st, base_body = handle.request("/", {}, method="GET")
            token = "".join(str(base_body or "").split())[:40]
            if token:
                spec["expect_contains"] = token
                spec.pop("expect_status", None)
        except Exception:
            pass
    up = spec.get("upload")
    if isinstance(up, dict):
        status, response = handle.upload_file(path, up.get("field") or "file",
                                              up.get("filename") or "poc.txt",
                                              str(up.get("content") or ""))
    else:
        status, response = handle.request(path, params, method=method)
    expect_status = spec.get("expect_status")
    expect_contains = str(spec.get("expect_contains") or "")
    if expect_status is None and not expect_contains:
        raise RuntimeError("需要 expect_status 或 expect_contains 才能判定验证结果")
    ok = True
    if expect_status is not None:
        try:
            ok = ok and int(status) == int(expect_status)
        except (TypeError, ValueError):
            ok = False
    if expect_contains:
        ok = ok and (expect_contains in (response or ""))
    evidence = (f"request: {method} {path} {json.dumps(params, ensure_ascii=False)[:200]}\n"
                f"response: HTTP {status}\n{(response or '')[:800]}")
    for n in nodes:
        if n.get("type") == "verify":
            n["label"] = ("验证成功：" + (spec.get("note") or f"HTTP {status}")) if ok else f"验证失败：HTTP {status}"
            n["evidence"] = evidence
    chain.verified = bool(ok)
    chain.nodes_json = json.dumps(nodes, ensure_ascii=False)[:20000]
    vuln_created = 0
    if ok:
        sink = next((n for n in nodes if n.get("type") == "sink"), {}) or {}
        fp = str(sink.get("file") or "")
        ln = int(sink.get("line") or 0)
        rule_id = f"chain:{chain.id}:{'file_read' if '文件读取' in (chain.title or '') else 'verify'}"[:128]
        exists = None
        if fp:
            exists = db.query(Vulnerability).filter(
                Vulnerability.task_id == task.id,
                Vulnerability.rule_id == rule_id,
                Vulnerability.file_path == fp,
                Vulnerability.line == ln).first()
        if exists is None:
            db.add(Vulnerability(
                task_id=task.id, source="chain", rule_id=rule_id,
                title=(chain.title or "利用链复现")[:128], severity="HIGH",
                file_path=fp[:512], line=ln,
                code_snippet=(sink.get("code") or sink.get("label") or "")[:1600],
                precondition=(spec.get("note") or "沙箱动态验证")[:512],
                poc_payload=(f"{method} {path} {json.dumps(params, ensure_ascii=False)}")[:2000],
                poc_verified=True,
                verify_result=(f"沙箱验证 HTTP {status}: {str(response or '')[:800]}")[:2000],
                agent_status="verified", agent_confidence="high",
                agent_evidence=evidence[:6000],
            ))
            vuln_created = 1
    db.add(chain)
    db.commit()
    return {"ok": True, "verified": bool(ok), "status": status,
            "response": (response or "")[:1000], "vuln_created": vuln_created,
            "method": method, "path": path, "params": params,
            "note": spec.get("note") or ""}
