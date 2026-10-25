"""Agent 审计 Orchestrator（升级阶段 3）：候选漏洞调度、预算/并发控制、结论写回"""
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import (AGENT_CONCURRENCY, AGENT_TOKEN_BUDGET,
                        FULL_AUDIT_ROUNDS, FULL_AUDIT_TOKEN_PER_ROUND, FULL_AUDIT_MAX_FINDINGS)
from app.agent import react, tools as agent_tools
from app.agent_settings import AGENT_SETTING_DEFAULTS
from app.db import SessionLocal
from app.models import Vulnerability
from app.skills.poc import normalize_payload

log = logging.getLogger("agent.orchestrator")

# 沙箱并发闸唯一定义在 agent/tools.py（此处不再重复创建，否则全局上限翻倍）
# token 预算全局记账（每任务）
_budget_lock = threading.Lock()


class Budget:
    """任务级 token 预算（软上限）：超限停止新开 Agent，已有 Agent 收尾"""

    def __init__(self, total: int = AGENT_TOKEN_BUDGET):
        self.total = total
        self.used = 0
        self.exhausted = False

    def consume(self, n: int) -> bool:
        with _budget_lock:
            self.used += n
            if self.used >= self.total:
                self.exhausted = True
            return not self.exhausted


def _settings_or_default(settings: dict | None) -> dict:
    """settings 为 None 时回落到 config.py 静态常量，保证默认行为不变。"""
    if settings:
        return settings
    return {
        "agent_max_vulns": AGENT_SETTING_DEFAULTS["agent_max_vulns"],
        "agent_max_steps": AGENT_SETTING_DEFAULTS["agent_max_steps"],
        "agent_concurrency": AGENT_CONCURRENCY,
        "agent_token_budget": AGENT_TOKEN_BUDGET,
        "full_audit_rounds": FULL_AUDIT_ROUNDS,
        "full_audit_token_per_round": FULL_AUDIT_TOKEN_PER_ROUND,
        "full_audit_max_findings": FULL_AUDIT_MAX_FINDINGS,
    }


def analyze_vulns(db: Session, vuln_rows, workspace: str, tech_stack: str,
                  handle=None, llm_cfg: dict = None, cancel_check=None, log_fn=None,
                  settings: dict | None = None) -> dict:
    """对候选漏洞批量执行 Agent 深度研判，写回 agent_* 字段。
    返回 {verified, false_positive, unverified, error} 计数。
    cancel_check：可选回调，返回 True 表示用户已请求停止，剩余候选不再分析。
    settings：Agent 引擎可调参数（并发/步数/token 预算），None 时用默认值。"""
    st = _settings_or_default(settings)
    from openai import OpenAI

    log_fn = log_fn or (lambda m: None)
    if cancel_check is not None and cancel_check():
        log_fn("检测到停止请求，跳过 Agent 研判")
        for row in vuln_rows:
            row.agent_status = "unverified"
            row.agent_reason = "任务已被用户停止，Agent 研判中止"
            row.analyzed_at = datetime.now()
        db.commit()
        return {"verified": 0, "false_positive": 0, "unverified": len(vuln_rows), "error": 0}
    client = OpenAI(base_url=llm_cfg["base_url"], api_key=llm_cfg["api_key"], timeout=90)
    model = llm_cfg.get("agent_model") or llm_cfg["model"]
    budget = Budget(total=st["agent_token_budget"])
    counts = {"verified": 0, "false_positive": 0, "unverified": 0, "error": 0}

    lang = (tech_stack or "unknown").split(",")[0]
    reg = agent_tools.build_tool_registry(workspace, lang, handle=handle)

    def work(row):
        """单条 Agent 分析；沙箱验证工具串行占用全局信号量"""
        if cancel_check is not None and cancel_check():
            return row, "unverified", "任务已被用户停止，Agent 研判中止", ""
        if budget.exhausted:
            return row, "unverified", f"任务 token 预算耗尽（已用 {budget.used}）", ""
        # 沙箱工具的动态验证受全局并发限制：简单包装——分析前先取信号量会阻塞太久，
        # 改为：无 handle 时纯静态；有 handle 时 3 线程并发阅读 + 2 并发动态（信号量在 http 工具内部）
        vuln_dict = {
            "rule_id": row.rule_id, "severity": row.severity,
            "file_path": row.file_path, "line": row.line,
            "code_snippet": row.code_snippet, "message": row.verify_result or "",
        }
        result = react.run_agent(vuln_dict, reg, client, model, budget.total - budget.used,
                                 log_fn, max_steps=st["agent_max_steps"])
        budget.consume(result.tokens_used)
        # 独立 Session 写回：Agent 并发线程共享同一 Session 会导致 commit 冲突
        # （SessionTransactionState.CLOSED），故每条结论由工作线程用独立会话落库。
        s = SessionLocal()
        try:
            r = s.get(type(row), row.id)
            if r is not None:
                r.agent_status = result.verdict
                r.agent_reason = result.reason[:1000]
                r.agent_confidence = getattr(result, "confidence", "low")[:8]
                explo = getattr(result, "exploitability", "")
                evid = getattr(result, "evidence", "")
                r.agent_evidence = (f"[exploitability={explo}] {evid}" if explo else evid)[:4000]
                precond = (getattr(result, "precondition", "") or "").strip()
                if precond and not (r.precondition or "").strip():
                    r.precondition = precond[:512]
                if result.verdict == "verified":
                    payload = getattr(result, "payload", "") or ""
                    if payload and not r.poc_payload:
                        r.poc_payload = normalize_payload(payload)[:500]
                    if evid:
                        r.verify_result = f"Agent 动态验证: {evid}"[:1000]
                r.analyzed_at = datetime.now()
                s.commit()
        finally:
            s.close()
        return row, result.verdict, result.reason, result

    with ThreadPoolExecutor(max_workers=st["agent_concurrency"]) as pool:
        futures = [pool.submit(work, row) for row in vuln_rows]
        for fut in as_completed(futures):
            try:
                row, verdict, reason, result = fut.result()
            except Exception as e:
                log.warning("Agent 分析异常: %s", e)
                counts["error"] += 1
                continue
            counts[verdict] = counts.get(verdict, 0) + 1
    # 记录 token 消耗到任务表（前端展示成本）
    try:
        if vuln_rows:
            t = db.get(Task, getattr(vuln_rows[0], "task_id", None))
            if t is not None:
                t.tokens_used = (t.tokens_used or 0) + int(budget.used)
                db.commit()
    except Exception:
        pass
    return counts


def full_audit(db: Session, task_id: int, workspace: str, tech_stack: str,
               handle=None, llm_cfg: dict = None, existing=None,
               cancel_check=None, log_fn=None, fingerprint_json: str = "",
               settings: dict | None = None) -> dict:
    """Agent 全量审计：不依赖 semgrep 命中行，Agent 自主遍历全部源码发现漏洞
    （未授权访问/逻辑/链式漏洞等静态规则难覆盖的类型）。发现的漏洞写入 Vulnerability 表，
    rule_id 前缀 agent-discovered-。existing: [(file_path, line, rule_id), ...] 用于去重。
    返回 {"found": n, "skipped": n, "error": n}。
    settings：Agent 引擎可调参数（轮次/每轮 token/每轮条数/步数），None 时用默认值。"""
    st = _settings_or_default(settings)
    from openai import OpenAI

    log_fn = log_fn or (lambda m: None)
    if cancel_check is not None and cancel_check():
        log_fn("检测到停止请求，跳过全量审计")
        return {"found": 0, "skipped": 0, "error": 0}
    if not workspace or not os.path.isdir(workspace):
        log_fn(f"工作区不存在，跳过全量审计: {workspace}")
        return {"found": 0, "skipped": 0, "error": 0}
    client = OpenAI(base_url=llm_cfg["base_url"], api_key=llm_cfg["api_key"], timeout=90)
    model = llm_cfg.get("agent_model") or llm_cfg["model"]
    lang = (tech_stack or "unknown").split(",")[0]
    reg = agent_tools.build_tool_registry(workspace, lang, handle=handle)

    seen = set()
    for fp, ln, rid in (existing or []):
        seen.add((fp, int(ln or 0)))
        if str(rid).startswith("agent-discovered"):
            seen.add((fp, int(ln or 0), rid))
    found, skipped, error = 0, 0, 0

    rounds = st["full_audit_rounds"]
    for rnd in range(1, rounds + 1):
        if cancel_check is not None and cancel_check():
            log_fn("检测到停止请求，中止全量审计")
            break
        ctx = (f"这是第 {rnd}/{rounds} 轮全量审计。"
               f"已确认 {found} 条新漏洞，请继续挖掘尚未覆盖的文件与攻击面；"
               f"不要重复提交已发现的 (file,line)。")
        if fingerprint_json:
            ctx += ("\n组件指纹（帮助判断框架与对应攻击面，如 Struts2→OGNL RCE、"
                    "ThinkPHP→RCE、Fastjson→反序列化、Pickle→反序列化等）：\n"
                    + fingerprint_json[:800])
        res = react.run_full_audit_round(reg, client, model, st["full_audit_token_per_round"],
                                         log_fn, rnd, ctx, max_steps=st["agent_max_steps"])
        # 每轮结束记录 token 消耗到任务表（前端展示成本）
        try:
            t = db.get(Task, task_id)
            if t is not None:
                t.tokens_used = (t.tokens_used or 0) + int(res.get("tokens_used", 0) or 0)
                db.commit()
        except Exception:
            pass
        for f in res.get("findings", [])[:st["full_audit_max_findings"]]:
            fp = str(f.get("file_path", ""))
            try:
                ln = int(f.get("line", 0) or 0)
            except (TypeError, ValueError):
                ln = 0
            key = (fp, ln)
            if key in seen:
                skipped += 1
                continue
            if key + (f.get("rule_id", ""),) in seen:
                skipped += 1
                continue
            seen.add(key)
            seen.add((fp, ln, str(f.get("rule_id", ""))))
            try:
                snippet = ""
                p = Path(workspace) / fp
                if p.is_file():
                    lines = p.read_text(errors="ignore").splitlines()
                    snippet = "\n".join(lines[max(0, ln - 3): ln + 2])
                row = Vulnerability(
                    task_id=task_id, source="agent-full",
                    rule_id=str(f.get("rule_id", "agent-discovered"))[:128],
                    severity=str(f.get("severity", "HIGH")).upper()[:16],
                    file_path=fp[:512], line=ln, code_snippet=snippet[:2000],
                    agent_status="verified",
                    agent_confidence=str(f.get("confidence", "medium"))[:8],
                    agent_reason=str(f.get("reason", ""))[:1000],
                    precondition=str(f.get("precondition", ""))[:512],
                    poc_payload=normalize_payload(str(f.get("payload", "")))[:500],
                    agent_evidence=(f"[exploitability={f.get('exploitability', 'none')}] "
                                    f"{f.get('evidence', '')}")[:4000],
                    verify_result=f"Agent 全量审计: {str(f.get('evidence', ''))[:200]}",
                    analyzed_at=datetime.now(),
                )
                db.add(row)
                found += 1
            except Exception as e:
                error += 1
                log_fn(f"全量审计落库失败: {e}")
        db.commit()
    return {"found": found, "skipped": skipped, "error": error}
