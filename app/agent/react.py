"""ReAct 审计 Agent 循环（升级阶段 3）：Thought → ToolCall → Observation → 结论"""
import json
import logging
import time

from app.config import AGENT_MAX_STEPS

log = logging.getLogger("agent.react")

SYSTEM_PROMPT = """你是资深代码安全审计 Agent。对给定的静态扫描疑似漏洞进行深度研判：
1) 用 read_file 读漏洞上下文；2) 判断数据来源是否用户可控；3) 用 call_chain/search 跨文件追踪污点与过滤；
4) 用 route_map 确认可达性；5) 有 http_request/sandbox_exec 工具时构造 payload 动态验证（只针对本地沙箱，禁止外网）。
效率要求：每步必须有新进展（读新文件/新行/发起新动态验证）；若连续两步无新进展，直接调用 write_finding 下结论，避免无效循环。
每步只输出一个 JSON 对象（不要多余文本）：
{"thought": "简短思考", "tool": "工具名", "args": {...}}
当能下结论时调用 write_finding 工具：
{"thought": "总结", "tool": "write_finding", "args": {"verdict": "verified|false_positive|unverified",
 "exploitability": "high|medium|low|none", "payload": "验证payload或空", "confidence": "high|medium|low",
 "precondition": "复现条件：触发前提（如 匿名可达，无需登录 / 需登录管理员 / 需订单号存在数据库），无法确认写 待确认",
 "evidence": "证据链：source→中间处理→sink 行→动态结果（简洁中文）", "reason": "结论理由（中文）"}}"""

AVAILABLE_TOOLS_DESC = ""

FULL_AUDIT_SYSTEM_PROMPT = """你是资深代码安全审计专家，对给定源码目录执行全量人工审计（不受静态扫描命中行限制）。
目标：发现所有可利用漏洞，包括但不限于：
- 未授权访问/越权：路由/接口缺少登录鉴权、IDOR、直接调用内部方法
- 注入类：SQLi、命令注入、代码注入（eval/assert/create_function）、SSTI、XXE、反序列化（unserialize/yaml.load/pickle）
- 文件类：任意文件读取/写入/删除/上传、路径穿越、zip 解压陷阱、phar:// 触发
- SSRF / 开放重定向 / 不安全的反序列化入口
- 危险函数：eval/system/exec/passthru/shell_exec/proc_open/popen/assert/反序列化触发链
- 业务逻辑漏洞：支付金额可控、越权操作、验证码/鉴权绕过、竞态
- 链式利用：多个小问题组合成 RCE/任意文件读取
方法要求：
1) 先用 file_tree/list_dir 建立完整文件清单，标注哪些文件已审；优先审计路由/控制器/入口文件与含危险函数的文件
2) 用 read_file 读关键文件；用 search/call_chain/route_map 跨文件追踪 source→sink 与过滤逻辑
3) 有 http_request/sandbox_exec 工具时，构造 payload 动态验证（仅针对本地沙箱，禁止外网）
4) 每个漏洞必须给出精确的 file_path/line、漏洞类型与可复现 payload；过滤存在时写明绕过方式
输出要求：审计完成（或步数将尽）时调用 write_finding 提交 findings 数组；数组元素字段：
{"file_path","line","rule_id"(agent-discovered-sqli / -rce / -command / -file-read / -file-delete / -file-write / -unauth / -idor / -ssrf / -xxe / -deserialization / -ssti / -logic 等),"severity"(CRITICAL|HIGH|MEDIUM|LOW),"verdict"(verified|false_positive),"exploitability"(high|medium|low|none),"confidence","payload","precondition"(复现条件：认证要求/数据依赖/环境依赖，如 匿名可达 / 需登录学生账号),"evidence"(source→过滤→sink→动态验证结果，简洁中文),"reason"}
只提交 verified 的漏洞；未复现/存疑的不提交。没有新漏洞也要调用 write_finding 提交空 findings 数组。
每步只输出一个 JSON 对象（不要多余文本）：{"thought":"简短思考","tool":"工具名","args":{...}}"""


# ---------------- 阶段 4 v2：四阶段 + 工具子集 ----------------
STAGE_ORDER = ("triage", "exploit", "verify", "judge")
STAGE_RATIO = {"triage": 0.20, "exploit": 0.30, "verify": 0.30, "judge": 0.20}
STAGE_MAX_STEPS = {"triage": 4, "exploit": 5, "verify": 6, "judge": 2}
STAGE_TOOLS = {
    "triage": {"file_tree", "read_file", "search", "list_dir", "call_chain",
               "route_map", "run_semgrep_subset"},
    "exploit": {"read_file", "search", "call_chain", "route_map", "run_semgrep_subset"},
    "verify": {"http_request", "sandbox_exec", "read_file"},
    "judge": set(),
}

STAGE_PROMPTS = {
    "triage": """当前阶段：triage（初筛）。只读静态上下文，不要发动态请求。
判断：参数是否用户可控、是否有明显过滤/鉴权、是否值得进入 exploit。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"worth":true|false,"reason":"一句话","context":"关键文件:行、调用链、可疑点"}}
最多 4 步；没有证据不要编造。""",
    "exploit": """当前阶段：exploit（构造利用路径）。只做静态分析，不发请求。
输出 source→sink 路径、过滤/绕过、payload 草案、前置条件（匿名/登录/管理员）。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"plan":"步骤","payload":"payload或空","precondition":"...","evidence":"代码证据"}}
最多 5 步。""",
    "verify": """当前阶段：verify（沙箱验证）。只使用 http_request / sandbox_exec 对本地沙箱验证。
记录真实的 method/path/params/body 与响应；成功才 verified=true。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"verified":true|false,"request":"...","response":"...","evidence":"回显/延时/回调","reason":"失败原因"}}
最多 6 步；沙箱不可用直接 false + reason。""",
    "judge": """当前阶段：judge（终审）。本阶段没有工具。
根据 triage/exploit/verify 的证据给出最终结论，调用 write_finding：
{"thought":"总结","tool":"write_finding","args":{"verdict":"verified|false_positive|unverified",
 "exploitability":"high|medium|low|none","payload":"...","confidence":"high|medium|low",
 "precondition":"...","evidence":"...","reason":"..."}}
只依据已有证据；verify 未成功不要写 verified。""",
}

# ---------------- 全量审计四阶段 ----------------
FULL_STAGES = ("recon", "hunt", "verify", "judge")
FULL_STAGE_RATIO = {"recon": 0.15, "hunt": 0.40, "verify": 0.25, "judge": 0.20}
FULL_STAGE_MAX_STEPS = {"recon": 6, "hunt": 10, "verify": 8, "judge": 3}
FULL_STAGE_TOOLS = {
    "recon": {"file_tree", "list_dir", "search", "route_map", "read_file", "call_chain"},
    "hunt": {"read_file", "search", "call_chain", "route_map", "run_semgrep_subset", "list_dir"},
    "verify": {"http_request", "sandbox_exec", "read_file"},
    "judge": set(),
}
FULL_STAGE_PROMPTS = {
    "recon": """当前阶段：recon（全量审计初筛）。先建立文件/路由清单，选 5–10 个高价值文件或攻击面。
不要提交漏洞，不要发动态请求。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"targets":[{"file":"相对路径","why":"可疑原因"}],"plan":"下一阶段审计顺序"}}
最多 6 步。""",
    "hunt": """当前阶段：hunt（逐点审计）。围绕 targets 用静态工具追踪 source→sink；只用代码证据，不动态验证。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"findings":[{"file_path":"...","line":0,
"rule_id":"agent-discovered-...","severity":"CRITICAL|HIGH|MEDIUM|LOW","verdict":"candidate",
"payload":"草案或空","precondition":"...","evidence":"source→sink 代码证据","reason":"..."}],"context":"..."}}
最多 10 步、最多 12 条；没有新漏洞就提交空 findings。""",
    "verify": """当前阶段：verify（沙箱验证）。候选按 file:line 用 http_request/sandbox_exec 验证；
只允许本地沙箱；没有工具或沙箱不可用直接 stage_done 空 results。
完成时只调用 stage_done：
{"thought":"...","tool":"stage_done","args":{"results":[{"file_path":"...","line":0,
"verified":true|false,"request":"...","response":"...","evidence":"...","reason":"失败原因"}]}}
最多 8 步；不要伪造回显。""",
    "judge": """当前阶段：judge（全量审计终审）。本阶段没有工具。
合并 hunt findings 与 verify results，只提交有证据的漏洞；调用 write_finding 提交 findings 数组：
{"thought":"总结","tool":"write_finding","args":{"findings":[{"file_path":"...","line":0,
"rule_id":"agent-discovered-...","severity":"CRITICAL|HIGH|MEDIUM|LOW","verdict":"verified",
"exploitability":"high|medium|low|none","confidence":"high|medium|low","payload":"...",
"precondition":"...","evidence":"source→sink→动态证据","reason":"..."}],"reason":"本轮摘要"}}
verify 未成功/无动态证据的不要写 verified。没有漏洞也要提交空 findings 数组。""",
}


def _est_tokens(text: str) -> int:
    """token 估算（CJK 感知）：中文约 0.7 token/字，ASCII 约 1 token/3.5 字符。
    旧版 len//3 对纯中文低估约 2 倍，导致预算控制虚高。"""
    t = str(text or "")
    if not t:
        return 1
    cjk = sum(1 for ch in t if '\u2e80' <= ch <= '\u9fff' or '\uff00' <= ch <= '\uffef')
    other = len(t) - cjk
    return max(1, int(cjk * 0.7 + other / 3.5))


def _chat(client, model: str, messages: list) -> str:
    """调用 LLM；推理型模型（reasoner/r1/o3 等）不支持 temperature 参数，自动省略"""
    kwargs = {"model": model, "messages": messages}
    if not any(t in model.lower() for t in ("reasoner", "r1", "o1", "o3", "thinking")):
        kwargs["temperature"] = 0
    resp = client.chat.completions.create(**kwargs)
    # 真实记账：API 返回的实际用量（含每步重发的全部上下文）。
    # 旧版按字符估算，实测低估真实消耗约 10 倍以上（用户账单 2000 万 vs 平台显示 147 万）。
    used = 0
    try:
        used = int(resp.usage.total_tokens or 0)
    except Exception:
        used = 0
    return resp.choices[0].message.content or "", used


def _parse_step(text: str) -> dict | None:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```")[1].lstrip("json\r\n")
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        return json.loads(t[i: j + 1])
    except json.JSONDecodeError:
        return None


class AgentResult:
    def __init__(self):
        self.verdict = "unverified"
        self.exploitability = "none"
        self.evidence = ""
        self.payload = ""
        self.confidence = "low"
        self.precondition = ""
        self.reason = ""
        self.steps_used = 0
        self.tokens_used = 0
        self.stages = {}


def _run_stage(stage: str, vuln_desc: str, prior: list, tools: dict, client, model: str,
               token_budget: int, max_steps: int, log_fn,
               system_prompt: str | None = None,
               allowed_names: set | None = None) -> tuple[dict, int]:
    """单个阶段的 mini ReAct：只允许本阶段工具，stage_done/write_finding 结束。"""
    allowed = allowed_names if allowed_names is not None else STAGE_TOOLS.get(stage, set())
    stage_tools = {k: v for k, v in tools.items() if k in allowed}
    tool_desc = "\n".join(f"- {n}: {d}" for n, (_, d) in stage_tools.items()) or "（本阶段无工具）"
    sys_prompt = (system_prompt or STAGE_PROMPTS[stage]) + "\n\n可用工具:\n" + tool_desc
    user = vuln_desc
    if prior:
        user += "\n\n前序阶段证据：\n" + "\n".join(prior)[-3000:]
    messages = [{"role": "system", "content": sys_prompt},
                {"role": "user", "content": user}]
    tokens = _est_tokens(sys_prompt) + _est_tokens(user)
    for step in range(1, max_steps + 1):
        if tokens >= token_budget:
            return {"error": "budget", "reason": f"{stage} 阶段预算耗尽"}, tokens
        try:
            text, real_used = _chat(client, model, messages)
            tokens += real_used if real_used else _est_tokens(text) + 50
        except Exception as e:
            return {"error": "llm", "reason": f"{stage} LLM 调用失败: {e}"}, tokens
        data = _parse_step(text)
        if data is None:
            messages.append({"role": "assistant", "content": text[:500]})
            messages.append({"role": "user", "content": "输出格式错误，请输出 JSON：{\"thought\":..., \"tool\":..., \"args\":{...}}"})
            continue
        tool = str(data.get("tool", "")).strip()
        args = data.get("args") or {}
        if tool == "stage_done" or (stage == "judge" and tool == "write_finding"):
            log_fn(f"[{stage}] step{step}: {tool}")
            return args, tokens
        item = stage_tools.get(tool)
        if item is None:
            obs = f"ERROR: 当前阶段不可用工具 {tool}，可用: {', '.join(stage_tools) or '无'}"
        else:
            fn, _ = item
            try:
                obs = str(fn(**args))[:3000]
            except Exception as e:
                obs = f"ERROR: 工具执行异常: {e}"
        log_fn(f"[{stage}] step{step}: {tool} {json.dumps(args, ensure_ascii=False)[:120]}")
        tokens += _est_tokens(obs)
        messages.append({"role": "assistant", "content": json.dumps(data, ensure_ascii=False)[:1000]})
        if len(messages) > 18:
            messages = messages[:2] + messages[-16:]
        messages.append({"role": "user", "content": f"Observation:\n{obs}\n\n继续（或 stage_done 结束本阶段）。"})
    return {"error": "steps", "reason": f"{stage} 阶段步数耗尽"}, tokens


def run_agent(vuln: dict, tools: dict, client, model: str, token_budget: int,
              log_fn=None, max_steps: int | None = None) -> AgentResult:
    """阶段 4 v2：triage → exploit → verify → judge 四阶段编排。
    每个阶段只拿到自己的工具子集，token 预算按 20/30/30/20 分配。"""
    max_steps = max_steps or AGENT_MAX_STEPS
    log_fn = log_fn or (lambda m: None)
    result = AgentResult()
    vuln_desc = (f"疑似漏洞: 规则 {vuln['rule_id']} 严重性 {vuln['severity']}\n"
                 f"位置: {vuln['file_path']}:{vuln['line']}\n"
                 f"代码片段:\n{vuln['code_snippet'][:800]}\n扫描器说明: {vuln.get('message', '')}")
    prior, stages = [], {}
    remaining = max(1, int(token_budget))
    worth, verify_ok = True, False
    for stage in STAGE_ORDER:
        if stage in ("exploit", "verify") and not worth:
            stages[stage] = {"skipped": "triage 判定不值得深挖"}
            continue
        if stage == "verify" and not (set(tools) & {"http_request", "sandbox_exec"}):
            stages[stage] = {"skipped": "无沙箱工具"}
            continue
        budget = max(300, int(token_budget * STAGE_RATIO[stage]))
        budget = min(budget, remaining) if remaining > 0 else 0
        if budget <= 0:
            stages[stage] = {"skipped": "总预算耗尽"}
            continue
        stage_steps = max(1, min(STAGE_MAX_STEPS[stage], max_steps))
        args, used = _run_stage(stage, vuln_desc, prior, tools, client, model,
                                budget, stage_steps, log_fn)
        result.tokens_used += used
        remaining -= used
        stages[stage] = {"args": args, "tokens": used}
        if stage == "triage":
            worth = bool(args.get("worth", True))
            if args.get("reason"):
                prior.append("triage: " + str(args["reason"])[:500])
            if args.get("context"):
                prior.append("context: " + str(args["context"])[:1500])
        elif stage == "exploit":
            if args.get("payload"):
                result.payload = str(args["payload"])[:500]
            if args.get("precondition"):
                result.precondition = str(args["precondition"])[:500]
            if args.get("plan") or args.get("evidence"):
                prior.append("exploit: " + json.dumps(args, ensure_ascii=False)[:1500])
        elif stage == "verify":
            verify_ok = bool(args.get("verified"))
            prior.append("verify: " + json.dumps(args, ensure_ascii=False)[:1800])
        elif stage == "judge":
            if args.get("error"):
                result.reason = str(args.get("reason") or "judge 阶段未完成")[:1000]
            else:
                verdict = str(args.get("verdict", "unverified"))
                result.verdict = verdict if verdict in ("verified", "false_positive", "unverified") else "unverified"
                result.evidence = str(args.get("evidence", ""))[:4000]
                result.payload = str(args.get("payload", "") or result.payload)[:500]
                result.precondition = str(args.get("precondition", "") or result.precondition)[:500]
                result.confidence = str(args.get("confidence", "low"))[:8]
                explo = str(args.get("exploitability", "none")).lower()
                result.exploitability = explo if explo in ("high", "medium", "low", "none") else "none"
                result.reason = str(args.get("reason", ""))[:1000]
            break
    if not result.reason:
        result.reason = ("阶段化 Agent 未完成 judge（verify_ok=%s）" % verify_ok)[:1000]
    result.stages = stages
    return result


def run_full_audit_round(tools: dict, client, model: str, token_budget: int, log_fn=None,
                         round_no: int = 1, context: str = "",
                         max_steps: int | None = None) -> dict:
    """全量审计单轮（阶段 4 v2）：recon → hunt → verify → judge。
    返回 {"findings": [...], "tokens_used": int, "reason": str, "stages": {...}}"""
    max_steps = max_steps or AGENT_MAX_STEPS
    log_fn = log_fn or (lambda m: None)
    base_desc = (f"全量审计第 {round_no} 轮。{context}").strip()
    prior, stage_results = [], {}
    tokens, remaining = 0, max(1, int(token_budget))
    findings, reason = [], ""
    for stage in FULL_STAGES:
        if stage == "verify" and not (set(tools) & {"http_request", "sandbox_exec"}):
            stage_results[stage] = {"skipped": "无沙箱工具"}
            continue
        budget = max(500, int(token_budget * FULL_STAGE_RATIO[stage]))
        budget = min(budget, remaining) if remaining > 0 else 0
        if budget <= 0:
            stage_results[stage] = {"skipped": "总预算耗尽"}
            continue
        stage_steps = max(1, min(FULL_STAGE_MAX_STEPS[stage], max_steps))
        args, used = _run_stage(stage, base_desc, prior, tools, client, model,
                                budget, stage_steps, log_fn,
                                system_prompt=FULL_STAGE_PROMPTS[stage],
                                allowed_names=FULL_STAGE_TOOLS[stage])
        tokens += used
        remaining -= used
        stage_results[stage] = {"args": args, "tokens": used}
        if args.get("error"):
            prior.append(f"{stage} error: {args.get('reason')}")
            continue
        if stage == "recon":
            prior.append("recon targets: " + json.dumps(args.get("targets") or [], ensure_ascii=False)[:2000])
            if args.get("plan"):
                prior.append("plan: " + str(args["plan"])[:1000])
        elif stage == "hunt":
            hunt_findings = args.get("findings") or []
            if not isinstance(hunt_findings, list):
                hunt_findings = []
            prior.append("hunt findings: " + json.dumps(hunt_findings, ensure_ascii=False)[:4000])
            if args.get("context"):
                prior.append("context: " + str(args["context"])[:1500])
        elif stage == "verify":
            results = args.get("results") or []
            if not isinstance(results, list):
                results = []
            prior.append("verify results: " + json.dumps(results, ensure_ascii=False)[:4000])
        elif stage == "judge":
            raw = args.get("findings") or ([args] if args.get("file_path") else [])
            for f in raw:
                if not isinstance(f, dict) or not f.get("file_path"):
                    continue
                if f.get("verdict") not in (None, "verified"):
                    continue
                findings.append(f)
            reason = str(args.get("reason", ""))[:500]
            break
    if not reason:
        reason = f"第 {round_no} 轮未完成 judge（阶段：{','.join(stage_results)}）"
    log_fn(f"round{round_no} 完成：提交 {len(findings)} 条候选（{reason}）")
    return {"findings": findings, "tokens_used": tokens,
            "reason": reason, "stages": stage_results}
