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
    return client.chat.completions.create(**kwargs).choices[0].message.content or ""


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


def run_agent(vuln: dict, tools: dict, client, model: str, token_budget: int,
              log_fn=None, max_steps: int | None = None) -> AgentResult:
    """对单条疑似漏洞执行 ReAct 循环。tools: {name: (func, desc)}
    max_steps：单条步数硬上限（None 时用默认 AGENT_MAX_STEPS）。"""
    max_steps = max_steps or AGENT_MAX_STEPS
    log_fn = log_fn or (lambda m: None)
    result = AgentResult()
    tool_desc = "\n".join(f"- {name}: {desc}" for name, (_, desc) in tools.items())
    sys_prompt = SYSTEM_PROMPT + "\n\n可用工具:\n" + tool_desc
    tokens = _est_tokens(sys_prompt)

    vuln_desc = (f"疑似漏洞: 规则 {vuln['rule_id']} 严重性 {vuln['severity']}\n"
                 f"位置: {vuln['file_path']}:{vuln['line']}\n"
                 f"代码片段:\n{vuln['code_snippet'][:800]}\n扫描器说明: {vuln.get('message', '')}")
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": vuln_desc},
    ]

    for step in range(1, max_steps + 1):
        if tokens >= token_budget:
            result.reason = f"token 预算耗尽（{tokens}），标记 unverified"
            log_fn(result.reason)
            break
        result.steps_used = step
        try:
            text = _chat(client, model, messages)
        except Exception as e:
            result.reason = f"LLM 调用失败: {e}"
            log_fn(result.reason)
            break
        tokens += _est_tokens(text) + 50
        step_data = _parse_step(text)
        if step_data is None:
            messages.append({"role": "assistant", "content": text[:500]})
            messages.append({"role": "user", "content": "输出格式错误，请输出 JSON：{\"thought\":..., \"tool\":..., \"args\":{...}}"})
            continue

        tool = str(step_data.get("tool", "")).strip()
        args = step_data.get("args") or {}
        if tool == "write_finding":
            verdict = str(args.get("verdict", "unverified"))
            result.verdict = verdict if verdict in ("verified", "false_positive", "unverified") else "unverified"
            result.evidence = str(args.get("evidence", ""))[:4000]
            result.payload = str(args.get("payload", ""))[:500]
            result.precondition = str(args.get("precondition", ""))[:500]
            result.confidence = str(args.get("confidence", "low"))[:8]
            explo = str(args.get("exploitability", "none")).lower()
            result.exploitability = explo if explo in ("high", "medium", "low", "none") else "none"
            result.reason = str(args.get("reason", ""))[:1000]
            tokens += _est_tokens(result.evidence)
            result.tokens_used = tokens
            return result

        item = tools.get(tool)
        if item is None:
            obs = f"ERROR: 未知工具 {tool}，可用: {', '.join(tools)}"
        else:
            fn, _ = item  # 注册表格式 {name: (func, desc)}，必须解包后调用
            try:
                obs = str(fn(**args))[:3000]
            except Exception as e:
                obs = f"ERROR: 工具执行异常: {e}"
        log_fn(f"step{step}: {tool} {json.dumps(args, ensure_ascii=False)[:120]}")
        tokens += _est_tokens(obs)
        messages.append({"role": "assistant", "content": json.dumps(step_data, ensure_ascii=False)[:1000]})
        # 上下文裁剪：保留 system + 首条 user + 最近 8 轮
        if len(messages) > 18:
            messages = messages[:2] + messages[-16:]
        messages.append({"role": "user", "content": f"Observation:\n{obs}\n\n继续下一步（或 write_finding 下结论）。"})

    result.tokens_used = tokens
    if not result.reason:
        result.reason = f"步数达上限 {max_steps}，标记 unverified"
    return result


def run_full_audit_round(tools: dict, client, model: str, token_budget: int, log_fn=None,
                         round_no: int = 1, context: str = "",
                         max_steps: int | None = None) -> dict:
    """全量审计单轮：Agent 自由遍历整个源码目录，write_finding 提交 findings 数组。
    tools: {name: (func, desc)}；返回 {"findings": [...], "tokens_used": int, "reason": str}
    max_steps：单轮步数硬上限（None 时用默认 AGENT_MAX_STEPS）。"""
    max_steps = max_steps or AGENT_MAX_STEPS
    log_fn = log_fn or (lambda m: None)
    tool_desc = "\n".join(f"- {name}: {desc}" for name, (_, desc) in tools.items())
    sys_prompt = FULL_AUDIT_SYSTEM_PROMPT + "\n\n可用工具:\n" + tool_desc + "\n\n" + context
    tokens = _est_tokens(sys_prompt)
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": "开始全量审计。请先建立文件清单，再逐文件深入追踪漏洞；全部完成后用 write_finding 提交 findings 数组。"},
    ]
    findings: list[dict] = []
    reason = ""

    for step in range(1, max_steps + 1):
        if tokens >= token_budget:
            reason = f"token 预算耗尽（{tokens}），终止本轮"
            log_fn(reason)
            break
        try:
            text = _chat(client, model, messages)
        except Exception as e:
            reason = f"LLM 调用失败: {e}"
            log_fn(reason)
            break
        tokens += _est_tokens(text) + 50
        step_data = _parse_step(text)
        if step_data is None:
            messages.append({"role": "assistant", "content": text[:500]})
            messages.append({"role": "user", "content": "输出格式错误，请输出 JSON：{\"thought\":..., \"tool\":..., \"args\":{...}}"})
            continue
        tool = str(step_data.get("tool", "")).strip()
        args = step_data.get("args") or {}
        if tool == "write_finding":
            raw = args.get("findings") or ([args] if args.get("file_path") else [])
            for f in raw:
                if not isinstance(f, dict) or not f.get("file_path"):
                    continue
                if f.get("verdict") not in (None, "verified"):
                    continue
                findings.append(f)
            reason = str(args.get("reason", ""))[:500]
            break
        item = tools.get(tool)
        if item is None:
            obs = f"ERROR: 未知工具 {tool}，可用: {', '.join(tools)}"
        else:
            fn, _ = item
            try:
                obs = str(fn(**args))[:3000]
            except Exception as e:
                obs = f"ERROR: 工具执行异常: {e}"
        log_fn(f"round{round_no} step{step}: {tool} {json.dumps(args, ensure_ascii=False)[:120]}")
        tokens += _est_tokens(obs)
        messages.append({"role": "assistant", "content": json.dumps(step_data, ensure_ascii=False)[:1000]})
        if len(messages) > 18:
            messages = messages[:2] + messages[-16:]
        messages.append({"role": "user", "content": f"Observation:\n{obs}\n\n继续审计（或全部完成时 write_finding 提交 findings 数组）。"})

    if not reason:
        reason = f"第 {round_no} 轮步数达上限 {max_steps}"
    log_fn(f"round{round_no} 完成：提交 {len(findings)} 条候选（{reason}）")
    return {"findings": findings, "tokens_used": tokens, "reason": reason}
