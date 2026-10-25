"""Agent 引擎可调参数：Config 表（key/value）优先，env/默认值兜底。
与 config.py 的静态常量解耦：worker 在阶段 6.5/7.5 启动前动态读取，
支持前端"设置"页调整后即时生效（新任务按新值执行），无需重启服务。
"""
from app.models import Config

# 默认值（与 app/config.py 中 os.environ 兜底值保持一致）
AGENT_SETTING_DEFAULTS = {
    "agent_max_vulns": 20,                # 单任务 Agent 深度研判条数上限
    "agent_max_steps": 15,                # 单条漏洞 Agent 步数硬上限
    "agent_concurrency": 3,               # Agent 分析线程池并发
    "agent_token_budget": 1_500_000,      # 每任务 token 软上限（估算）
    "full_audit_rounds": 3,               # 全量审计轮次
    "full_audit_token_per_round": 400_000,  # 每轮 token 软上限（估算）
    "full_audit_max_findings": 8,         # 每轮提交漏洞条数上限
}

SETTING_LABELS = {
    "agent_max_vulns": "深度研判条数上限",
    "agent_max_steps": "单条 Agent 步数上限",
    "agent_concurrency": "研判并发数",
    "agent_token_budget": "每任务 token 预算",
    "full_audit_rounds": "全量审计轮次",
    "full_audit_token_per_round": "每轮 token 预算",
    "full_audit_max_findings": "每轮漏洞条数上限",
}


def agent_settings(db) -> dict:
    """读取 Agent 引擎参数（Config 表优先，默认值兜底），全部返回 int。"""
    rows: dict[str, str] = {}
    if db is not None:
        try:
            rows = {c.key: c.value for c in db.query(Config).all()}
        except Exception:
            rows = {}
    out: dict[str, int] = {}
    for k, default in AGENT_SETTING_DEFAULTS.items():
        raw = rows.get(k)
        if raw is None or str(raw).strip() == "":
            raw = default
        try:
            out[k] = int(raw)
        except (TypeError, ValueError):
            out[k] = default
    return out
