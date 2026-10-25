"""Pydantic 请求响应模型"""
from datetime import datetime

from pydantic import BaseModel


class TaskOut(BaseModel):
    id: int
    filename: str
    status: str
    project_type: str
    tech_stack: str
    fingerprint: str = ""
    audit_mode: str = "full"
    tokens_used: int = 0
    cancel_requested: bool = False
    error_msg: str | None = None
    report_path: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TaskDetailOut(TaskOut):
    """详情接口专用：附带执行日志（列表接口保持轻量不返回 log）"""
    log: str = ""


class VulnerabilityOut(BaseModel):
    id: int
    task_id: int
    source: str
    rule_id: str
    title: str | None = None  # AI 生成的中文漏洞名
    precondition: str | None = None  # 复现条件
    severity: str
    file_path: str
    line: int
    code_snippet: str
    llm_is_real: bool | None = None
    llm_reason: str | None = None
    llm_confidence: str | None = None
    poc_verified: bool | None = None
    verify_result: str | None = None
    poc_payload: str | None = None
    agent_status: str | None = None
    agent_evidence: str | None = None
    agent_confidence: str | None = None
    agent_reason: str | None = None
    analyzed_at: datetime | None = None

    model_config = {"from_attributes": True}


class ConfigUpdate(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    # Agent 引擎可调参数（int | None 表示不修改）
    agent_max_vulns: int | None = None
    agent_max_steps: int | None = None
    agent_concurrency: int | None = None
    agent_token_budget: int | None = None
    full_audit_rounds: int | None = None
    full_audit_token_per_round: int | None = None
    full_audit_max_findings: int | None = None


class ConfigOut(BaseModel):
    base_url: str
    api_key: str  # 脱敏后
    model: str
    # Agent 引擎可调参数（当前生效值，字符串形式便于前端展示）
    agent_max_vulns: str = "20"
    agent_max_steps: str = "15"
    agent_concurrency: str = "3"
    agent_token_budget: str = "1500000"
    full_audit_rounds: str = "3"
    full_audit_token_per_round: str = "400000"
    full_audit_max_findings: str = "8"
