"""Pydantic 请求响应模型"""
from datetime import datetime

from pydantic import BaseModel


class TaskOut(BaseModel):
    id: int
    filename: str
    status: str
    project_type: str
    tech_stack: str
    error_msg: str | None = None
    report_path: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityOut(BaseModel):
    id: int
    task_id: int
    source: str
    rule_id: str
    severity: str
    file_path: str
    line: int
    code_snippet: str
    llm_is_real: bool | None = None
    llm_reason: str | None = None
    llm_confidence: str | None = None
    poc_verified: bool | None = None
    verify_result: str | None = None

    model_config = {"from_attributes": True}


class ConfigUpdate(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""


class ConfigOut(BaseModel):
    base_url: str
    api_key: str  # 脱敏后
    model: str
