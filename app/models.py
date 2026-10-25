"""ORM 数据模型"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Task(Base):
    """任务主表"""
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_hash: Mapped[str] = mapped_column(String(64), default="", index=True)  # 内容 SHA-256，用于去重
    upload_path: Mapped[str] = mapped_column(String(512), default="")  # 原始上传文件路径
    status: Mapped[str] = mapped_column(String(32), default="pending")
    project_type: Mapped[str] = mapped_column(String(16), default="web")
    tech_stack: Mapped[str] = mapped_column(String(128), default="unknown")
    fingerprint: Mapped[str] = mapped_column(Text, default="")  # 组件指纹（JSON：组件/语言分布/后缀统计）
    audit_mode: Mapped[str] = mapped_column(String(16), default="full")  # full=完整审计；static=仅静态扫描（不消耗token）
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)  # Agent 阶段已消耗 token 估算
    workspace_path: Mapped[str] = mapped_column(String(512), default="")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)  # 用户请求停止
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    log: Mapped[str] = mapped_column(Text, default="")
    report_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sandbox_cid: Mapped[str | None] = mapped_column(String(80), nullable=True)  # 保留的沙箱容器 ID（手工 POC 验证用）
    sandbox_port: Mapped[int | None] = mapped_column(Integer, nullable=True)    # 容器内部服务端口
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)


class Vulnerability(Base):
    """漏洞明细表"""
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("tasks.id"))
    source: Mapped[str] = mapped_column(String(32), default="")
    rule_id: Mapped[str] = mapped_column(String(128), default="")
    title: Mapped[str | None] = mapped_column(String(128), nullable=True)  # AI 生成的中文漏洞名（报告展示用）
    precondition: Mapped[str | None] = mapped_column(String(512), nullable=True)  # 复现条件（如：需登录/匿名可达/需特定数据）
    severity: Mapped[str] = mapped_column(String(16), default="")
    file_path: Mapped[str] = mapped_column(String(512), default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    llm_is_real: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    llm_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_confidence: Mapped[str | None] = mapped_column(String(8), nullable=True)
    poc_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verify_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Agent 深度研判字段（升级阶段 3，兼容旧数据）
    agent_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # verified/false_positive/unverified/error
    agent_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)      # 证据链
    agent_confidence: Mapped[str | None] = mapped_column(String(8), nullable=True)
    agent_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class Config(Base):
    """系统配置表"""
    __tablename__ = "config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
