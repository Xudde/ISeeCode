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


class AgentRun(Base):
    """外部 AI（Zcode/Qoder）深挖会话租约与 checkpoint。"""
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("tasks.id"), index=True)
    session_key: Mapped[str] = mapped_column(String(80), default="")
    status: Mapped[str] = mapped_column(String(16), default="running")  # running/completed/blocked/expired
    stage: Mapped[str] = mapped_column(String(16), default="")  # triage/exploit/verify/judge/done
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    checkpoint: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)


class ExploitChain(Base):
    """AI 深挖产出的利用链（阶段 0.8）：nodes/edges JSON，任务页画节点图。"""
    __tablename__ = "exploit_chains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("tasks.id"), index=True)
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(200), default="")
    nodes_json: Mapped[str] = mapped_column(Text, default="[]")
    edges_json: Mapped[str] = mapped_column(Text, default="[]")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class AuthzEndpoint(Base):
    """框架级鉴权语义（阶段 1）：endpoint 标签 + 中间件链证据。"""
    __tablename__ = "authz_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("tasks.id"), index=True)
    framework: Mapped[str] = mapped_column(String(32), default="")
    method: Mapped[str] = mapped_column(String(16), default="ANY")
    path: Mapped[str] = mapped_column(String(512), default="")
    labels: Mapped[str] = mapped_column(String(32), default="unknown")
    middleware_chain: Mapped[str] = mapped_column(Text, default="[]")
    evidence_file: Mapped[str] = mapped_column(String(512), default="")
    evidence_line: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(8), default="low")
    note: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class PatchFeature(Base):
    """补丁差分特征（阶段 2）：CVE/commit → sink/check 特征与变体扫描记录。"""
    __tablename__ = "patch_features"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, ForeignKey("tasks.id"), index=True)
    cve: Mapped[str] = mapped_column(String(64), default="")
    repo: Mapped[str] = mapped_column(String(200), default="")
    commit_ref: Mapped[str] = mapped_column(String(200), default="")
    features_json: Mapped[str] = mapped_column(Text, default="{}")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class Watchlist(Base):
    """情报 watchlist（阶段 5）：关注的开源包/仓库。"""
    __tablename__ = "intel_watchlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16), default="package")  # package/repo
    target: Mapped[str] = mapped_column(String(200), default="")     # 包名
    ecosystem: Mapped[str] = mapped_column(String(32), default="")   # PyPI/npm/Go/Maven
    repo: Mapped[str] = mapped_column(String(200), default="")       # owner/name
    auto_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    notify: Mapped[bool] = mapped_column(Boolean, default=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class IntelEvent(Base):
    """情报事件：OSV/Advisory 命中的新漏洞。"""
    __tablename__ = "intel_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(16), default="osv")
    event_key: Mapped[str] = mapped_column(String(200), default="", index=True)
    advisory_id: Mapped[str] = mapped_column(String(64), default="")
    cve: Mapped[str] = mapped_column(String(32), default="")
    package: Mapped[str] = mapped_column(String(200), default="")
    ecosystem: Mapped[str] = mapped_column(String(32), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    fixed: Mapped[str] = mapped_column(String(64), default="")
    repo: Mapped[str] = mapped_column(String(200), default="")
    target: Mapped[str] = mapped_column(String(200), default="")
    published: Mapped[str] = mapped_column(String(32), default="")
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class AuditEvent(Base):
    """操作审计（阶段 7）：只记录变更类 API 与关键动作，不落请求体。"""
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, index=True)
    action: Mapped[str] = mapped_column(String(64), default="", index=True)
    target: Mapped[str] = mapped_column(String(64), default="")
    method: Mapped[str] = mapped_column(String(8), default="")
    path: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[int] = mapped_column(Integer, default=0)
    actor: Mapped[str] = mapped_column(String(16), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str] = mapped_column(Text, default="")
