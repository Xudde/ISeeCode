"""全局路径与常量配置"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
WORKSPACE_DIR = DATA_DIR / "workspaces"
REPORT_DIR = DATA_DIR / "reports"

for _d in (DATA_DIR, UPLOAD_DIR, WORKSPACE_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_URL = f"sqlite:///{DATA_DIR / 'app.db'}"

# 全局安全红线常量（大包可通过环境变量调整）
MAX_UPLOAD_SIZE = int(os.environ.get("AUDIT_MAX_UPLOAD_MB", "4096")) * 1024 * 1024   # 默认 4GB
MAX_EXTRACT_SIZE = int(os.environ.get("AUDIT_MAX_EXTRACT_MB", "10240")) * 1024 * 1024  # 默认 10GB
TASK_TIMEOUT = int(os.environ.get("AUDIT_TASK_TIMEOUT", "300"))                         # 沙箱/反编译等 5 分钟
SAST_TIMEOUT = int(os.environ.get("AUDIT_SAST_TIMEOUT", "1800"))                       # 大源码 semgrep 30 分钟

# 允许上传的扩展名
ALLOWED_EXTENSIONS = {".zip"}
# 反编译输入扩展名（升级阶段 2）
DECOMPILE_EXTENSIONS = {".jar", ".war", ".class", ".dex", ".dll", ".exe", ".pyc", ".so", ".elf", ".bin"}
# Windows 驱动静态审计输入（阶段三）
DRIVER_EXTENSIONS = {".sys"}

# ---- Agent 审计引擎（升级阶段 3）----
AGENT_MAX_STEPS = int(os.environ.get("AGENT_MAX_STEPS", 15))          # 单条漏洞 Agent 步数硬上限
AGENT_TOKEN_BUDGET = int(os.environ.get("AGENT_TOKEN_BUDGET", 1_500_000))  # 每任务 token 软上限（估算）
AGENT_CONCURRENCY = int(os.environ.get("AGENT_CONCURRENCY", 3))       # Agent 分析线程池并发
SANDBOX_CONCURRENCY = int(os.environ.get("SANDBOX_CONCURRENCY", 2))   # 沙箱动态验证并发上限
AGENT_MAX_VULNS = int(os.environ.get("AGENT_MAX_VULNS", 20))          # 单任务 Agent 深度研判条数上限

# ---- Agent 全量审计（升级阶段 3.2：根治漏报，不依赖静态规则命中）----
FULL_AUDIT_ROUNDS = int(os.environ.get("FULL_AUDIT_ROUNDS", 3))                # 全量审计轮次（每轮覆盖未探索文件）
FULL_AUDIT_TOKEN_PER_ROUND = int(os.environ.get("FULL_AUDIT_TOKEN_PER_ROUND", 400_000))  # 每轮 token 软上限（估算）
FULL_AUDIT_MAX_FINDINGS = int(os.environ.get("FULL_AUDIT_MAX_FINDINGS", 8))    # 每轮提交漏洞条数上限
