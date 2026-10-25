"""SAST skill：调用 semgrep 用内置规则 + 官方规则集缓存扫描源码（阶段 1 扩展：多语言多栈）"""
import json
import subprocess
from pathlib import Path

from app.config import TASK_TIMEOUT, DATA_DIR

RULES_DIR = Path(__file__).parent / "rules"
RULE_LANG_FILES = {
    "python": "python.yaml",
    "java": "java.yaml",
    "php": "php.yaml",
    "javascript": "javascript.yaml",
    "typescript": "typescript.yaml",
    "go": "go.yaml",
    "csharp": "csharp.yaml",
    "c": "c.yaml",
    "cpp": "cpp.yaml",
    "kotlin": "kotlin.yaml",
    "ruby": "ruby.yaml",
    "rust": "rust.yaml",
    "swift": "swift.yaml",
    "dart": "dart.yaml",
    "scala": "scala.yaml",
    "html": "html.yaml",
}

# 单次任务最多扫描多少个技术栈（防止大项目扫描时间爆炸）
MAX_SCAN_STACKS = 4
# 官方规则集（semgrep registry，semgrep.dev 官方托管；只含模式匹配规则、不执行代码，无危险操作）
# 通用漏洞规则包：所有语言共用
OFFICIAL_GENERIC = ["p/security-audit", "p/owasp-top-ten", "p/command-injection", "p/sql-injection", "p/xss"]
# 语言专属规则包：只对对应主栈附加
OFFICIAL_LANG = {
    "python": ["p/python"],
    "java": ["p/java"],
    "php": ["p/php"],
    "javascript": ["p/javascript"],
    "typescript": ["p/javascript"],
    "go": ["p/golang"],
    "csharp": ["p/csharp"],
}
# 扫描超时：附加官方规则集后单栈扫描放宽到 10 分钟（大项目多规则集可能变慢）
SAST_TIMEOUT_OFFICIAL = 600


def _run_semgrep(configs: list[str], workspace: str, timeout: int = TASK_TIMEOUT) -> list[dict]:
    """执行一次 semgrep，返回原始 results 列表"""
    cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore",
           "--metrics=off", "--disable-nosem", "--max-memory", "2048"]
    for c in configs:
        cmd += ["--config", c]
    cmd += [workspace]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("semgrep 扫描超时")
    except FileNotFoundError:
        raise RuntimeError("semgrep 未安装，无法执行静态扫描")

    if proc.returncode not in (0, 1, 2):  # semgrep 发现漏洞时返回非 0
        raise RuntimeError(f"semgrep 执行失败: {proc.stderr[:300]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("semgrep 输出解析失败")
    return data.get("results", [])


def _official_configs(tech: str) -> list[str]:
    """对主栈返回可用官方规则包（逐个探测，失败静默剔除，结果持久化到 data/official_rules.json）
    安全说明：仅从 semgrep.dev 官方 registry 拉取，规则为纯模式匹配 yaml，不含可执行代码。
    兼容旧 flag 文件（内容为 1 表示 security-audit/owasp-top-ten 已验证可用）。"""
    import logging
    import os
    if os.environ.get("AUDIT_OFFICIAL_RULES", "1") != "1":
        return []
    if tech not in OFFICIAL_LANG and tech not in ("python", "java", "javascript", "typescript", "go", "php", "csharp"):
        return []
    desired = list(dict.fromkeys(OFFICIAL_GENERIC + OFFICIAL_LANG.get(tech, [])))
    flag_file = DATA_DIR / "official_rules.flag"
    json_file = DATA_DIR / "official_rules.json"
    ok = set()
    try:
        if json_file.exists():
            import json as _json
            ok = set(_json.loads(json_file.read_text()).get("ok", []))
        elif flag_file.exists() and flag_file.read_text().strip() == "1":
            ok = set(OFFICIAL_GENERIC)  # 旧验证过的通用包视为可用，无需重探
    except (OSError, ValueError):
        ok = set()
    changed = False
    for pack in desired:
        if pack in ok:
            continue
        try:
            probe_dir = DATA_DIR / "_probe"
            probe_dir.mkdir(parents=True, exist_ok=True)
            _run_semgrep([pack], str(probe_dir), timeout=20)  # 离线时快速失败，避免首启阻塞近 10 分钟
            ok.add(pack)
            logging.getLogger("sast").info(f"官方规则包可用: {pack}")
        except Exception as e:
            logging.getLogger("sast").info(f"官方规则包不可用（已剔除）: {pack} -> {e}")
        changed = True
    if changed:
        try:
            json_file.write_text(json.dumps({"ok": sorted(ok), "probed_at": str(Path(__file__).stat().st_mtime)}))
        except OSError:
            pass
    return [p for p in desired if p in ok]


def _vuln_category(rule_id: str) -> str:
    """从 rule_id 提取漏洞类别，用于合并同位置重复命中（不同规则集可能命中同一行）"""
    rid = rule_id.lower()
    for cat, keys in (
        ("sql", ("sql", "sqli")),
        ("cmd", ("command", "os-system", "shell")),
        ("xss", ("xss",)),
        ("path", ("path", "traversal", "file")),
        ("ssrf", ("ssrf",)),
        ("xxe", ("xxe", "xml")),
        ("ssti", ("ssti", "template")),
        ("deser", ("deserialize", "pickle")),
        ("ldap", ("ldap",)),
        ("crypto", ("crypto", "md5", "sha1", "random")),
        ("auth", ("auth", "password", "jwt", "session", "csrf", "redirect")),
    ):
        if any(k in rid for k in keys):
            return cat
    return "misc"


def run_sast(workspace: str, techs: list[str] | str) -> list[dict]:
    """执行 semgrep 多栈扫描，返回漏洞列表 [{rule_id, severity, file_path, line, code_snippet}]"""
    if isinstance(techs, str):
        techs = [techs] if techs != "unknown" else []
    techs = techs[:MAX_SCAN_STACKS]

    all_results: list[dict] = []
    official = _official_configs(techs[0]) if techs else []

    for i, tech in enumerate(techs):
        rule_file = RULES_DIR / RULE_LANG_FILES.get(tech, "")
        configs: list[str] = []
        if rule_file.exists():
            configs.append(str(rule_file))
        if i == 0 and official:
            configs += official
        if not configs:
            configs = ["auto"]  # 完全无规则时兜底 auto
        timeout = SAST_TIMEOUT_OFFICIAL if (official and i == 0) else TASK_TIMEOUT
        try:
            all_results += _run_semgrep(configs, workspace, timeout=timeout)
        except RuntimeError as e:
            import logging
            logging.getLogger("sast").warning(f"扫描 {tech} 失败: {e}")

    # 第一层去重（规则+文件+行）→ 第二层：同一文件同一行同一类别只保留严重性最高的一条
    _sev_rank = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
    all_results.sort(key=lambda r: _sev_rank.get((r.get("extra", {}).get("severity") or "").upper(), 3))
    return _post_process(all_results, workspace)

def _clean_text(t: str) -> str:
    """清除 semgrep 官方规则包注入的页脚（如 'requires login'），避免污染展示与 Agent 上下文"""
    import re as _re
    if not t:
        return ""
    return _re.sub(r"\s*requires\s+login\b[^\n]*", "", t, flags=_re.IGNORECASE).strip()


def _post_process(all_results, workspace: str):
    vulns, seen = [], set()
    root = Path(workspace).resolve()
    for r in all_results:
        fp = r.get("path", "")
        try:
            fp = str(Path(fp).resolve().relative_to(root))
        except ValueError:
            pass
        line = r.get("start", {}).get("line", 0)
        check_id = r.get("check_id", "")
        key = (check_id, fp, line)
        if key in seen:
            continue
        seen.add(key)
        # 同位置同类别去重：不同规则集命中同一行时只保留严重性最高的
        cat_key = (_vuln_category(check_id), fp, line)
        if cat_key in seen:
            continue
        seen.add(cat_key)
        vulns.append({
            "rule_id": check_id,
            "severity": (r.get("extra", {}).get("severity") or "").upper(),
            "file_path": fp,
            "line": line,
            "code_snippet": _clean_text(r.get("extra", {}).get("lines") or r.get("extra", {}).get("message") or "")[:1000],
            "message": _clean_text(r.get("extra", {}).get("message", "")),
        })
    return vulns
