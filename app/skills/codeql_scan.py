# -*- coding: utf-8 -*-
"""CodeQL 数据流推理引擎（阶段四，可选巨人）：小仓库自动建库+查询，SARIF → findings。

Java/Kotlin/C# 使用 build-mode=none；Python/JS/Ruby 无需构建。
大仓库（>AUDIT_CODEQL_MAX_FILES）或工具缺失时自动跳过，避免拖垮串行队列。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

from app.audit_labels import vuln_label

CODEQL_BIN = os.environ.get("AUDIT_CODEQL_BIN", "/opt/giants/codeql/codeql")
CODEQL_ROOT = Path(os.environ.get("AUDIT_CODEQL_ROOT", "/opt/giants/codeql"))
MAX_FILES = int(os.environ.get("AUDIT_CODEQL_MAX_FILES", "5000"))
MAX_FINDINGS = int(os.environ.get("AUDIT_CODEQL_MAX_FINDINGS", "200"))
DB_TIMEOUT = int(os.environ.get("AUDIT_CODEQL_DB_TIMEOUT", "600"))
ANALYZE_TIMEOUT = int(os.environ.get("AUDIT_CODEQL_ANALYZE_TIMEOUT", "600"))
ANALYZE_RAM_MB = int(os.environ.get("AUDIT_CODEQL_RAM_MB", "4096"))
SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "bower_components",
             ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
             "target", "obj", "coverage", ".next", ".nuxt", "decompiled_embedded"}
LANG_MAP = {
    "java": ("java", True), "kotlin": ("java", True),
    "python": ("python", True),
    "javascript": ("javascript", True), "typescript": ("javascript", True),
    "csharp": ("csharp", True), "ruby": ("ruby", True),
    "go": ("go", False),
}
TECH_EXTS = {
    "java": (".java",), "kotlin": (".kt", ".kts"),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "typescript": (".ts", ".tsx"),
    "csharp": (".cs",), "ruby": (".rb",), "go": (".go",),
}


def _pick_lang(root: Path, techs: list[str]) -> tuple[str | None, bool]:
    """按源码文件数选主语言，避免 examples 里的 TS/JS 抢走 Go/Java 项目的 CodeQL。"""
    supported = [t for t in techs if t in LANG_MAP]
    if not supported:
        return None, False
    counts = {t: 0 for t in supported}
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            for tech in supported:
                if ext in TECH_EXTS.get(tech, ()):
                    counts[tech] += 1
                    break
    backend = [t for t in supported if t in ("java", "kotlin", "python",
                                             "csharp", "ruby", "go")]
    frontend = [t for t in supported if t in ("javascript", "typescript")]
    # 全栈项目优先深挖后端；否则 Memos/Paperless 会被前端文件数带偏
    front_count = sum(counts.get(t, 0) for t in frontend)
    back_count = max((counts.get(t, 0) for t in backend), default=0)
    # 少量 Python/Go 辅助脚本不应把 Node 项目的 CodeQL 带偏
    use_backend = bool(backend and frontend and back_count >= 20
                       and back_count >= 0.2 * max(front_count, 1))
    pool = backend if use_backend else supported
    tech = max(pool, key=lambda t: counts.get(t, 0))
    if counts.get(tech, 0) == 0:
        tech = pool[0]
    return LANG_MAP[tech]


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (OSError, FileNotFoundError) as e:
        return 127, "", str(e)


def _count_files(root: Path) -> int:
    n = 0
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        n += len(filenames)
        if n > MAX_FILES * 4:
            break
    return n


def _find_suite(lang: str) -> Path | None:
    hits = sorted((CODEQL_ROOT / "qlpacks" / "codeql" / f"{lang}-queries").glob(
        "*/codeql-suites/*security-extended.qls"))
    return hits[-1] if hits else None


def _rel_uri(uri: str, root: Path) -> str:
    u = urllib.parse.unquote(str(uri or ""))
    u = re.sub(r"^file://(?:/)?", "/", u).replace("\\", "/")
    try:
        p = Path(u)
        if p.is_absolute():
            return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        pass
    return u.lstrip("/")


def scan(workspace: str, log_fn=None, ram_mb: int | None = None,
         threads: int | None = None) -> list[dict]:
    log = log_fn or (lambda m: None)
    if os.environ.get("AUDIT_CODEQL", "1") != "1" or not Path(CODEQL_BIN).exists():
        return []
    root = Path(workspace)
    if not root.is_dir():
        return []
    from app.skills.tech_detect import run_tech_detect_multi
    lang, build_none = _pick_lang(root, run_tech_detect_multi(workspace))
    if not lang:
        log("CodeQL：栈不在支持范围，跳过")
        return []
    nfiles = _count_files(root)
    if nfiles > MAX_FILES:
        log(f"CodeQL 跳过：文件数 {nfiles} > {MAX_FILES}")
        return []
    suite = _find_suite(lang)
    if suite is None:
        log(f"CodeQL 跳过：缺少 {lang} 查询套件")
        return []

    log(f"CodeQL 建库（{lang}，{nfiles} 文件，10-60 秒）…")
    db = tempfile.mkdtemp(prefix="codeql_db_")
    sarif = Path(db) / "results.sarif"
    try:
        cmd = [CODEQL_BIN, "database", "create", db, "--language", lang,
               "--source-root", str(root), "--overwrite"]
        if build_none:
            cmd += ["--build-mode", "none"]
        rc, _, err = _run(cmd, DB_TIMEOUT)
        if rc != 0:
            log(f"CodeQL 建库失败（跳过）: {err[-160:]}")
            return []
        log("CodeQL 执行 security-extended 查询…")
        ram = int(ram_mb or ANALYZE_RAM_MB)
        th = max(1, min(int(threads or 2), 8))
        rc, _, err = _run([CODEQL_BIN, "database", "analyze", db, str(suite),
                           "--format=sarif-latest", "--output", str(sarif),
                           "--rerun", f"--threads={th}", f"--ram={ram}"],
                          ANALYZE_TIMEOUT)
        if rc != 0 or not sarif.exists():
            log(f"CodeQL 查询失败（跳过）: {err[-160:]}")
            return []
        data = json.loads(sarif.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        log(f"CodeQL 异常（跳过）: {e}")
        return []
    finally:
        shutil.rmtree(db, ignore_errors=True)
    return _map_sarif(data, root, lang, nfiles, log)


def _line_snippet(root: Path, rel: str, line: int) -> str:
    try:
        p = root / rel
        if not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
            return ""
        lines = p.read_text(errors="ignore").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:120]
    except OSError:
        pass
    return ""


def _flow_summary(result: dict, root: Path, cache: dict | None = None) -> str:
    """提取 SARIF codeFlows 的 source→sink 路径：去重连续重复点，每步带代码。"""
    cache = cache if cache is not None else {}
    for flow in (result.get("codeFlows") or []):
        for thread in (flow.get("threadFlows") or []):
            points = []
            last = None
            for item in (thread.get("locations") or []):
                loc = item.get("location") or {}
                phy = loc.get("physicalLocation") or {}
                fp = _rel_uri(phy.get("artifactLocation", {}).get("uri", ""), root)
                line = int(phy.get("region", {}).get("startLine", 0) or 0)
                if not fp:
                    continue
                key = (fp, line)
                if key == last:
                    continue
                last = key
                if key not in cache:
                    cache[key] = _line_snippet(root, fp, line)
                code = cache[key]
                points.append("%s:%s%s" % (fp, line, (" `" + code + "`") if code else ""))
            if points:
                return " → ".join(points[:12])[:1600]
    return ""


def _map_sarif(data: dict, root: Path, lang: str, nfiles: int, log) -> list[dict]:
    run = (data.get("runs") or [{}])[0]
    rules = {str(r.get("id")): r for r in
             (run.get("tool", {}).get("driver", {}).get("rules") or [])}
    out, seen = [], set()
    line_cache = {}
    for res in (run.get("results") or []):
        rid = str(res.get("ruleId") or "")
        locs = res.get("locations") or []
        loc = (locs[0].get("physicalLocation") if locs else {}) or {}
        fp = _rel_uri(loc.get("artifactLocation", {}).get("uri", ""), root)
        line = int(loc.get("region", {}).get("startLine", 0) or 0)
        if not rid or not fp or (fp, line, rid) in seen:
            continue
        seen.add((fp, line, rid))
        meta = rules.get(rid) or {}
        props = meta.get("properties") or {}
        level = str(res.get("level") or
                    meta.get("defaultConfiguration", {}).get("level") or "warning").lower()
        try:
            sec = float(props.get("security-severity") or 0)
        except (TypeError, ValueError):
            sec = 0.0
        severity = ("ERROR" if level == "error" or sec >= 7
                    else "WARNING" if level == "warning" or sec >= 4 else "INFO")
        short = (meta.get("shortDescription") or {}).get("text") or rid
        label = vuln_label(rid)
        msg = str((res.get("message") or {}).get("text") or "")
        snippet = loc.get("contextRegion", {}).get("snippet", {}).get("text") or msg
        flow_text = _flow_summary(res, root, line_cache)
        if flow_text:
            snippet = (str(snippet) + "\nCodeQL flow: " + flow_text)[:1600]
        out.append({
            "source": "codeql",
            "rule_id": f"codeql:{rid}"[:128],
            "title": (label if label != "疑似漏洞" else short)[:120],
            "severity": severity,
            "file_path": fp[:512],
            "line": line,
            "code_snippet": str(snippet)[:1600],
            "message": msg[:300] or short,
            "agent_evidence": ("CodeQL 数据流: " + flow_text)[:1800] if flow_text else None,
        })
    out.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x["severity"], 3))
    out = out[:MAX_FINDINGS]
    log(f"CodeQL 完成：{len(out)} 条（{lang}，{nfiles} 文件）")
    return out
