# -*- coding: utf-8 -*-
"""补丁差分 + 同源变体 v1（阶段 2）。

输入：CVE 修复 commit / compare diff（文本），或本地 patch 文本。
步骤：解析 unified diff → 提取“移除的危险 sink + 新增的安全检查 + 关键符号”
      → 在目标源码中搜索同 sink/同符号的变体候选（缺少对应检查时加权）。
输出：平台统一漏洞 dict（source=variant），只做候选，不代表已复现。
"""
import json
import re
import subprocess
import urllib.request
from pathlib import Path

SKIP_DIRS = {"node_modules", "vendor", "third_party", "thirdparty", "bower_components",
             ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
             "target", "obj", "coverage", ".next", ".nuxt", "test", "tests",
             "test-cli", "testing", "e2e", "cypress", "spec", "specs",
             "__tests__", "docs", "examples", "example", "samples"}
CODE_EXTS = {".py", ".java", ".kt", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
             ".go", ".php", ".rb", ".cs", ".c", ".cpp", ".h"}
MAX_FILES = 4000
MAX_FILE_SIZE = 2 * 1024 * 1024

SINK_TOKENS = [
    "eval", "exec", "execSync", "spawn", "spawnSync", "system", "popen",
    "passthru", "shell_exec", "proc_open", "unserialize", "pickle.loads",
    "yaml.load", "readObject", "ObjectInputStream", "readFile", "writeFile",
    "createReadStream", "sendFile", "unlink", "os.path.join", "path.join",
    "path.resolve", "child_process", "innerHTML", "dangerouslySetInnerHTML",
    "render_template", "Template(", "query(", "execute(", "rawQuery",
    "requests.get", "requests.post", "axios.", "fetch(", "urlopen",
]
CHECK_TOKENS = [
    "if ", "is None", "== null", "!==", "startsWith", "endsWith", "includes",
    "allowed", "whitelist", "blacklist", "sanitize", "escape", "basename",
    "realpath", "normalize", "validate", "verify", "auth", "permission",
    "isAdmin", "isAuthenticated", "hasPermission", "path.resolve", "path.basename",
]
NOISE_IDENTS = {"if", "for", "while", "return", "function", "const", "let", "var",
                "this", "self", "true", "false", "null", "none", "import", "from",
                "class", "def", "async", "await", "then", "catch", "try", "else"}


def _iter_files(root: Path):
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in CODE_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        n += 1
        if n > MAX_FILES:
            break
        yield p


def parse_diff(text: str) -> list[dict]:
    files, cur = [], None
    for line in (text or "").splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.*?) b/(.*)$", line)
            if not m:
                continue
            cur = {"old": m.group(1), "new": m.group(2), "added": [], "removed": [], "hunks": 0}
            files.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("@@"):
            cur["hunks"] += 1
        elif line.startswith("+") and not line.startswith("+++"):
            cur["added"].append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            cur["removed"].append(line[1:])
    return files


def extract_features(diff_text: str, cve: str = "", repo: str = "", commit: str = "") -> dict:
    files = parse_diff(diff_text)
    sinks, checks, keywords, changed = set(), set(), set(), []
    for f in files:
        for line in f["removed"]:
            for tok in SINK_TOKENS:
                if tok in line:
                    sinks.add(tok)
        for line in f["added"]:
            for tok in CHECK_TOKENS:
                if tok in line:
                    checks.add(tok)
            for m in re.finditer(r"\b([A-Za-z_]\w{2,})\s*\(", line):
                w = m.group(1)
                if w.lower() not in NOISE_IDENTS:
                    keywords.add(w)
        for line in f["added"] + f["removed"]:
            for m in re.finditer(r"\b([A-Za-z_]\w{3,})\b", line):
                w = m.group(1)
                if w.lower() not in NOISE_IDENTS and ("_" in w or w[:1].isupper()):
                    keywords.add(w)
        if f["added"] or f["removed"]:
            changed.append(f["new"])
    return {
        "cve": cve, "repo": repo, "commit": commit,
        "files": changed[:50], "sinks": sorted(sinks), "checks": sorted(checks),
        "keywords": sorted(keywords)[:80],
        "stats": {"files": len(files), "changed": len(changed),
                  "added": sum(len(f["added"]) for f in files),
                  "removed": sum(len(f["removed"]) for f in files)},
    }


def scan_workspace(workspace: str, features: dict, severity: str = "WARNING",
                   max_findings: int = 50) -> list[dict]:
    root = Path(workspace)
    if not root.is_dir():
        return []
    sinks = features.get("sinks") or []
    checks = features.get("checks") or []
    kws = features.get("keywords") or []
    cve = features.get("cve") or ""
    if not sinks and not kws:
        return []
    out, seen = [], set()
    for p in _iter_files(root):
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        for i, line in enumerate(lines, 1):
            hit = [s for s in sinks if s in line]
            if not hit:
                continue
            score = len(hit)
            low = line.lower()
            if any(c in low for c in checks):
                score -= 1
            if kws and any(k in line for k in kws):
                score += 1
            if score < 1:
                continue
            key = (rel, i, ",".join(sorted(hit)))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "source": "variant",
                "rule_id": f"variant:{cve or 'fix'}:{hit[0]}"[:128],
                "title": f"同源变体候选：{hit[0]}（参考 {cve or '修复补丁'}）"[:120],
                "severity": severity,
                "file_path": rel[:512], "line": i,
                "code_snippet": "\n".join(lines[max(0, i - 3):i + 2])[:1200],
                "message": (f"修复特征：移除 sink={','.join(hit)}；新增检查={','.join(checks[:6]) or '-'}；"
                            f"目标同 sink 且未看到对应检查，建议人工核对")[:300],
                "precondition": "同源变体候选：需确认参数可达性与过滤差异",
            })
            if len(out) >= max_findings:
                return out
    return out


def fetch_patch(repo: str, base: str = "", head: str = "", commit: str = "",
                timeout: int = 30) -> str:
    """从 GitHub 拉 compare/commit 的 unified diff（只读，不克隆仓库）。
    用 curl --max-time 包住 DNS/TLS/传输，网络受限时快速失败。"""
    repo = (repo or "").strip().strip("/")
    if not re.match(r"^[\w.-]+/[\w.-]+$", repo):
        raise ValueError("repo 格式应为 owner/repo")
    if commit:
        url = f"https://api.github.com/repos/{repo}/commits/{commit}"
    elif base and head:
        url = f"https://api.github.com/repos/{repo}/compare/{base}...{head}"
    else:
        raise ValueError("需要 commit 或 base+head")
    cmd = ["curl", "-sS", "-L", "--max-time", str(timeout),
           "-H", "Accept: application/vnd.github.v3.diff",
           "-H", "User-Agent: iseecode-variant-scan", "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"GitHub diff 获取超时（>{timeout}s）")
    if p.returncode != 0:
        raise TimeoutError(f"GitHub diff 获取失败（curl {p.returncode}）：{p.stderr.decode(errors='ignore')[:120]}")
    data = p.stdout
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("diff 超过 32MB，已拒绝")
    return data.decode("utf-8", "replace")


def analyze(task_workspace: str, patch_text: str = "", repo: str = "",
            base: str = "", head: str = "", commit: str = "", cve: str = "",
            severity: str = "WARNING", max_findings: int = 50) -> dict:
    diff = patch_text or ""
    if not diff:
        diff = fetch_patch(repo=repo, base=base, head=head, commit=commit)
    features = extract_features(diff, cve=cve, repo=repo, commit=commit or f"{base}...{head}")
    findings = scan_workspace(task_workspace, features, severity=severity,
                              max_findings=max_findings)
    return {"features": features, "findings": findings,
            "summary": {"changed_files": features["stats"]["changed"],
                        "sinks": len(features["sinks"]),
                        "checks": len(features["checks"]),
                        "variant_candidates": len(findings)}}


def features_json(features: dict) -> str:
    return json.dumps(features, ensure_ascii=False)[:20000]
