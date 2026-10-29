# -*- coding: utf-8 -*-
"""项目自身版本 CVE（OSV）：trivy 只查依赖，查不到 Tomcat/Next.js 这类
“项目本身版本”的 CVE。这里从 manifest 提取 name+version，查 OSV。
只发送包名与版本号，不上传源码；AUDIT_SELF_CVE=0 可关闭。"""
import json
import os
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

OSV_API = "https://api.osv.dev/v1/query"
SKIP_DIRS = {"node_modules", ".git", "vendor", "third_party", "thirdparty",
             "dist", "build", "target", "test", "tests", "docs", "examples",
             "example", "samples", ".venv", "venv", "__pycache__", ".next"}
MAX_MANIFESTS = 15
MAX_CANDIDATES = 12
MAX_RESULTS = 120
TIME_BUDGET = 90
SEMVER_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")


def _log(fn, m):
    (fn or (lambda x: None))("自版本 CVE: " + m)


def _version_hint(task_name: str) -> str:
    m = SEMVER_RE.search(task_name or "")
    return m.group(1) if m else ""


def _line_of(path: Path, needle: str) -> int:
    try:
        for i, line in enumerate(path.read_text(errors="ignore").splitlines()[:2000], 1):
            if needle in line:
                return i
    except OSError:
        pass
    return 0


def _manifests(root: Path, names: set[str], max_depth: int = 4):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        if len(rel.parts) > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for name in filenames:
            if name.lower() in names:
                out.append(Path(dirpath) / name)
                if len(out) >= MAX_MANIFESTS:
                    return out
    return out


def _xml_text(node) -> str:
    if node is None:
        return ""
    return (node.text or "").strip() if node.tag else ""


def _maven_candidates(root: Path) -> list[tuple[str, str, str, Path]]:
    out = []
    for pom in _manifests(root, {"pom.xml"}, max_depth=3):
        try:
            data = ET.parse(pom).getroot()
        except Exception:
            continue
        tag = lambda n: n.tag.split("}")[-1] if isinstance(n.tag, str) else ""
        parent = next((c for c in data if tag(c) == "parent"), None)
        group = _xml_text(next((c for c in data if tag(c) == "groupId"), None))
        artifact = _xml_text(next((c for c in data if tag(c) == "artifactId"), None))
        version = _xml_text(next((c for c in data if tag(c) == "version"), None))
        if not group and parent is not None:
            group = _xml_text(next((c for c in parent if tag(c) == "groupId"), None))
        if not version and parent is not None:
            version = _xml_text(next((c for c in parent if tag(c) == "version"), None))
        if group and artifact and re.match(r"^\d+\.\d+", version):
            out.append(("Maven", f"{group}:{artifact}", version, pom))
    # Tomcat 是 Ant 构建，没有根 pom；用 build.properties.default 还原版本
    bp = root / "build.properties.default"
    if bp.exists() and (root / "java" / "org" / "apache" / "catalina").is_dir():
        try:
            txt = bp.read_text(errors="ignore")
            major = re.search(r"^version\.major=(\d+)", txt, re.M)
            minor = re.search(r"^version\.minor=(\d+)", txt, re.M)
            build = re.search(r"^version\.build=(\d+)", txt, re.M)
            if major and minor and build:
                ver = f"{major.group(1)}.{minor.group(1)}.{build.group(1)}"
                out.append(("Maven", "org.apache.tomcat:tomcat-catalina", ver, bp))
        except OSError:
            pass
    return out


def _package_json_candidates(root: Path) -> list[tuple[str, str, str, Path]]:
    out = []
    for pkg in _manifests(root, {"package.json"}, max_depth=4):
        try:
            d = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        name = d.get("name")
        ver = str(d.get("version") or "")
        if isinstance(name, str) and name and re.match(r"^\d+\.\d+\.\d+", ver):
            out.append(("npm", name, ver, pkg))
    return out


def _pyproject_candidates(root: Path, hint: str) -> list[tuple[str, str, str, Path]]:
    out = []
    for pp in _manifests(root, {"pyproject.toml"}, max_depth=4):
        try:
            txt = pp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        name = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', txt, re.M)
        ver = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', txt, re.M)
        if not name:
            continue
        version = ver.group(1) if ver else hint
        if re.match(r"^\d+\.\d+\.\d+", version):
            out.append(("PyPI", name.group(1), version, pp))
    return out


def _go_candidates(root: Path, hint: str) -> list[tuple[str, str, str, Path]]:
    out = []
    if not hint:
        return out
    for gm in _manifests(root, {"go.mod"}, max_depth=2):
        try:
            txt = gm.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = re.search(r"^module\s+(\S+)", txt, re.M)
        if m:
            ver = hint if hint.startswith("v") else "v" + hint
            out.append(("Go", m.group(1), ver, gm))
    return out


def _osv(eco: str, name: str, version: str) -> dict:
    body = json.dumps({"package": {"name": name, "ecosystem": eco},
                       "version": version}).encode()
    req = urllib.request.Request(OSV_API, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode())


def _cve_of(v: dict) -> str:
    for a in (v.get("aliases") or []):
        if str(a).startswith("CVE-"):
            return a
    return str(v.get("id") or "")


def _severity(v: dict) -> str:
    sev = str((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"CRITICAL": "ERROR", "HIGH": "ERROR", "MODERATE": "WARNING",
            "MEDIUM": "WARNING", "LOW": "INFO"}.get(sev, "WARNING")


def _fixed(v: dict) -> str:
    for aff in (v.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def scan(workspace: str, task_name: str = "", log_fn=None) -> list[dict]:
    if os.environ.get("AUDIT_SELF_CVE", "1") != "1":
        return []
    root = Path(workspace)
    if not root.is_dir():
        return []
    hint = _version_hint(task_name)
    candidates = (_maven_candidates(root) + _package_json_candidates(root)
                  + _pyproject_candidates(root, hint) + _go_candidates(root, hint))
    seen, uniq = set(), []
    for eco, name, ver, path in candidates:
        key = (eco, name, ver)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((eco, name, ver, path))
    if not uniq:
        _log(log_fn, "未找到可识别版本的项目清单（pom/package.json/pyproject/go.mod）")
        return []
    uniq = uniq[:MAX_CANDIDATES]
    _log(log_fn, f"清单候选 {len(uniq)} 个（{hint or '无版本提示'}），查询 OSV…")
    deadline = time.monotonic() + TIME_BUDGET
    vulns, errors = [], 0
    for eco, name, ver, path in uniq:
        if time.monotonic() > deadline:
            _log(log_fn, "OSV 查询超预算，提前结束")
            break
        try:
            data = _osv(eco, name, ver)
        except Exception:
            errors += 1
            continue
        for v in (data.get("vulns") or []):
            cve = _cve_of(v)
            if not cve:
                continue
            fixed = _fixed(v)
            summary = str(v.get("summary") or v.get("details") or "")[:160]
            line = _line_of(path, ver)
            vulns.append({
                "source": "giants",
                "rule_id": f"giants:self-cve:{cve}"[:128],
                "title": f"{name} {ver}: {cve}"[:120],
                "severity": _severity(v),
                "file_path": str(path.relative_to(root)).replace("\\", "/"),
                "line": line,
                "code_snippet": (f"{name} {ver} → 修复 {fixed or '见公告'}"
                                 + (f"；{summary}" if summary else ""))[:500],
                "message": (f"OSV {v.get('id')} · "
                            f"https://osv.dev/vulnerability/{v.get('id')}")[:300],
            })
    vulns.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x["severity"], 3))
    if len(vulns) > MAX_RESULTS:
        vulns = vulns[:MAX_RESULTS]
    _log(log_fn, f"OSV 命中 {len(vulns)} 条（查询失败 {errors} 个包）")
    return vulns
