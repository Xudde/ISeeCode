# -*- coding: utf-8 -*-
"""MobSF APK 静态分析引擎（阶段四，可选巨人）。

通过 curl 调用本机 MobSF REST API（upload → scan），映射为平台 findings。
不新增 Python 依赖；MobSF 未启动/未配置 Key 时自动跳过。
"""
import json
import os
import re
import subprocess
from pathlib import Path

MOBSF_URL = os.environ.get("AUDIT_MOBSF_URL", "http://127.0.0.1:8010").rstrip("/")
MOBSF_KEY = os.environ.get("AUDIT_MOBSF_KEY", "")
MAX_FINDINGS = int(os.environ.get("AUDIT_MOBSF_MAX_FINDINGS", "150"))


def _sev(level) -> str:
    s = str(level or "").lower()
    if s in ("high", "critical", "error"):
        return "ERROR"
    if s in ("warning", "medium", "hotspot"):
        return "WARNING"
    return "INFO"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")[:80] or "finding"


def _curl(args: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(["curl", "-sS", f"--max-time", str(timeout)] + args,
                           capture_output=True, text=True, timeout=timeout + 10)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 127, "", str(e)


def _finding(title: str, severity: str, desc: str, rule: str,
             file_name: str, message: str = "") -> dict:
    return {
        "source": "mobsf",
        "rule_id": f"mobsf:{_slug(rule)}"[:128],
        "title": str(title or rule or "MobSF 发现")[:120],
        "severity": severity,
        "file_path": file_name,
        "line": 0,
        "code_snippet": str(desc or title or "")[:1000],
        "message": str(message or "")[:300],
    }


def scan(apk_path: str, log_fn=None) -> list[dict]:
    log = log_fn or (lambda m: None)
    if os.environ.get("AUDIT_MOBSF", "1") != "1":
        return []
    if not MOBSF_KEY:
        log("MobSF 未配置 API Key（AUDIT_MOBSF_KEY），跳过")
        return []
    p = Path(apk_path)
    if not p.is_file():
        return []
    rc, out, err = _curl(["-H", f"Authorization: {MOBSF_KEY}",
                          "-F", f"file=@{p}", f"{MOBSF_URL}/api/v1/upload"], 180)
    if rc != 0:
        log(f"MobSF 上传失败（跳过）: {err[-160:]}")
        return []
    try:
        meta = json.loads(out)
    except json.JSONDecodeError:
        log("MobSF 上传返回非 JSON（跳过）")
        return []
    if meta.get("status") != "success":
        log(f"MobSF 上传失败: {str(meta)[:160]}")
        return []
    h = meta.get("hash")
    fname = meta.get("file_name") or p.name
    log(f"MobSF 上传成功，开始静态扫描（30-120 秒）… {fname}")
    rc, out, err = _curl(["-H", f"Authorization: {MOBSF_KEY}", "-X", "POST",
                          "-F", "scan_type=apk", "-F", f"file_name={fname}",
                          "-F", f"hash={h}", f"{MOBSF_URL}/api/v1/scan"], 900)
    if rc != 0:
        log(f"MobSF 扫描失败（跳过）: {err[-160:]}")
        return []
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        log("MobSF 扫描返回非 JSON（跳过）")
        return []
    log(f"MobSF 扫描完成：app={report.get('app_name') or '-'} "
        f"package={report.get('package_name') or '-'}")
    return _map_report(report, p.name, log)


def _map_report(report: dict, file_name: str, log) -> list[dict]:
    out, seen = [], set()

    def add(title, sev, desc, rule, message=""):
        key = (str(rule), str(title))
        if key in seen:
            return
        seen.add(key)
        out.append(_finding(title, sev, desc, rule, file_name, message))

    appsec = report.get("appsec") or {}
    for level in ("high", "warning", "info", "hotspot"):
        for item in (appsec.get(level) or []):
            if isinstance(item, dict):
                add(item.get("title"), _sev(level), item.get("description"),
                    f"appsec-{item.get('section') or ''}-{item.get('title')}",
                    item.get("section") or "")
    for item in ((report.get("manifest_analysis") or {}).get("manifest_findings") or []):
        if isinstance(item, dict):
            add(item.get("title"), _sev(item.get("severity")),
                item.get("description"), f"manifest-{item.get('rule') or item.get('title')}")
    for item in ((report.get("certificate_analysis") or {}).get("certificate_findings") or []):
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            add(item[2], _sev(item[0]), item[2], f"certificate-{item[1]}")
        elif isinstance(item, dict):
            add(item.get("title"), _sev(item.get("severity")),
                item.get("description"), f"certificate-{item.get('title')}")
    for item in ((report.get("network_security") or {}).get("network_findings") or []):
        if isinstance(item, dict):
            add(item.get("title"), _sev(item.get("severity")),
                item.get("description"), f"network-{item.get('title')}")
    for item in (report.get("secrets") or []):
        if isinstance(item, dict):
            title = item.get("title") or "硬编码敏感信息"
            add(title, "WARNING", item.get("description") or item.get("match") or "",
                f"secret-{title}", "请确认密钥有效性并轮换")
    exported = report.get("exported_count") or {}
    if isinstance(exported, dict) and any(int(v or 0) > 0 for v in exported.values()):
        add("存在导出组件（需确认访问控制）", "WARNING",
            json.dumps(exported, ensure_ascii=False), "exported-components",
            "导出的 Activity/Service/Receiver/Provider 可能被第三方应用调用")
    n_tr = int((report.get("trackers") or {}).get("detected_trackers") or 0)
    if n_tr > 0:
        add(f"检测到 {n_tr} 个跟踪器", "INFO",
            json.dumps((report.get("trackers") or {}).get("trackers") or [],
                       ensure_ascii=False)[:800], "trackers")
    perms = report.get("malware_permissions") or report.get("permissions") or {}
    if isinstance(perms, dict) and perms:
        add("APK 权限/恶意权限特征", "INFO",
            json.dumps(perms, ensure_ascii=False)[:800], "permissions")

    summary = (f"app={report.get('app_name') or '-'} | package={report.get('package_name') or '-'} | "
               f"version={report.get('version_name') or '-'} | security_score={appsec.get('security_score')} | "
               f"trackers={n_tr}")
    out.insert(0, _finding("MobSF APK 静态画像", "INFO", summary, "summary",
                           file_name, "MobSF 静态分析结果汇总"))
    out.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(x["severity"], 3))
    log(f"MobSF 产出 {len(out)} 条线索（security_score={appsec.get('security_score')}）")
    return out[:MAX_FINDINGS]
