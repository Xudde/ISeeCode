# -*- coding: utf-8 -*-
"""Windows 驱动（.sys）静态审计（阶段三）。

纯标准库解析 PE32/PE32+：机器/子系统/节/导入/导出/签名表/PDB/字符串，
按内核驱动攻击面输出风险线索。零 token、无外部依赖、不反汇编、不加载驱动。
所有结论均为启发式，需人工复核（尤其 DACL / IOCTL 参数校验）。
"""
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE_SIZE = 200 * 1024 * 1024
STRING_SCAN_LIMIT = 64 * 1024 * 1024
MAX_STRINGS = 40000

# 巨人引擎（可选，缺失时自动跳过）：capa 能力识别 + Ghidra 反汇编
CAPA_BIN = os.environ.get("AUDIT_CAPA_BIN", "/opt/giants/capa-venv/bin/capa")
CAPA_RULES = os.environ.get("AUDIT_CAPA_RULES", "/opt/giants/capa-rules-10")
CAPA_SIGS = os.environ.get("AUDIT_CAPA_SIGS", "/opt/giants/capa-src/sigs")
GHIDRA_HEADLESS = os.environ.get("AUDIT_GHIDRA_HEADLESS",
                                 "/usr/share/ghidra/support/analyzeHeadless")
GHIDRA_SCRIPT = Path(__file__).resolve().parent / "native_scripts" / "ExportDecompiled.java"
CAPA_TIMEOUT = int(os.environ.get("AUDIT_CAPA_TIMEOUT", "240"))
GHIDRA_TIMEOUT = int(os.environ.get("AUDIT_GHIDRA_TIMEOUT", "600"))

MACHINES = {
    0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C0: "ARM",
    0x01C4: "ARMv7 Thumb", 0x0200: "IA64", 0x5064: "RISC-V 64",
}
SUBSYSTEMS = {
    1: "native(内核)", 2: "Windows GUI", 3: "Windows CUI",
    9: "Windows CE", 10: "EFI 应用", 11: "EFI 引导驱动",
    12: "EFI 运行时驱动", 13: "EFI ROM", 14: "Xbox", 16: "Windows 引导",
}
DEVICE_RE = re.compile(r"(?i)\\(?:Device|DosDevices|BaseNamedObjects)\\[A-Za-z0-9_.\-]{1,80}")
DEVICE_ALT_RE = re.compile(r"\\\\\?\?\\[A-Za-z0-9_.\-]{1,80}")
URL_RE = re.compile(r"(?i)https?://[^\s\"'<>]{8,160}")

DEVICE_APIS = ("IoCreateDevice", "IoCreateDeviceSecure", "WdfDeviceCreate")
SYMLINK_APIS = ("IoCreateSymbolicLink", "IoRegisterDeviceInterface",
                "WdfDeviceCreateDeviceInterface")
IRP_APIS = ("IoGetCurrentIrpStackLocation", "IofCompleteRequest",
            "IoBuildDeviceIoControlRequest", "WdfRequestRetrieveInputBuffer",
            "WdfRequestRetrieveOutputBuffer")
MMIO_APIS = ("MmMapIoSpace", "MmMapIoSpaceEx", "MmGetPhysicalAddress")
PROCESS_APIS = ("ZwOpenProcess", "ZwOpenThread", "PsLookupProcessByProcessId",
                "KeStackAttachProcess", "MmCopyVirtualMemory", "ZwTerminateProcess",
                "ObOpenObjectByPointer", "ObReferenceObjectByHandle",
                "ZwProtectVirtualMemory", "ZwAllocateVirtualMemory",
                "NtOpenProcess", "NtOpenThread")
CALLBACK_APIS = ("PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
                 "PsSetLoadImageNotifyRoutine", "ObRegisterCallbacks",
                 "PsSetCreateThreadNotifyRoutine")


def _u16(data, off, default=0):
    try:
        return struct.unpack_from("<H", data, off)[0]
    except (struct.error, TypeError):
        return default


def _u32(data, off, default=0):
    try:
        return struct.unpack_from("<I", data, off)[0]
    except (struct.error, TypeError):
        return default


def _u64(data, off, default=0):
    try:
        return struct.unpack_from("<Q", data, off)[0]
    except (struct.error, TypeError):
        return default


def _cstr(data, off, maxlen=512):
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + maxlen))
    if end < 0:
        end = min(len(data), off + maxlen)
    return data[off:end].decode("ascii", "ignore")


def parse_pe(data: bytes) -> dict | None:
    """解析 PE 头/节/导入/导出/签名表/PDB；非法或截断返回 None。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = _u32(data, 0x3C)
    if pe_off < 0x40 or pe_off + 0x18 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    coff = pe_off + 4
    machine = _u16(data, coff)
    num_sections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    opt = coff + 20
    if opt_size < 60 or opt + opt_size > len(data):
        return None
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        return None
    is64 = magic == 0x20B
    entrypoint = _u32(data, opt + 16)
    size_image = _u32(data, opt + 56)
    size_headers = _u32(data, opt + 60)
    subsystem = _u16(data, opt + 68)
    dll_chars = _u16(data, opt + 70)
    image_base = _u64(data, opt + 24) if is64 else _u32(data, opt + 28)
    num_dirs = _u32(data, opt + (108 if is64 else 92))
    dd_off = opt + (112 if is64 else 96)
    dirs = []
    for i in range(min(num_dirs, 16)):
        o = dd_off + i * 8
        if o + 8 > len(data):
            break
        dirs.append((_u32(data, o), _u32(data, o + 4)))

    sections = []
    sec_off = opt + opt_size
    for i in range(min(num_sections, 96)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "ignore")
        vsize = _u32(data, o + 8)
        va = _u32(data, o + 12)
        raw_size = _u32(data, o + 16)
        raw_ptr = _u32(data, o + 20)
        sflags = _u32(data, o + 36)
        sections.append({
            "name": name, "vsize": vsize, "va": va,
            "raw_size": raw_size, "raw_ptr": raw_ptr, "flags": sflags,
            "exec": bool(sflags & 0x20000000), "write": bool(sflags & 0x80000000),
            "wx": bool((sflags & 0x20000000) and (sflags & 0x80000000)),
        })

    def rva_to_off(rva):
        if rva is None:
            return None
        if rva < size_headers and rva < len(data):
            return rva
        for s in sections:
            span = max(s["vsize"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                delta = rva - s["va"]
                if delta < s["raw_size"] and s["raw_ptr"] + delta < len(data):
                    return s["raw_ptr"] + delta
        return None

    imports: dict[str, list[str]] = {}
    if len(dirs) > 1 and dirs[1][0]:
        off = rva_to_off(dirs[1][0])
        if off is not None:
            for i in range(256):
                base = off + i * 20
                if base + 20 > len(data):
                    break
                oft = _u32(data, base)
                name_rva = _u32(data, base + 12)
                ft = _u32(data, base + 16)
                if not (oft or name_rva or ft):
                    break
                dll_off = rva_to_off(name_rva)
                dll = _cstr(data, dll_off) if dll_off is not None else ""
                funcs = []
                thunk_off = rva_to_off(oft or ft)
                if thunk_off is not None:
                    step = 8 if is64 else 4
                    flag = 1 << (63 if is64 else 31)
                    for j in range(3000):
                        o = thunk_off + j * step
                        if o + step > len(data):
                            break
                        val = _u64(data, o) if is64 else _u32(data, o)
                        if val == 0:
                            break
                        if val & flag:
                            funcs.append(f"#{val & 0xFFFF}")
                        else:
                            n_off = rva_to_off(val & 0x7FFFFFFF)
                            nm = _cstr(data, n_off + 2) if n_off is not None else ""
                            if nm:
                                funcs.append(nm)
                imports[dll or f"dll_{i}"] = funcs

    exports = []
    if len(dirs) > 0 and dirs[0][0]:
        off = rva_to_off(dirs[0][0])
        if off is not None:
            n_names = _u32(data, off + 24)
            names_rva = _u32(data, off + 32)
            names_off = rva_to_off(names_rva)
            if names_off is not None:
                for i in range(min(n_names, 500)):
                    o = names_off + i * 4
                    if o + 4 > len(data):
                        break
                    p = rva_to_off(_u32(data, o))
                    nm = _cstr(data, p) if p is not None else ""
                    if nm:
                        exports.append(nm)

    pdb = ""
    if len(dirs) > 6 and dirs[6][0]:
        off = rva_to_off(dirs[6][0])
        if off is not None:
            for i in range(min(dirs[6][1] // 28, 16)):
                base = off + i * 28
                if base + 28 > len(data):
                    break
                typ = _u32(data, base + 12)
                ptr = _u32(data, base + 24)
                if typ == 2 and ptr and ptr + 24 < len(data) and data[ptr:ptr + 4] == b"RSDS":
                    pdb = _cstr(data, ptr + 24, 260)
                    break

    cert_off, cert_size = (dirs[4] if len(dirs) > 4 else (0, 0))
    signed = bool(cert_off and cert_size >= 8)
    cert_type = _u16(data, cert_off + 6) if signed and cert_off + 8 <= len(data) else 0

    mitigations = {
        "ASLR": bool(dll_chars & 0x0040),
        "NX": bool(dll_chars & 0x0100),
        "CFG": bool(dll_chars & 0x4000),
        "ForceIntegrity": bool(dll_chars & 0x0080),
        "HighEntropyVA": bool(dll_chars & 0x0020),
    }

    return {
        "machine": machine, "is64": is64, "timestamp": timestamp,
        "characteristics": characteristics, "opt_size": opt_size,
        "entrypoint": entrypoint, "image_base": image_base,
        "size_image": size_image, "size_headers": size_headers,
        "subsystem": subsystem, "dll_chars": dll_chars,
        "sections": sections, "dirs": dirs,
        "imports": imports, "exports": exports,
        "pdb": pdb, "signed": signed, "signature_size": cert_size,
        "cert_type": cert_type, "mitigations": mitigations,
    }


def _collect_strings(data: bytes) -> list[str]:
    chunk = data[:STRING_SCAN_LIMIT]
    ascii_raw = re.findall(rb"[\x20-\x7e]{4,}", chunk)
    utf16_raw = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", chunk)
    out, seen = [], set()
    for raw in ascii_raw:
        s = raw.decode("latin1").strip()
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= MAX_STRINGS:
                return out
    for raw in utf16_raw:
        s = raw.decode("utf-16le", "ignore").strip()
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= MAX_STRINGS:
                break
    return out


def _v(rule: str, severity: str, title: str, snippet: str,
       message: str = "", file_path: str = "") -> dict:
    return {
        "source": "native", "rule_id": rule, "title": title,
        "severity": severity, "file_path": file_path, "line": 0,
        "code_snippet": snippet[:1500], "message": message,
    }


def _collect_capa_apis(node, out: set) -> None:
    """从 capa match 树里收集命中的 API/特征名（用于证据展示）"""
    if isinstance(node, dict):
        feat = node.get("feature")
        if isinstance(feat, dict):
            if feat.get("api"):
                out.add(str(feat["api"]))
            if feat.get("characteristic"):
                out.add(str(feat["characteristic"]))
            if feat.get("string"):
                out.add(str(feat["string"])[:40])
        for v in node.values():
            _collect_capa_apis(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_capa_apis(v, out)


def _run_cmd(cmd: list[str], timeout: int, env=None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)
    except OSError as e:
        return 126, "", str(e)


def _capa_findings(path: str, display: str, log) -> list[dict]:
    """capa 能力识别（巨人）：规则匹配驱动能力，转成平台 findings。缺失时静默跳过。"""
    if os.environ.get("AUDIT_CAPA", "1") != "1":
        return []
    if not (Path(CAPA_BIN).exists() and Path(CAPA_RULES).is_dir() and Path(CAPA_SIGS).is_dir()):
        log("capa 未安装/规则缺失，跳过能力识别")
        return []
    log("capa 能力识别…")
    rc, out, err = _run_cmd([CAPA_BIN, "-r", CAPA_RULES, "--signatures", CAPA_SIGS,
                             "-j", path], CAPA_TIMEOUT)
    if rc != 0:
        log(f"capa 执行失败（跳过）: {(err or out)[-200:]}")
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        log("capa 输出解析失败（跳过）")
        return []
    rules = data.get("rules") or {}
    found = []
    for name, r in rules.items():
        meta = (r or {}).get("meta") or {}
        ns = str(meta.get("namespace") or "")
        if not ns:
            continue  # 过滤 contain loop 等通用规则
        matches = (r or {}).get("matches") or []
        apis, addrs = set(), []
        for m in matches:
            try:
                addr = m[0].get("value")
                if addr:
                    addrs.append(int(addr))
            except (AttributeError, TypeError, ValueError, IndexError):
                pass
            _collect_capa_apis(m, apis)
        risky = any(k in ns for k in (
            "process", "memory", "privilege", "persistence", "anti-analysis",
            "communication", "load-code", "user32", "driver"))
        # 驱动创建设备/完成 IRP 属于正常能力，不宜标 WARNING；只对进程/内存/对抗类提级
        severity = "WARNING" if risky and not ns.startswith("host-interaction/driver") else "INFO"
        desc = str(meta.get("description") or "").strip()
        snippet = (f"capa: {name} | namespace={ns} | 匹配 {len(matches)} 处"
                   + (f" | 地址 {', '.join(hex(a) for a in addrs[:5])}" if addrs else "")
                   + (f" | API/特征: {', '.join(sorted(apis)[:10])}" if apis else ""))
        slug = re.sub(r"[^a-z0-9]+", "-", f"{ns}-{name}".lower()).strip("-")[:100]
        found.append({
            "source": "capa",
            "rule_id": f"capa:{slug}",
            "title": f"capa 能力：{name}"[:120],
            "severity": severity,
            "file_path": display,
            "line": 0,
            "code_snippet": snippet[:1500],
            "message": desc[:300] or f"capa 能力规则命中（{ns}）",
        })
    if found:
        summary = "\n".join(f"- {f['title']} [{f['severity']}]" for f in found[:20])
        found.insert(0, {
            "source": "capa",
            "rule_id": "capa:capability-summary",
            "title": f"capa 能力画像（{len(found)} 项）",
            "severity": "INFO",
            "file_path": display,
            "line": 0,
            "code_snippet": summary[:1500],
            "message": "基于 capa 规则的驱动能力识别；能力不等于漏洞，需结合业务权限判断",
        })
        log(f"capa 命中 {len(found) - 1} 项能力")
    else:
        log("capa 未命中能力规则")
    return found


def _ghidra_findings(path: str, display: str, artifact_dir: str | None, log) -> list[dict]:
    """Ghidra headless 反汇编并导出伪 C（巨人），产物供人工/IDE 深挖。"""
    if os.environ.get("AUDIT_GHIDRA", "1") != "1" or not artifact_dir:
        return []
    if not (Path(GHIDRA_HEADLESS).exists() and GHIDRA_SCRIPT.exists()):
        log("Ghidra 未安装/脚本缺失，跳过反汇编导出")
        return []
    out_dir = Path(artifact_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return []
    out_c = out_dir / f"{Path(path).stem}.decompiled.c"
    proj = tempfile.mkdtemp(prefix="ghidra_drv_")
    env = os.environ.copy()
    env["GHIDRA_DECOMP_OUT"] = str(out_c)
    log(f"Ghidra 反汇编中（可能需要 10-30 秒）→ {out_c.name}")
    cmd = [GHIDRA_HEADLESS, proj, "drvproj", "-import", path, "-overwrite",
           "-analysisTimeoutPerFile", "180", "-scriptPath", str(GHIDRA_SCRIPT.parent),
           "-postScript", GHIDRA_SCRIPT.name, "-deleteProject"]
    try:
        rc, out, err = _run_cmd(cmd, GHIDRA_TIMEOUT, env=env)
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    if rc != 0 or not out_c.exists():
        log(f"Ghidra 失败（跳过）rc={rc}: {(err or out)[-200:]}")
        return []
    try:
        text = out_c.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    funcs = re.findall(r"/\* FUNC (.+?) @ ([0-9a-fx]+) \*/", text)
    if not funcs:
        log("Ghidra 未导出函数（跳过）")
        return []
    names = [f"{n}@{a}" for n, a in funcs[:20]]
    log(f"Ghidra 导出 {len(funcs)} 个函数")
    return [{
        "source": "ghidra",
        "rule_id": "windows-driver:ghidra-decompiled",
        "title": f"Ghidra 反汇编/伪 C 已导出（{len(funcs)} 个函数）",
        "severity": "INFO",
        "file_path": display,
        "line": 0,
        "code_snippet": (f"伪 C: {out_c}\n函数: " + ", ".join(names))[:1500],
        "message": "供人工/IDE Agent 深挖 IOCTL 与参数校验；平台不自动判定反汇编逻辑漏洞",
    }]


def _fingerprint(summary: dict) -> dict:
    comps = ["Windows Kernel Driver"]
    if summary.get("driver_model") and summary["driver_model"] != "unknown":
        comps.append(f"{summary['driver_model']} 驱动")
    if summary.get("signed"):
        comps.append("已签名驱动")
    return {
        "components": comps,
        "lang_stats": {"native": 1},
        "total_files": 1,
        "driver": summary,
    }


def analyze(path: str, log_fn=None, deep: bool = True,
            artifact_dir: str | None = None) -> dict:
    """分析单个 .sys；返回 {findings, summary, fingerprint}。
    deep=True 时追加 capa 能力识别 + Ghidra 反汇编导出（缺失则自动跳过）。"""
    log = log_fn or (lambda m: None)
    p = Path(path)
    name = p.name
    try:
        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ValueError("文件超过 200MB")
        data = p.read_bytes()
    except (OSError, ValueError) as e:
        err = _v("windows-driver:parse-error", "WARNING", "驱动文件读取失败",
                 f"{name}: {e}", "无法读取驱动文件", name)
        summary = {"file": name, "size": 0, "valid_pe": False}
        return {"findings": [err], "summary": summary,
                "fingerprint": {"components": ["Windows 驱动（读取失败）"],
                                "lang_stats": {"native": 1}, "total_files": 1}}

    info = parse_pe(data)
    if info is None:
        err = _v("windows-driver:parse-error", "WARNING", "驱动 PE 解析失败（非标准 PE/加壳/损坏）",
                 f"{name}（{size} 字节）无法解析 MZ/PE 头",
                 "文件可能是非 PE、加壳或损坏；无法继续做导入/签名分析", name)
        summary = {"file": name, "size": size, "valid_pe": False}
        return {"findings": [err], "summary": summary,
                "fingerprint": {"components": ["Windows 驱动（PE 解析失败）"],
                                "lang_stats": {"native": 1}, "total_files": 1}}

    imports = info["imports"]
    all_funcs = {f for fs in imports.values() for f in fs if f}
    dll_names = {d.lower() for d in imports}
    import_count = sum(len(fs) for fs in imports.values())
    kernel_dlls = [d for d in imports if "ntoskrnl" in d.lower() or "ntkrnl" in d.lower()
                   or "hal.dll" in d.lower() or "wdfldr" in d.lower()]
    wdf = any(f.startswith("Wdf") for f in all_funcs) or "wdfldr.sys" in dll_names
    wdm = bool(kernel_dlls) or any(f.startswith(("Io", "Ke", "Mm", "Ob", "Ps", "Zw", "Ex", "Se"))
                                   for f in all_funcs)
    model = "WDF" if wdf else ("WDM" if wdm else "unknown")
    is_kernel = info["subsystem"] == 1 or bool(kernel_dlls)

    strings = _collect_strings(data)
    device_names, urls = [], []
    for s in strings:
        if len(device_names) < 8:
            for m in DEVICE_RE.finditer(s):
                if m.group(0) not in device_names:
                    device_names.append(m.group(0))
            for m in DEVICE_ALT_RE.finditer(s):
                if m.group(0) not in device_names:
                    device_names.append(m.group(0))
        if len(urls) < 5:
            for m in URL_RE.finditer(s):
                if m.group(0) not in urls:
                    urls.append(m.group(0))
    pdb = info["pdb"] or next((s for s in strings if s.lower().endswith(".pdb")), "")
    wx_sections = [s["name"] for s in info["sections"] if s["wx"]]
    missing_mit = [k for k, v in info["mitigations"].items() if not v and k in ("ASLR", "NX", "CFG")]

    try:
        ts_txt = (datetime.fromtimestamp(info["timestamp"], tz=timezone.utc)
                  .strftime("%Y-%m-%d %H:%M UTC") if info["timestamp"] else "未知")
    except (OSError, OverflowError, ValueError):
        ts_txt = "未知"

    machine_cn = MACHINES.get(info["machine"], f"0x{info['machine']:04X}")
    subsystem_cn = SUBSYSTEMS.get(info["subsystem"], f"未知({info['subsystem']})")
    signed_txt = (f"有（证书表 {info['signature_size']} 字节，未验签）"
                  if info["signed"] else "无嵌入签名（可能目录签名）")
    mit_txt = " ".join(f"{k}{'✓' if v else '✗'}" for k, v in info["mitigations"].items())
    summary_text = (
        f"{machine_cn} | 子系统 {subsystem_cn} | {model} | {size / 1024:.1f}KB | 签名 {signed_txt} | "
        f"导入 {import_count}（{', '.join(sorted(imports)[:4]) or '无'}） | 导出 {len(info['exports'])} | "
        f"节 {len(info['sections'])} | 缓解 {mit_txt}"
    )
    summary = {
        "file": name, "size": size, "valid_pe": True,
        "machine": machine_cn, "subsystem": subsystem_cn,
        "is_kernel_driver": is_kernel, "driver_model": model,
        "signed": info["signed"], "signature_size": info["signature_size"],
        "timestamp": ts_txt, "image_size": info["size_image"],
        "sections": len(info["sections"]), "wx_sections": wx_sections,
        "import_dlls": sorted(imports), "import_count": import_count,
        "export_count": len(info["exports"]), "pdb": pdb,
        "device_names": device_names, "urls": urls,
        "mitigations": info["mitigations"],
        "wdf": wdf, "secure_device_api": "IoCreateDeviceSecure" in all_funcs,
        "raw_summary": summary_text,
    }
    log(f"驱动画像: {summary_text}")
    if pdb:
        log(f"PDB: {pdb}")
    if device_names:
        log(f"设备/符号链接名: {', '.join(device_names[:5])}")

    findings = [_v("windows-driver:summary", "INFO", "驱动静态画像（PE 元数据）",
                   summary_text, "静态解析结果，供人工建立攻击面视图", name)]

    if not is_kernel:
        findings.append(_v("windows-driver:not-kernel", "WARNING", "PE 不像标准内核驱动",
                           f"subsystem={subsystem_cn}; machine={machine_cn}; "
                           f"kernel DLLs={kernel_dlls or '无'}; imports={import_count}",
                           "可能是普通 DLL/EXE、用户态组件，或导入表被加壳；驱动结论需谨慎", name))
    if not info["signed"]:
        findings.append(_v("windows-driver:unsigned", "WARNING",
                           "未发现嵌入数字签名（需核对目录签名/加载策略）",
                           "Security Directory 为空（PE 安全目录 offset/size = 0）",
                           "系统自带驱动常用目录签名（.cat），本工具在 Linux 上只能检测"
                           "嵌入证书表，无法验证目录签名信任链；请在 Windows 上运行 "
                           "Get-AuthenticodeSignature 复核。若确实无签名，则存在 BYOVD 加载风险", name))
    if wx_sections:
        findings.append(_v("windows-driver:writable-code", "WARNING", "存在可写+可执行节（W+X）",
                           "节: " + ", ".join(wx_sections),
                           "代码节同时可写可执行，可能被用于运行期打补丁/载荷注入；需结合入口逻辑复核", name))
    if "IoCreateDevice" in all_funcs and "IoCreateDeviceSecure" not in all_funcs and not wdf:
        findings.append(_v("windows-driver:device-exposure", "WARNING",
                           "设备对象创建未见安全描述符 API（需复核 DACL）",
                           "导入 IoCreateDevice，未见 IoCreateDeviceSecure；"
                           "也未使用 WDF 设备对象",
                           "用户态能否打开设备取决于创建后的安全描述符；请找到 IRP_MJ_CREATE/"
                           "DEVICE_CONTROL 处理与访问校验", name))
    if any(f in all_funcs for f in SYMLINK_APIS):
        hit = [f for f in SYMLINK_APIS if f in all_funcs]
        findings.append(_v("windows-driver:symbolic-link", "WARNING",
                           "驱动创建用户态可访问接口（符号链接/设备接口）",
                           "导入: " + ", ".join(hit),
                           "符号链接/设备接口是用户态进入驱动的入口；需确认访问控制与 IOCTL 权限", name))
    if wdf and "WdfDeviceCreate" in all_funcs:
        findings.append(_v("windows-driver:wdf-device", "INFO",
                           "WDF 设备对象（需确认 SDDL/访问控制）",
                           "WdfDeviceCreate 在导入表中",
                           "WDF 可将安全描述符交给框架托管，但仍需确认 SDDL 字符串与队列权限", name))
    if any(f in all_funcs for f in IRP_APIS):
        hit = [f for f in IRP_APIS if f in all_funcs]
        findings.append(_v("windows-driver:ioctl-surface", "INFO",
                           "存在 IRP/IOCTL 处理迹象（需人工审查控制码）",
                           "导入: " + ", ".join(hit),
                           "静态无法还原 IRP 分发表；请人工确认 IOCTL 控制码、输入/输出缓冲区长度、"
                           "调用者权限与 ProbeForRead/Write 使用", name))
    mmio = [f for f in MMIO_APIS if f in all_funcs]
    if mmio:
        findings.append(_v("windows-driver:mmio", "WARNING",
                           "物理内存映射原语（MmMapIoSpace）",
                           "导入: " + ", ".join(mmio),
                           "可导致任意物理内存读写；需确认 IOCTL 是否限制地址范围与调用者权限", name))
    proc = [f for f in PROCESS_APIS if f in all_funcs]
    if proc:
        findings.append(_v("windows-driver:process-memory", "WARNING",
                           "跨进程内存/句柄操作原语",
                           "导入: " + ", ".join(proc),
                           "需确认目标进程/句柄的来源与权限校验；此类原语是 BYOVD/EDR 绕过常见组件", name))
    callbacks = [f for f in CALLBACK_APIS if f in all_funcs]
    if callbacks:
        findings.append(_v("windows-driver:callbacks", "INFO",
                           "注册内核回调（进程/镜像/句柄监控）",
                           "导入: " + ", ".join(callbacks),
                           "属于高权限攻击面；需确认回调注册/注销与数据来源", name))
    if missing_mit:
        findings.append(_v("windows-driver:missing-mitigations", "INFO",
                           "驱动编译缓解措施缺失",
                           "未启用: " + ", ".join(missing_mit) + "（" + mit_txt + "）",
                           "缓解缺失不等于漏洞，但会降低利用门槛；建议核对构建配置", name))
    if pdb:
        findings.append(_v("windows-driver:pdb-path", "INFO", "PE 调试信息包含 PDB 路径（构建信息泄露）",
                           f"PDB: {pdb}",
                           "PDB 路径可能泄露构建目录/符号线索，便于漏洞研究；生产驱动建议剥离", name))
    if device_names:
        findings.append(_v("windows-driver:device-names", "INFO",
                           "驱动包含设备/符号链接名（用户态入口线索）",
                           "; ".join(device_names[:8]),
                           "可用于确认设备对象是否暴露给用户态；与 IoCreateDevice/符号链接导入交叉验证", name))
    if urls:
        findings.append(_v("windows-driver:network-indicators", "INFO",
                           "驱动包含 URL/网络地址（更新/回连线索）",
                           "; ".join(urls[:5]),
                           "内核驱动通常不应主动联网；需确认用途（更新/遥测/回调）", name))
    if not imports:
        findings.append(_v("windows-driver:imports-none", "WARNING", "驱动无导入表（加壳/损坏/极简样本）",
                           "Import Directory 为空或解析失败",
                           "正常 WDM/WDF 驱动会导入 ntoskrnl/wdfldr；无导入表需确认是否加壳或非完整 PE", name))

    if deep:
        findings += _capa_findings(path, name, log)
        findings += _ghidra_findings(path, name, artifact_dir, log)

    return {"findings": findings, "summary": summary, "fingerprint": _fingerprint(summary)}
