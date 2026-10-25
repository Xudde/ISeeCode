"""反编译 skill（升级阶段 2）：jar/apk/dex/dotnet/pyc/go 二进制 → 源码，失败降级字符串特征扫描"""
import hashlib
import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from app.config import TASK_TIMEOUT, DATA_DIR

log = logging.getLogger("decompile")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # source-audit-platform/
TOOLS_DIR = Path(os.environ.get("AUDIT_DECOMPILER_DIR", PROJECT_ROOT / "tools" / "decompilers"))
CACHE_DIR = DATA_DIR / "decompiled_cache"  # 绝对路径，避免依赖运行目录

# 工具可用性缓存（进程内）
_tool_ok: dict[str, bool] = {}


def _which(name: str) -> bool:
    if name in _tool_ok:
        return _tool_ok[name]
    _tool_ok[name] = shutil.which(name) is not None
    return _tool_ok[name]


def _java_jar_ok(jar_name: str) -> bool:
    """java + 指定 jar 是否可用"""
    if not _which("java"):
        return False
    jar = TOOLS_DIR / jar_name
    return jar.exists() and jar.stat().st_size > 100_000


def tool_status() -> dict[str, bool]:
    """各反编译工具可用性（用于日志与前端提示）"""
    return {
        "cfr": _java_jar_ok("cfr.jar"),
        "jadx": (TOOLS_DIR / "jadx" / "bin" / "jadx").exists() or _which("jadx"),
        "apktool": _java_jar_ok("apktool.jar"),
        "ilspycmd": _which("ilspycmd"),
        "pycdc": _which("pycdc"),
        "redress": _which("redress"),
    }


def detect_kind(filename: str) -> str | None:
    """按扩展名判断反编译类型；None 表示不是反编译输入"""
    name = filename.lower()
    if name.endswith((".jar", ".war")) or name.endswith(".class"):
        return "java"
    if name.endswith((".apk", ".dex")):
        return "android"
    if name.endswith((".dll", ".exe")):
        return "dotnet"
    if name.endswith(".pyc"):
        return "python"
    if name.endswith((".so", ".elf", ".bin")):
        return "native"
    return None


# 每类的主产物语言（用于扫描栈）
KIND_LANG = {"java": "java", "android": "java", "dotnet": "csharp",
             "python": "python", "native": "cpp"}


def _run(cmd: list[str], timeout: int = TASK_TIMEOUT) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr)[-500:]
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError as e:
        return 127, str(e)


def _cache_get(filepath: str, kind: str, log_fn) -> Path | None:
    """查反编译缓存（v2 格式），命中返回缓存目录。
    v1 缓存（.done 标记）产自"共享输出目录整目录快照"时代，内容互相污染
    （A 二进制缓存里混着 B/C 的源码），一律视为失效，按未命中重新反编译。"""
    try:
        h = hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
    except OSError:
        return None
    cache = CACHE_DIR / f"{kind}_{h[:32]}"
    if (cache / ".v2").exists():
        log_fn(f"命中反编译缓存(v2): {cache.name}")
        return cache
    return None


def _cache_put(filepath: str, kind: str, src_dir: Path) -> Path | None:
    """把「本二进制自己的」产物 src/ 目录写入缓存（只存增量，绝不含其他二进制的产物）。"""
    try:
        h = hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
    except OSError:
        return None
    cache = CACHE_DIR / f"{kind}_{h[:32]}"
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if cache.exists():
            shutil.rmtree(cache, ignore_errors=True)
        if src_dir.exists():
            shutil.copytree(src_dir, cache / "src", dirs_exist_ok=True)
        else:
            (cache / "src").mkdir(parents=True, exist_ok=True)
        (cache / ".v2").touch()
    except OSError as e:
        log.warning("写反编译缓存失败: %s", e)
        return None
    return cache


def _merge_src(src_dir: Path, out: Path) -> None:
    """把一份反编译产物 src/ 合并进共享输出目录（合并语义，绝不 rmtree：
    保护其他二进制已合并的产物；同名文件覆盖，不同命名共存）。"""
    if not src_dir.is_dir():
        return
    shutil.copytree(src_dir, out / "src", dirs_exist_ok=True)


def _unzip_safe(zip_path, dest) -> bool:
    """安全解压（防 Zip Slip）"""
    dest = Path(dest)
    try:
        with zipfile.ZipFile(zip_path) as z:
            for info in z.infolist():
                target = (dest / info.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    log.warning("Zip Slip 拦截: %s", info.filename)
                    return False
            z.extractall(dest)
        return True
    except (zipfile.BadZipFile, OSError) as e:
        log.warning("解压失败: %s", e)
        return False


def decompile(filepath: str, workspace: str, log_fn=None) -> dict:
    """执行反编译。返回 {kind, lang, ok, degraded, info}
    产物写入 workspace/decompiled/。全部失败时 degraded=True（调用方走字符串特征降级）。
    """
    log_fn = log_fn or (lambda m: None)
    kind = detect_kind(filepath)
    out = Path(workspace) / "decompiled"
    out.mkdir(parents=True, exist_ok=True)
    result = {"kind": kind, "lang": KIND_LANG.get(kind, "unknown"),
              "ok": False, "degraded": False, "info": ""}

    if kind is None:
        result["degraded"] = True
        result["info"] = "非反编译文件类型"
        return result

    # 1) 缓存命中：合并进输出目录（绝不 rmtree 共享目录——修复 v1 的"后者冲掉前者"bug）
    cached = _cache_get(filepath, kind, log_fn)
    if cached:
        try:
            _merge_src(cached / "src", out)
            result["ok"] = True
            result["info"] = "缓存命中"
            return result
        except OSError:
            pass

    # 2) 缓存未命中：反编译到本二进制私有的临时目录，
    #    成功后只把「自己的产物」写缓存并合并进输出目录，最后清理临时目录
    import tempfile
    tmp_out = Path(tempfile.mkdtemp(prefix=f".dc_{kind}_", dir=str(out.parent)))
    try:
        ok = False
        info = ""
        if kind == "java":
            # .class 先收集到临时目录再喂 cfr
            ok, info = _decompile_java(filepath, tmp_out, log_fn)
        elif kind == "android":
            ok, info = _decompile_android(filepath, tmp_out, log_fn)
        elif kind == "dotnet":
            ok, info = _decompile_dotnet(filepath, tmp_out, log_fn)
        elif kind == "python":
            ok, info = _decompile_python(filepath, tmp_out, log_fn)
        elif kind == "native":
            ok, info = False, "原生二进制不支持源码级反编译（ghidra 未启用）"

        result["ok"], result["info"] = ok, info
        if not ok:
            result["degraded"] = True
            return result

        _cache_put(filepath, kind, tmp_out / "src")
        _merge_src(tmp_out / "src", out)
        return result
    finally:
        shutil.rmtree(tmp_out, ignore_errors=True)


def _decompile_java(src: str, out: Path, log_fn) -> tuple[bool, str]:
    """cfr 反编译 jar/war/class"""
    if not _java_jar_ok("cfr.jar"):
        return False, "cfr 未安装（scripts/install_decompilers.sh）"
    tmp = out / "_raw"
    tmp.mkdir(parents=True, exist_ok=True)
    # war 可能内嵌 jar/classes：先解包
    if src.lower().endswith((".war", ".jar")):
        inner = tmp / "unpacked"
        if _unzip_safe(src, str(inner)):
            # 递归提取内层 jar/class
            for j in list(inner.rglob("*.jar")) + list(inner.rglob("*.war")):
                _unzip_safe(str(j), str(inner / (j.stem + "_x")))
            src_dir = inner
        else:
            src_dir = Path(src)
    else:
        src_dir = Path(src)

    classes = list(src_dir.rglob("*.class")) if src_dir.is_dir() else [Path(src)]
    jar_files = [Path(src)] if Path(src).suffix.lower() in (".jar", ".war") else []
    targets = jar_files or classes
    if not targets:
        return False, "未找到 class 文件"
    n = 0
    for t in targets[:200]:  # 上限防爆炸
        rc, _ = _run(["java", "-jar", str(TOOLS_DIR / "cfr.jar"), str(t),
                      "--outputdir", str(out / "src")], timeout=300)
        if rc == 0:
            n += 1
    log_fn(f"cfr 反编译完成 {n}/{len(targets)} 个目标")
    return (n > 0), f"cfr 反编译 {n} 个目标"


def _decompile_android(path: str, out: Path, log_fn) -> tuple[bool, str]:
    """jadx 反编译 apk/dex（dex 先复制为 .dex 便于 jadx 识别）"""
    jadx_bin = TOOLS_DIR / "jadx" / "bin" / "jadx"
    if not jadx_bin.exists() and not _which("jadx"):
        return False, "jadx 未安装（scripts/install_decompilers.sh）"
    bin_cmd = [str(jadx_bin)] if jadx_bin.exists() else ["jadx"]
    src = path
    if path.lower().endswith(".dex"):
        src = str(out / "input.dex")
        shutil.copy(path, src)
    rc, msg = _run(bin_cmd + ["-d", str(out / "src"), "--no-res", "-q", src], timeout=600)
    n = len(list((out / "src").rglob("*.java"))) if (out / "src").exists() else 0
    log_fn(f"jadx 反编译产物 {n} 个 java 文件")
    return (rc == 0 and n > 0), f"jadx 反编译 {n} 个文件"


def _decompile_dotnet(path: str, out: Path, log_fn) -> tuple[bool, str]:
    """ilspycmd 反编译 .NET 程序集。
    注意：ilspycmd 7.x 要求 -o 输出目录预先存在（不会自动创建），必须先 mkdir。
    """
    if not _which("ilspycmd"):
        return False, "ilspycmd 未安装（需 dotnet-sdk：dotnet tool install ilspycmd -g）"
    src_dir = out / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    # 1) 项目模式（每个类型单独 .cs）
    rc, _ = _run(["ilspycmd", "-p", "-o", str(src_dir), path], timeout=600)
    n = len(list(src_dir.rglob("*.cs"))) if src_dir.exists() else 0
    if rc == 0 and n > 0:
        log_fn(f"ilspycmd 反编译产物 {n} 个 cs 文件")
        return True, f"ilspycmd 反编译 {n} 个文件"
    # 2) 兜底：stdout 模式（整汇编源码写单个 .cs，不截断）
    try:
        proc = subprocess.run(["ilspycmd", path], capture_output=True,
                              text=True, timeout=600, errors="ignore")
        out_text = proc.stdout
    except subprocess.TimeoutExpired:
        out_text = ""
    if out_text and not out_text.lstrip().startswith(("Usage:", "The directory")):
        (src_dir / (Path(path).stem + ".cs")).write_text(out_text, encoding="utf-8", errors="ignore")
        n2 = len(list(src_dir.rglob("*.cs")))
        log_fn(f"ilspycmd stdout 模式反编译产物 {n2} 个 cs 文件")
        return (n2 > 0), f"ilspycmd stdout 反编译 {n2} 个文件"
    log_fn("ilspycmd 反编译失败")
    return False, "ilspycmd 反编译失败"


def _decompile_python(path: str, out: Path, log_fn) -> tuple[bool, str]:
    """pycdc / decompyle3 反编译 pyc"""
    if _which("pycdc"):
        rc, output = _run(["pycdc", path], timeout=300)
        if rc == 0 and output.strip():
            (out / "src").mkdir(parents=True, exist_ok=True)
            (out / "src" / (Path(path).stem + ".py")).write_text(output, encoding="utf-8", errors="ignore")
            return True, "pycdc 反编译完成"
    if _which("decompyle3"):
        rc, _ = _run(["decompyle3", "-o", str(out / "src"), path], timeout=300)
        if rc == 0:
            return True, "decompyle3 反编译完成"
    return False, "pycdc/decompyle3 未安装（scripts/install_decompilers.sh）"


# 危险 API 字符串特征（降级扫描用）：class 名/方法名特征
DEGRADE_PATTERNS = [
    ("RCE: Runtime.exec 特征", r"L?java/lang/Runtime.*exec"),
    ("RCE: ProcessBuilder 特征", r"java/lang/ProcessBuilder"),
    ("反序列化: ObjectInputStream", r"java/io/ObjectInputStream"),
    ("反序列化: pickle/marshal", r"(__builtin__)?(pickle|marshal)\s*(loads|load)"),
    ("SQL 拼接: executeQuery 字面量", r"(?i)select\s.+\sfrom\s.+\swhere\s.?\+"),
    ("弱加密: DES/MD5 特征", r"(DES/|MD5|getInstance\(\"?DES)"),
    ("SSRF/HTTP: URLConnection", r"java/net/URLConnection"),
    ("JNDI 注入: InitialContext.lookup", r"javax/naming/InitialContext.*lookup"),
    ("动态加载: DexClassLoader", r"dalvik/system/(Dex|Path)ClassLoader"),
    ("反射执行: Class.forName+invoke", r"java/lang/reflect/Method.*invoke"),
    # 原生/通用（exe/so/dll/elf 降级扫描）
    ("命令执行符号: system/popen/exec 家族", r"(?i)\b(system|popen|execve|execv|execl|execlp|posix_spawn|CreateProcess|WinExec|ShellExecute|Process\.Start)\b\s*\("),
    ("SQL 语句字面量: SELECT/INSERT/UPDATE/DELETE", r"(?i)\b(select|insert|update|delete)\s+.{0,60}\b(from|into|set|where)\b"),
    ("硬编码 URL: http(s)/ftp", r"(?i)\bhttps?://[^\s\"']{8,}|\bftp://[^\s\"']{8,}"),
    ("硬编码内网/本机地址: 127.0.0.1/10./172.16/192.168", r"\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
    ("私钥/证书特征: BEGIN PRIVATE KEY", r"BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|-----BEGIN"),
    ("API 密钥特征: sk-/AKIA/AIza/ghp", r"(?i)\b(sk-[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,})\b"),
    ("原生网络调用: send/connect/socket", r"(?i)\b(send\(|connect\(|WSASend|curl_easy|WinHttp|URLDownloadToFile)"),
]


def degrade_string_scan(filepath: str) -> list[dict]:
    """降级：提取字节码内字符串常量做危险 API 特征匹配（zip 容器先解包再读）"""
    import io
    import re
    data = Path(filepath).read_bytes()
    chunks = []
    if zipfile.is_zipfile(filepath):
        with zipfile.ZipFile(filepath) as z:
            for info in z.infolist():
                if info.filename.endswith((".class", ".dex")):
                    chunks.append(z.read(info.filename))
        if not chunks:
            chunks = [data]
    else:
        chunks = [data]
    text = b"\n".join(
        s for c in chunks for s in re.findall(rb"[\x20-\x7e]{4,}", c)
    ).decode("utf-8", errors="ignore")
    vulns = []
    seen = set()
    for name, pat in DEGRADE_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m and name not in seen:
            seen.add(name)
            vulns.append({
                "rule_id": f"degrade-string::{name.split(':')[0].strip()}",
                "severity": "WARNING",
                "file_path": Path(filepath).name,
                "line": 0,
                "code_snippet": f"[降级扫描-字符串特征] {m.group(0)[:200]}",
                "message": f"反编译失败，基于字节码字符串特征判定：{name}",
            })
    return vulns
