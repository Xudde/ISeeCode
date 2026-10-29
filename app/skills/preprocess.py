"""预处理 skill：解压 zip 源码包（支持有限层嵌套 zip），含大小校验 / Zip Slip 防护 / 恶意样本初筛"""
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from app.config import MAX_EXTRACT_SIZE, WORKSPACE_DIR

# 恶意样本初筛：常见 Webshell / 威胁特征关键字（出现在文件名或小文件内容中）
SUSPICIOUS_KEYWORDS = [
    b"eval($_POST[", b"eval($_GET[", b"eval($_REQUEST[",
    b"assert($_POST[", b"base64_decode($_POST[",
    b"shell_exec($_", b"system($_",
    b"__import__('os').system", b"os.system(request.",
]
MAX_SCAN_FILE_SIZE = 512 * 1024  # 初筛只读前 512KB

# 嵌套压缩包保护：最多 3 层、20 个、累计解压仍受 MAX_EXTRACT_SIZE（默认 10GB）约束
MAX_NESTED_DEPTH = 3
MAX_NESTED_ARCHIVES = 100
NESTED_SKIP_DIRS = {"node_modules", ".git", ".svn", "vendor", "third_party",
                    "thirdparty", "dist", "build", "target", "__pycache__"}


def _safe_extract(zf: zipfile.ZipFile, dest: Path, limit: int = MAX_EXTRACT_SIZE) -> int:
    """安全解压，返回解压总字节数。校验 Zip Slip 与累计解压大小。"""
    total = 0
    for info in zf.infolist():
        # Zip Slip：目标路径必须仍在 dest 内
        target = (dest / info.filename).resolve()
        if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
            raise ValueError(f"检测到路径穿越攻击（Zip Slip）：{info.filename}")
        if info.is_dir():
            continue
        total += info.file_size
        if total > limit:
            raise ValueError("解压后总大小超过剩余上限")
    if total > limit:
        raise ValueError("解压后总大小超过剩余上限")
    zf.extractall(dest)
    return total


def _nested_archive_paths(root: Path):
    """列出工作区内待展开的 zip/7z/rar，跳过依赖/构建目录，忽略大小写后缀"""
    for p in root.rglob("*"):
        try:
            if not p.is_file() or p.suffix.lower() not in (".zip", ".7z", ".rar"):
                continue
        except OSError:
            continue
        low_parts = [part.lower() for part in p.relative_to(root).parts]
        if any(part in NESTED_SKIP_DIRS for part in low_parts):
            continue
        yield p


def _safe_extract_7z(path: Path, dest: Path, limit: int) -> int:
    """7z 列表预算校验后解压；拒绝绝对路径/.. 路径。"""
    bin7 = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if not bin7:
        raise ValueError("7z 未安装")
    proc = subprocess.run([bin7, "l", "-slt", str(path)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode not in (0, 1):
        raise ValueError("7z 列表失败: %s" % (proc.stderr or proc.stdout)[-200:])
    total = 0
    for block in re.split(r"\n\s*\n", proc.stdout):
        name = None
        size = 0
        folder = False
        sized = False
        for line in block.splitlines():
            if line.startswith("Path = "):
                name = line[7:]
            elif line.startswith("Size = "):
                sized = True
                try:
                    size = int(line[7:].strip() or 0)
                except ValueError:
                    size = 0
            elif line.startswith("Folder = "):
                folder = line[9:].strip() == "+"
        if not name or folder or not sized:
            continue
        norm = name.replace("\\", "/")
        if norm.startswith("/") or any(part == ".." for part in norm.split("/")):
            raise ValueError("检测到路径穿越: %s" % name)
        total += size
        if total > limit:
            raise ValueError("解压后总大小超过剩余上限")
    if total > limit:
        raise ValueError("解压后总大小超过剩余上限")
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([bin7, "x", "-y", "-o" + str(dest), str(path)],
                          capture_output=True, text=True, timeout=600)
    if proc.returncode not in (0, 1):
        raise ValueError("7z 解压失败: %s" % (proc.stderr or proc.stdout)[-200:])
    return total


def _safe_extract_rar(path: Path, dest: Path, limit: int) -> int:
    """unrar 列表预算校验后解压；拒绝绝对路径/.. 路径。"""
    binr = shutil.which("unrar")
    if not binr:
        raise ValueError("unrar 未安装")
    proc = subprocess.run([binr, "lt", str(path)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise ValueError("unrar 列表失败: %s" % (proc.stderr or proc.stdout)[-200:])
    total = 0
    name = None
    for line in proc.stdout.splitlines():
        if line.strip().startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.strip().startswith("Size:") and name:
            try:
                total += int(line.split(":", 1)[1].strip() or 0)
            except ValueError:
                pass
        elif not line.strip():
            name = None
        if name:
            norm = name.replace("\\", "/")
            if norm.startswith("/") or any(part == ".." for part in norm.split("/")):
                raise ValueError("检测到路径穿越: %s" % name)
        if total > limit:
            raise ValueError("解压后总大小超过剩余上限")
    if total > limit:
        raise ValueError("解压后总大小超过剩余上限")
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([binr, "x", "-o+", "-y", str(path), str(dest) + os.sep],
                          capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise ValueError("unrar 解压失败: %s" % (proc.stderr or proc.stdout)[-200:])
    return total


def _extract_nested(workspace: Path, budget: int, log_fn=None):
    """BFS 展开嵌套 zip，返回 (新增字节数, 已展开数量, 跳过列表)。失败只跳过，不阻断任务。"""
    log_fn = log_fn or (lambda m: None)
    queue = [(workspace, 0)]
    processed = set()
    total_new = 0
    count = 0
    skipped = []
    while queue:
        root, depth = queue.pop(0)
        if depth >= MAX_NESTED_DEPTH:
            continue
        for zpath in sorted(_nested_archive_paths(root)):
            if zpath in processed:
                continue
            processed.add(zpath)
            if count >= MAX_NESTED_ARCHIVES:
                skipped.append((str(zpath.relative_to(workspace)), "超过嵌套压缩包数量上限"))
                continue
            dest = zpath.parent / (zpath.stem + "_unzipped")
            if dest.exists():
                n = 1
                while (zpath.parent / (zpath.stem + "_unzipped_%d" % n)).exists():
                    n += 1
                dest = zpath.parent / (zpath.stem + "_unzipped_%d" % n)
            try:
                suffix = zpath.suffix.lower()
                if suffix == ".zip":
                    with zipfile.ZipFile(str(zpath)) as zf:
                        used = _safe_extract(zf, dest, budget)
                elif suffix == ".7z":
                    used = _safe_extract_7z(zpath, dest, budget)
                else:
                    used = _safe_extract_rar(zpath, dest, budget)
                budget -= used
                total_new += used
                count += 1
                log_fn("展开嵌套压缩包：%s（%d 字节）" % (zpath.relative_to(workspace), used))
                queue.append((dest, depth + 1))
            except Exception as e:
                skipped.append((str(zpath.relative_to(workspace)), str(e)))
                log_fn("跳过嵌套压缩包 %s：%s" % (zpath.relative_to(workspace), e))
    return total_new, count, skipped


def run_preprocess(task, upload_path: str, log_fn=None) -> dict:
    """解压上传包到 workspace，返回 {'workspace': str, 'total_size': int, ...}"""
    ws = WORKSPACE_DIR / f"task_{task.id}"
    if ws.exists():
        for p in sorted(ws.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        ws.rmdir()
    ws.mkdir(parents=True)

    src = Path(upload_path)
    with zipfile.ZipFile(src) as zf:
        total = _safe_extract(zf, ws, MAX_EXTRACT_SIZE)

    nested_bytes, nested_count, nested_skipped = _extract_nested(
        ws, max(0, MAX_EXTRACT_SIZE - total), log_fn)
    return {"workspace": str(ws), "total_size": total + nested_bytes,
            "nested_count": nested_count, "nested_skipped": nested_skipped}


def pre_screen(workspace: str) -> list[str]:
    """恶意样本初筛，返回可疑文件路径列表"""
    suspicious = []
    root = Path(workspace)
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        # 文件名特征
        name = f.name.lower()
        if name in ("webshell.php", "shell.php", "cmd.jsp", "backdoor.py") or \
           ("shell" in name and f.suffix in (".php", ".jsp", ".py")):
            suspicious.append(str(f.relative_to(root)))
            continue
        # 内容特征（只查小文本文件，前 512KB）
        try:
            if f.stat().st_size <= MAX_SCAN_FILE_SIZE:
                data = f.read_bytes()
                low = data.lower()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw.lower() in low:
                        suspicious.append(str(f.relative_to(root)))
                        break
        except OSError:
            continue
    return suspicious
