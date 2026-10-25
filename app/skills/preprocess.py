"""预处理 skill：解压 zip 源码包，含大小校验 / Zip Slip 防护 / 恶意样本初筛"""
import os
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


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> int:
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
        if total > MAX_EXTRACT_SIZE:
            raise ValueError("解压后总大小超过 1GB 上限")
    if total > MAX_EXTRACT_SIZE:
        raise ValueError("解压后总大小超过 1GB 上限")
    zf.extractall(dest)
    return total


def run_preprocess(task, upload_path: str) -> dict:
    """解压上传包到 workspace，返回 {'workspace': str, 'total_size': int}"""
    ws = WORKSPACE_DIR / f"task_{task.id}"
    if ws.exists():
        for p in sorted(ws.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        ws.rmdir()
    ws.mkdir(parents=True)

    src = Path(upload_path)
    with zipfile.ZipFile(src) as zf:
        total = _safe_extract(zf, ws)

    return {"workspace": str(ws), "total_size": total}


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
