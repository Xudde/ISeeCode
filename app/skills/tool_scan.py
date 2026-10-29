# -*- coding: utf-8 -*-
"""阶段 6 轻量目录扫描：把已安装的 ffuf 二进制送进沙箱，跑内置小路径字典。
不生成注入/XSS/命令执行 payload，只做可访问路径发现。"""
import io
import json
import tarfile


def _put(container, remote_name: str, data: bytes) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(remote_name)
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    container.put_archive("/tmp", buf.getvalue())


PATHS = [
    "", "admin", "api", "api/", "login", "logout", "config", "settings",
    "upload", "uploads", "download", "backup", "backups", "debug", "status",
    "health", "ping", "version", "user", "users", "account", "accounts",
    "static", "assets", "files", "file", "docs", "swagger", "openapi.json",
    ".git/HEAD", "robots.txt", "sitemap.xml",
]


def run_tool(task, tool: str = "ffuf", timeout: int = 90) -> dict:
    from app.skills.chain_engine import _sandbox_handle
    tool = (tool or "ffuf").strip().lower()
    if tool != "ffuf":
        raise ValueError("当前只支持 ffuf 轻量路径扫描")
    handle = _sandbox_handle(task)
    port = int(getattr(handle, "internal_port", 0) or 0)
    try:
        binary = open("/usr/bin/ffuf", "rb").read()
    except OSError as e:
        raise RuntimeError(f"宿主 ffuf 不可用: {e}")
    _put(handle.container, "ffuf", binary)
    _put(handle.container, "ffuf_paths.txt", ("\n".join(PATHS) + "\n").encode())
    cmd = ["/tmp/ffuf", "-u", f"http://127.0.0.1:{port}/FUZZ",
           "-w", "/tmp/ffuf_paths.txt", "-mc", "200,204,301,302,401,403",
           "-t", "5", "-timeout", "3", "-maxtime", str(max(10, int(timeout))),
           "-s", "-of", "json", "-o", "/tmp/ffuf_result.json"]
    out = handle.container.exec_run(cmd)
    text = (out.output or b"").decode(errors="replace")
    result = {}
    try:
        raw = handle.container.exec_run(["cat", "/tmp/ffuf_result.json"]).output or b""
        result = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        result = {}
    hits = []
    for r in (result.get("results") or []):
        hits.append({"url": r.get("url"), "status": r.get("status"),
                     "length": r.get("length")})
    return {"tool": "ffuf", "exit_code": out.exit_code,
            "hits": hits[:100], "output": text[:2000]}
