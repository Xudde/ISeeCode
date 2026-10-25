"""Docker 沙箱 skill：自动部署被审计项目到受限容器
资源限制：512MB 内存 / 1 CPU / 128 pids / 5 分钟超时（TASK_TIMEOUT）
"""
import re
import socket
import time
from pathlib import Path

import docker
import requests

from app.config import TASK_TIMEOUT

# 各技术栈的部署配置：镜像、探测端口、启动命令
LAUNCHER = """_sandbox_launch.py\"\"\""""
SANDBOX_CONFIGS = {
    "python": {
        "image": "audit-python-base",  # 预热镜像：内置 flask/fastapi/uvicorn/gunicorn
        "base_image": "python:3.11-slim",
        "ports": [5000],
        # 沙箱为 internal 网络（禁出网），故不再运行时 pip install；
        # 需额外依赖时请扩展 PYTHON_BASE_DOCKERFILE 重建预热镜像
        "cmd": "python /app/_sandbox_launch.py & sleep 3600",
    },
    "javascript": {
        "image": "node:20-slim",
        "ports": [3000, 8080],
        "cmd": (
            "npm install --silent 2>/dev/null; "
            "if [ -f package.json ]; then node $(node -e \"console.log(require('./package.json').main||'index.js')\") & fi; sleep 3600"
        ),
    },
    "php": {
        "image": "php:8-cli",
        "ports": [80],
        "cmd": (
            "R=''; [ -f index.php ] && R=index.php || R=$(ls -1 *.php 2>/dev/null | head -1); "
            "[ -n \"$R\" ] && php -S 0.0.0.0:80 \"$R\" || php -S 0.0.0.0:80; sleep 3600"
        ),
    },
    "java": {
        "image": "maven:3.9-eclipse-temurin-17",
        "ports": [8080],
        "cmd": (
            "if [ -f pom.xml ]; then mvn -q spring-boot:run & fi; sleep 3600"
        ),
    },
    "go": {
        "image": "golang:1.22",
        "ports": [8080],
        "cmd": "if [ -f main.go ]; then go run main.go & fi; sleep 3600",
    },
}

READY_TIMEOUT = 120  # 等待服务就绪秒数

PYTHON_BASE_DOCKERFILE = """FROM python:3.11-slim
RUN pip install --no-cache-dir flask fastapi uvicorn gunicorn
"""


def _ensure_python_base(client, task_log) -> bool:
    """懒构建 python 预热镜像（仅首次需要网络），失败回退官方镜像"""
    try:
        client.images.get("audit-python-base")
        return True
    except docker.errors.ImageNotFound:
        pass
    try:
        task_log("首次构建 python 预热镜像 audit-python-base…")
        import subprocess
        proc = subprocess.run(
            ["docker", "build", "-t", "audit-python-base", "-"],
            input=PYTHON_BASE_DOCKERFILE.encode(),
            capture_output=True, timeout=TASK_TIMEOUT,
        )
        if proc.returncode == 0:
            return True
        task_log(f"预热镜像构建失败: {proc.stderr.decode()[:200]}")
        return False
    except Exception as e:
        task_log(f"预热镜像构建失败，回退官方镜像: {e}")
        return False

LAUNCHER_CODE = '''"""沙箱自动启动器：自动发现 Flask/FastAPI 应用并绑定 0.0.0.0"""
import importlib.util
import sys
from pathlib import Path

PORT = 5000
SKIP = ("venv", "site-packages", "__pycache__", ".git", "_sandbox_launch")


def find_and_run():
    try:
        all_py = sorted(Path(".").rglob("*.py"))
    except (NotADirectoryError, PermissionError, OSError):
        all_py = []
        for p in Path(".").glob("**/*.py"):
            try:
                all_py.append(p)
            except OSError:
                pass
    for p in all_py:
        s = str(p)
        if any(x in s for x in SKIP):
            continue
        try:
            src = p.read_text(errors="ignore")
        except OSError:
            continue
        if "Flask(" not in src and "FastAPI()" not in src:
            continue
        name = p.stem.replace("-", "_").replace(".", "_") or "mod"
        spec = importlib.util.spec_from_file_location(name, p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[launcher] import {p} 失败: {e}", flush=True)
            continue
        obj = getattr(mod, "app", None)
        if obj is None:
            continue
        cls = type(obj).__name__
        print(f"[launcher] 启动 {cls} 来自 {p}", flush=True)
        if "Flask" in cls:
            obj.run(host="0.0.0.0", port=PORT)
            return
        if "FastAPI" in cls or "Starlette" in cls:
            import uvicorn
            uvicorn.run(obj, host="0.0.0.0", port=PORT)
            return
    print("[launcher] 未找到可启动的 Web 应用", flush=True)


if __name__ == "__main__":
    find_and_run()
'''


class SandboxHandle:
    """容器句柄：保存 client/container/端口映射，供 POC 使用与最终清理"""

    def __init__(self, client, container, host_port, internal_port):
        self.client = client
        self.container = container
        self.host_port = host_port
        self.internal_port = internal_port

    @property
    def base_url(self) -> str:
        # internal 网络下宿主无法访问发布端口，POC 一律走 exec 内部请求
        return ""

    def request(self, route: str, params: dict | None = None, timeout: int = 15,
                method: str = "GET") -> tuple[int, str]:
        """在容器内发 HTTP 请求（绕过宿主端口限制），支持 GET/POST。
        客户端自动探测：优先 python3（python 栈），缺失则回退 curl / php（php:8-cli 等镜像无 python3）。"""
        import urllib.parse
        method = (method or "GET").upper()
        is_post = method == "POST"
        body = urllib.parse.urlencode(params) if (params and is_post) else ""
        qs = ("?" + urllib.parse.urlencode(params)) if (params and not is_post) else ""
        url = f"http://127.0.0.1:{self.internal_port}{route}{qs}"
        kind = getattr(self, "_client", None)
        if kind is None:
            probe = self.container.exec_run(["python3", "-c", "print(1)"])
            if probe.exit_code == 0:
                kind = "py"
            else:
                probe2 = self.container.exec_run(["sh", "-c", "curl --version"])
                kind = "curl" if probe2.exit_code == 0 else "php"
            self._client = kind
        try:
            if kind == "py":
                # URL/数据经 argv 传入，避免拼进脚本文本（引号/特殊字符会破坏脚本甚至注入）
                if is_post:
                    script = (
                        "import sys,urllib.request,urllib.error\n"
                        "url,body,timeout=sys.argv[1],sys.argv[2],float(sys.argv[3])\n"
                        "req=urllib.request.Request(url,method='POST')\n"
                        "req.add_header('Content-Type','application/x-www-form-urlencoded')\n"
                        "try:\n"
                        "    r=urllib.request.urlopen(req,data=body.encode(),timeout=timeout)\n"
                        "    print(r.status);print(r.read().decode(errors='replace')[:20000])\n"
                        "except urllib.error.HTTPError as e:\n"
                        "    print(e.code);print(e.read().decode(errors='replace')[:20000])\n"
                        "except Exception as e:\n"
                        "    print(0);print('EXEC_ERR:'+type(e).__name__)\n"
                    )
                    out = self.container.exec_run(["python3", "-c", script, url, body, str(timeout)])
                else:
                    script = (
                        "import sys,urllib.request,urllib.error\n"
                        "url,timeout=sys.argv[1],float(sys.argv[2])\n"
                        "try:\n"
                        "    r=urllib.request.urlopen(urllib.request.Request(url),timeout=timeout)\n"
                        "    print(r.status);print(r.read().decode(errors='replace')[:20000])\n"
                        "except urllib.error.HTTPError as e:\n"
                        "    print(e.code);print(e.read().decode(errors='replace')[:20000])\n"
                        "except Exception as e:\n"
                        "    print(0);print('EXEC_ERR:'+type(e).__name__)\n"
                    )
                    out = self.container.exec_run(["python3", "-c", script, url, str(timeout)])
                text = out.output.decode(errors="replace")
                lines = text.split("\n", 1)
                try:
                    status = int(lines[0].strip())
                except (ValueError, IndexError):
                    return 0, text[:500]
                return status, lines[1] if len(lines) > 1 else ""
            if kind == "curl":
                # body 经 argv 传入 sh 脚本，避免引号拼接破坏命令
                script = ('METHOD=$1; URL=$2; BODY=$3\n'
                          'if [ -n "$BODY" ]; then\n'
                          f'  curl -s -m {timeout} -X "$METHOD" -d "$BODY" -w \'\\n%{{http_code}}\' "$URL"\n'
                          'else\n'
                          f'  curl -s -m {timeout} -X "$METHOD" -w \'\\n%{{http_code}}\' "$URL"\n'
                          'fi')
                out = self.container.exec_run(["sh", "-c", script, "sh", method, url, body])
                text = out.output.decode(errors="replace").rstrip()
                idx = text.rfind("\n")
                if idx < 0:
                    return 0, text[:500]
                try:
                    return int(text[idx + 1:].strip()), text[:idx]
                except ValueError:
                    return 0, text[:500]
            # php 兜底（php:8-cli 无 python3/curl 时）
            if is_post:
                script = ("$u=$argv[1];$d=$argv[2];"
                          "$o=['http'=>['method'=>'POST','header'=>\"Content-Type: application/x-www-form-urlencoded\\r\\n\","
                          "'content'=>$d]];$c=@file_get_contents($u,false,stream_context_create($o));"
                          "$h=$http_response_header[0]??'0';echo $h,\"\\n\",$c;")
            else:
                script = ("$u=$argv[1];$c=@file_get_contents($u);$h=$http_response_header[0]??'0';"
                          "echo $h,\"\\n\",$c;")
            out = self.container.exec_run(["php", "-r", script, url, body])
            text = out.output.decode(errors="replace")
            lines = text.split("\n", 1)
            m = re.search(r"(\d{3})", lines[0] if lines else "")
            status = int(m.group(1)) if m else 0
            return status, lines[1] if len(lines) > 1 else ""
        except Exception as e:
            return 0, f"EXEC_ERR:{type(e).__name__}"

    def cleanup(self) -> None:
        try:
            self.container.remove(force=True)
        except Exception:
            pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SANDBOX_NETWORK = "audit-sandbox-net"  # internal 网络：容器无外网出口，宿主仍可访问映射端口


def _ensure_sandbox_network(client) -> object | None:
    """确保 internal 沙箱网络存在（容器禁止出网，防反制/数据外传）"""
    try:
        return client.networks.get(SANDBOX_NETWORK)
    except Exception:
        try:
            return client.networks.create(SANDBOX_NETWORK, driver="bridge", internal=True)
        except Exception as e:
            print(f"[sandbox] 创建 internal 网络失败: {e}")
            return None


def deploy_sandbox(workspace: str, tech: str, task_log) -> SandboxHandle | None:
    """构建并启动沙箱容器，返回句柄；部署失败返回 None（不阻断任务）"""
    cfg = SANDBOX_CONFIGS.get(tech)
    if cfg is None:
        return None
    if not Path(workspace).exists():
        return None

    try:
        client = docker.from_env(timeout=120)
        image_name = cfg["image"]
        if tech == "python":
            if not _ensure_python_base(client, task_log):
                image_name = cfg["base_image"]
        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            task_log(f"拉取镜像 {image_name} …（首次较慢）")
            client.images.pull(image_name)

        # 注入启动器（python 栈），结束后清理
        ws_path = Path(workspace)
        launcher = ws_path / "_sandbox_launch.py"
        wrote_launcher = False
        if tech == "python" and not launcher.exists():
            launcher.write_text(LAUNCHER_CODE)
            wrote_launcher = True

        port_bindings = {p: _free_port() for p in cfg["ports"]}
        net = _ensure_sandbox_network(client)
        run_kwargs = {
            "image": image_name,
            "command": ["sh", "-c", cfg["cmd"]],
            "working_dir": "/app",
            "volumes": {str(Path(workspace).resolve()): {"bind": "/app", "mode": "ro"}},
            "ports": port_bindings,
            "mem_limit": "512m",
            "nano_cpus": 1_000_000_000,  # 1 CPU
            "pids_limit": 128,
            "detach": True,
        }
        if net is not None:
            run_kwargs["network"] = SANDBOX_NETWORK
        container = client.containers.run(**run_kwargs)
        # 预期的监听端口列表（可能应用只监听其一）
        expected = set(cfg["ports"])
        handle = SandboxHandle(client, container, port_bindings, None)
        if _wait_ready_sandbox(handle, set(cfg["ports"])):
            if wrote_launcher:
                launcher.unlink(missing_ok=True)
            return handle
        # 超时未就绪：取第一个映射端口兜底（由 POC 环节自行失败）
        if isinstance(handle.host_port, dict):
            handle.host_port = next(iter(handle.host_port.values()))
            handle.internal_port = cfg["ports"][0]
        return handle
    except Exception as e:
        task_log(f"沙箱部署异常: {e}")
        return None


def _wait_ready_sandbox(handle: "SandboxHandle", expected: set[int]) -> bool:
    """轮询探测服务是否就绪（通过容器内请求，internal 网络宿主不可达）"""
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        for internal in expected:
            probe = SandboxHandle.__new__(SandboxHandle)
            probe.container = handle.container
            probe.internal_port = internal
            try:
                status, _ = probe.request("/", timeout=3)
                if 0 < status < 500:
                    handle.internal_port = internal
                    return True
            except Exception:
                pass
        time.sleep(2)
    return False
