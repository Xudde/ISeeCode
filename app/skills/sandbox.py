"""Docker 沙箱 skill：自动部署被审计项目到受限容器
资源限制：512MB 内存 / 1 CPU / 128 pids / 5 分钟超时（TASK_TIMEOUT）
"""
import hashlib
import os
import re
import socket
import threading
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
        # 允许依赖拉取时先装 requirements，再由启动器拉起应用
        "cmd": (
            "if [ -f requirements.txt ]; then pip install -q --target /tmp/pydeps -r requirements.txt "
            ">/tmp/deps.log 2>&1; echo $? >/tmp/deps.exit; fi; "
            "PYTHONPATH=/tmp/pydeps python /app/_sandbox_launch.py & sleep 86400"
        ),
    },
    "javascript": {
        "image": "node:20-slim",
        "ports": [3000, 8080],
        "cmd": (
            "if [ \"$WORKSPACE_RW\" = \"1\" ]; then npm install --silent --cache /tmp/npm-cache "
            ">/tmp/deps.log 2>&1; echo $? >/tmp/deps.exit; else echo 0 >/tmp/deps.exit; fi; "
            "if [ -f package.json ]; then node $(node -e \"console.log(require('./package.json').main||'index.js')\") & fi; sleep 86400"
        ),
    },
    "php": {
        "image": "php:8-cli",
        "ports": [80],
        "cmd": (
            "R=''; [ -f index.php ] && R=index.php || R=$(ls -1 *.php 2>/dev/null | head -1); "
            "[ -n \"$R\" ] && php -S 0.0.0.0:80 \"$R\" || php -S 0.0.0.0:80; sleep 86400"
        ),
    },
    "java": {
        "image": "maven:3.9-eclipse-temurin-17",
        "ports": [8080],
        "cmd": (
            "if [ -f pom.xml ]; then mvn -q -Dmaven.repo.local=/tmp/.m2 spring-boot:run & fi; sleep 86400"
        ),
    },
    "go": {
        "image": "golang:1.22",
        "ports": [8080],
        "cmd": ("if [ -f main.go ]; then GOCACHE=/tmp/go-cache GOPATH=/tmp/go "
                "go run -mod=mod main.go & fi; sleep 86400"),
    },
}

READY_TIMEOUT = 300  # 等待服务就绪秒数（给 npm/pip/mvn 拉依赖留时间）

# 阶段 7 v2：默认最小权限；PHP 80 端口需要 NET_BIND_SERVICE
SANDBOX_HARDEN = os.environ.get("AUDIT_SANDBOX_HARDEN", "1").strip() != "0"
SANDBOX_BIND_HOST = os.environ.get("AUDIT_SANDBOX_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
SANDBOX_READONLY = os.environ.get("AUDIT_SANDBOX_READONLY", "1").strip() != "0"
EGRESS_PROXY_NAME = "iseecode-egress-proxy"
EGRESS_PROXY_PORT = int(os.environ.get("AUDIT_EGRESS_PROXY_PORT", "3128"))
PROXY_SCRIPT = Path(__file__).with_name("egress_proxy.py")
_PROXY_LOCK = threading.Lock()

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
                if probe2.exit_code == 0:
                    kind = "curl"
                else:
                    probe3 = self.container.exec_run(["node", "-e", "process.exit(0)"])
                    kind = "node" if probe3.exit_code == 0 else "php"
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
            if kind == "node":
                script = (
                    "const http=require('http');"
                    "const [url,method,body]=process.argv.slice(1);"
                    "const req=http.request(url,{method,headers:body?{'content-type':'application/x-www-form-urlencoded','content-length':Buffer.byteLength(body)}:{}},res=>{"
                    "let c=[];res.on('data',d=>c.push(d));res.on('end',()=>{console.log(res.statusCode);console.log(Buffer.concat(c).toString('utf8').slice(0,20000));});});"
                    "req.on('error',e=>{console.log(0);console.log('EXEC_ERR:'+(e.code||e.message));});"
                    "if(body)req.write(body);req.end();"
                )
                out = self.container.exec_run(["node", "-e", script, url, method, body])
                text = out.output.decode(errors="replace")
                lines = text.split("\n", 1)
                try:
                    status = int(lines[0].strip())
                except (ValueError, IndexError):
                    return 0, text[:500]
                return status, lines[1] if len(lines) > 1 else ""
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

    def upload_file(self, route: str, field: str = "file", filename: str = "poc.txt",
                    content: str = "", timeout: int = 15) -> tuple[int, str]:
        """容器内发 multipart 文件上传（python3 构造请求；用于链验证）。"""
        url = f"http://127.0.0.1:{self.internal_port}{route}"
        script = (
            "import sys,uuid,urllib.request,urllib.error\n"
            "url,field,fname,content,timeout=sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],float(sys.argv[5])\n"
            "b='----poc'+uuid.uuid4().hex\n"
            "body=('--%s\\r\\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\\r\\n"
            "Content-Type: text/plain\\r\\n\\r\\n%s\\r\\n--%s--\\r\\n' % (b,field,fname,content,b)).encode()\n"
            "req=urllib.request.Request(url,data=body,method='POST')\n"
            "req.add_header('Content-Type','multipart/form-data; boundary='+b)\n"
            "try:\n"
            "    r=urllib.request.urlopen(req,timeout=timeout); print(r.status); print(r.read().decode(errors='replace')[:20000])\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code); print(e.read().decode(errors='replace')[:20000])\n"
            "except Exception as e:\n"
            "    print(0); print('EXEC_ERR:'+type(e).__name__)\n"
        )
        probe = self.container.exec_run(["python3", "-c", "print(1)"])
        if probe.exit_code != 0:
            return 0, "EXEC_ERR:no python3 in sandbox"
        out = self.container.exec_run(["python3", "-c", script, url, field, filename,
                                       content, str(timeout)])
        text = out.output.decode(errors="replace")
        lines = text.split("\n", 1)
        try:
            status = int(lines[0].strip())
        except (ValueError, IndexError):
            return 0, text[:500]
        return status, lines[1] if len(lines) > 1 else ""

    def cleanup(self) -> None:
        try:
            self.container.remove(force=True)
        except Exception:
            pass


def is_running(cid: str) -> bool:
    """阶段 0.6：保留容器是否仍 RUNNING；不能只看 sandbox_cid 是否存在。"""
    if not cid:
        return False
    try:
        import docker
        return docker.from_env().containers.get(cid).status == "running"
    except Exception:
        return False


def cleanup_cid(cid: str) -> None:
    """删除已退出的保留容器（任务引用清理时调用）。"""
    if not cid:
        return
    try:
        import docker
        docker.from_env().containers.get(cid).remove(force=True)
    except Exception:
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SANDBOX_NETWORK = "audit-sandbox-net"  # internal 网络：容器无外网出口，宿主仍可访问映射端口
SANDBOX_EGRESS_NETWORK = "audit-sandbox-egress"  # 仅依赖拉取阶段使用，启动后断开

MINING_MARKERS = (
    "stratum+tcp", "stratum+ssl", "xmrig", "minerd", "cpuminer",
    "cryptonight", "randomx", "nicehash", "minergate",
    "pool.minexmr", "supportxmr", "moneroocean",
)


def _mining_hits(workspace: str, limit_files: int = 3000) -> list[str]:
    """粗筛挖矿特征；不是完整恶意样本检测，只用于决定是否允许沙箱拉依赖。"""
    root = Path(workspace)
    hits = []
    skipped_dirs = {"node_modules", ".git", ".venv", "venv", "vendor", "dist", "build", "target"}
    scanned = 0
    for p in root.rglob("*"):
        if scanned >= limit_files or len(hits) >= 8:
            break
        try:
            if not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
                continue
            if any(part.lower() in skipped_dirs for part in p.relative_to(root).parts):
                continue
            data = p.read_bytes()[:128 * 1024].lower()
        except OSError:
            continue
        scanned += 1
        for marker in MINING_MARKERS:
            if marker.encode("ascii") in data:
                hits.append(str(p.relative_to(root)))
                break
    return hits


def _egress_allowed(workspace: str, task_log) -> bool:
    """AUDIT_SANDBOX_EGRESS=0 永远禁网；1 强制；auto（默认）先查挖矿特征。"""
    mode = os.environ.get("AUDIT_SANDBOX_EGRESS", "auto").lower()
    if mode in ("0", "off", "false", "no"):
        task_log("沙箱外网：关闭（AUDIT_SANDBOX_EGRESS=0）")
        return False
    hits = _mining_hits(workspace)
    if hits:
        task_log("沙箱外网：检测到挖矿特征，禁止外网；命中示例 %s" % ", ".join(hits[:5]))
        return False
    if mode in ("1", "on", "true", "yes"):
        task_log("沙箱外网：强制开启依赖拉取，启动后断开")
        return True
    task_log("沙箱外网：未发现挖矿特征，允许依赖拉取（启动后断网）")
    return True


def _ensure_sandbox_network(client, egress: bool = False) -> object | None:
    """internal 网络默认禁网；egress=True 时创建普通 bridge，仅依赖拉取阶段使用。"""
    name = SANDBOX_EGRESS_NETWORK if egress else SANDBOX_NETWORK
    try:
        return client.networks.get(name)
    except Exception:
        try:
            return client.networks.create(name, driver="bridge", internal=not egress)
        except Exception as e:
            print(f"[sandbox] 创建网络 {name} 失败: {e}")
            return None


def _extra_allow() -> str:
    """data/egress_allowlist.txt（每行一个域名）+ AUDIT_EGRESS_ALLOW_EXTRA 追加。"""
    items = []
    path = Path(__file__).resolve().parents[2] / "data" / "egress_allowlist.txt"
    try:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    except OSError:
        pass
    items += [x.strip() for x in os.environ.get("AUDIT_EGRESS_ALLOW_EXTRA", "").split(",")
              if x.strip()]
    return ",".join(dict.fromkeys(items))


def _proxy_hash() -> str:
    try:
        return hashlib.sha256(PROXY_SCRIPT.read_bytes()).hexdigest()[:12]
    except OSError:
        return ""


def _ensure_egress_proxy(client, task_log):
    """启动/复用受控 egress 代理（internal + egress 双网卡，不发宿主端口）。"""
    if os.environ.get("AUDIT_SANDBOX_EGRESS_PROXY", "1").strip() == "0":
        return None
    if not PROXY_SCRIPT.is_file():
        task_log(f"受控代理脚本缺失: {PROXY_SCRIPT}")
        return None
    with _PROXY_LOCK:
        try:
            internal = _ensure_sandbox_network(client, egress=False)
            egress = _ensure_sandbox_network(client, egress=True)
            if internal is None or egress is None:
                return None
            version = _proxy_hash()
            allow = os.environ.get("AUDIT_EGRESS_ALLOW", "").strip()
            extra = _extra_allow()
            existing = None
            try:
                existing = client.containers.get(EGRESS_PROXY_NAME)
            except Exception:
                existing = None
            if existing is not None:
                labels = existing.labels or {}
                if (existing.status == "running" and labels.get("iseecode.proxy") == version
                        and (labels.get("iseecode.allow") or "") == allow
                        and (labels.get("iseecode.extra") or "") == extra):
                    try:
                        nets = (existing.attrs.get("NetworkSettings") or {}).get("Networks") or {}
                        if internal.name not in nets:
                            internal.connect(existing)
                        if egress.name not in nets:
                            egress.connect(existing)
                    except Exception:
                        pass
                    return existing
                try:
                    existing.remove(force=True)
                except Exception:
                    pass
            c = client.containers.run(
                "python:3.11-slim",
                ["python", "/proxy.py"],
                name=EGRESS_PROXY_NAME,
                detach=True,
                network=internal.name,
                volumes={str(PROXY_SCRIPT): {"bind": "/proxy.py", "mode": "ro"}},
                read_only=True,
                tmpfs={"/tmp": "rw,exec,nosuid,size=32m"},
                mem_limit="128m",
                pids_limit=64,
                init=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                environment={"PYTHONDONTWRITEBYTECODE": "1",
                             "AUDIT_EGRESS_ALLOW": allow,
                             "AUDIT_EGRESS_ALLOW_EXTRA": extra,
                             "AUDIT_EGRESS_PORT": str(EGRESS_PROXY_PORT)},
                labels={"iseecode.proxy": version, "iseecode.allow": allow,
                        "iseecode.extra": extra},
            )
            egress.connect(c)
            for _ in range(20):
                probe = c.exec_run(["python", "-c",
                                    f"import socket;s=socket.socket();s.settimeout(0.5);"
                                    f"s.connect(('127.0.0.1',{EGRESS_PROXY_PORT}))"])
                if probe.exit_code == 0:
                    task_log("受控 egress 代理已启动（仅包管理器白名单）")
                    return c
                time.sleep(0.25)
            task_log("受控 egress 代理端口未就绪，回退普通 egress 网络")
            try:
                c.remove(force=True)
            except Exception:
                pass
            return None
        except Exception as e:
            task_log(f"受控 egress 代理启动失败: {e}")
            return None


def _report_deps(container, task_log) -> None:
    """依赖安装结果落盘在 /tmp/deps.exit；失败时写入任务日志，避免静默缺依赖。"""
    try:
        r = container.exec_run(["sh", "-c", "cat /tmp/deps.exit 2>/dev/null"])
        code = (r.output or b"").decode(errors="replace").strip()
        if code and code != "0":
            log = container.exec_run(["sh", "-c", "tail -n 6 /tmp/deps.log 2>/dev/null"])
            text = (log.output or b"").decode(errors="replace").strip()
            task_log(f"依赖安装失败（exit {code}），应用可能缺少依赖：{text[-300:]}")
    except Exception:
        pass


def deploy_sandbox(workspace: str, tech: str, task_log, allow_egress=None) -> SandboxHandle | None:
    """构建并启动沙箱容器，返回句柄；部署失败返回 None（不阻断任务）。
    allow_egress=None 时按 AUDIT_SANDBOX_EGRESS + 挖矿初筛自动决定。"""
    cfg = SANDBOX_CONFIGS.get(tech)
    if cfg is None:
        return None
    if not Path(workspace).exists():
        return None
    if allow_egress is None:
        allow_egress = _egress_allowed(workspace, task_log)

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

        port_bindings = {f"{p}/tcp": (SANDBOX_BIND_HOST, _free_port()) for p in cfg["ports"]}
        using_proxy = False
        proxy_env = {}
        if allow_egress:
            proxy = _ensure_egress_proxy(client, task_log)
            if proxy is not None:
                net = _ensure_sandbox_network(client, egress=False)
                using_proxy = True
                proxy_url = f"http://{EGRESS_PROXY_NAME}:{EGRESS_PROXY_PORT}"
                proxy_env = {
                    "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
                    "http_proxy": proxy_url, "https_proxy": proxy_url,
                    "NO_PROXY": f"127.0.0.1,localhost,{EGRESS_PROXY_NAME}",
                    "no_proxy": f"127.0.0.1,localhost,{EGRESS_PROXY_NAME}",
                    "npm_config_proxy": proxy_url,
                    "npm_config_https_proxy": proxy_url,
                    "MAVEN_OPTS": (
                        f"-Dhttp.proxyHost={EGRESS_PROXY_NAME} -Dhttp.proxyPort={EGRESS_PROXY_PORT} "
                        f"-Dhttps.proxyHost={EGRESS_PROXY_NAME} -Dhttps.proxyPort={EGRESS_PROXY_PORT} "
                        "-Dhttp.nonProxyHosts=localhost|127.0.0.1"),
                }
            else:
                net = _ensure_sandbox_network(client, egress=True)
                task_log("受控代理不可用，回退普通 egress 网络（仅本次）")
        else:
            net = _ensure_sandbox_network(client, egress=False)
        env = {"WORKSPACE_RW": "1" if allow_egress else "0",
               "GOPROXY": os.environ.get("AUDIT_GOPROXY", "https://goproxy.cn,direct")}
        env.update(proxy_env)
        run_kwargs = {
            "image": image_name,
            "command": ["sh", "-c", cfg["cmd"]],
            "working_dir": "/app",
            "volumes": {str(Path(workspace).resolve()): {"bind": "/app", "mode": "rw" if allow_egress else "ro"}},
            "ports": port_bindings,
            "mem_limit": "512m",
            "nano_cpus": 1_000_000_000,  # 1 CPU
            "pids_limit": 128,
            "init": True,  # 回收僵尸进程
            "detach": True,
            "environment": env,
        }
        if SANDBOX_HARDEN:
            run_kwargs.update({
                "cap_drop": ["ALL"],
                "cap_add": ["NET_BIND_SERVICE"],  # PHP 内部 80 端口
                "security_opt": ["no-new-privileges:true"],
            })
        if SANDBOX_READONLY:
            run_kwargs.update({
                "read_only": True,
                "tmpfs": {
                    "/tmp": "rw,exec,nosuid,size=256m,mode=1777",
                    "/var/tmp": "rw,exec,nosuid,size=64m,mode=1777",
                    "/run": "rw,nosuid,size=64m,mode=755",
                    "/root": "rw,exec,nosuid,size=256m,mode=700",
                },
            })
        if net is not None:
            run_kwargs["network"] = net.name
        container = client.containers.run(**run_kwargs)
        # 预期的监听端口列表（可能应用只监听其一）
        expected = set(cfg["ports"])
        handle = SandboxHandle(client, container, port_bindings, None)
        if _wait_ready_sandbox(handle, set(cfg["ports"])):
            if allow_egress and net is not None and not using_proxy:
                try:
                    net.disconnect(container)
                    task_log("沙箱依赖拉取完成，已断开外网（后续 POC 在无外网环境执行）")
                except Exception as e:
                    task_log(f"沙箱断开外网失败（保持当前网络）: {e}")
            elif using_proxy:
                task_log("受控代理依赖拉取完成，沙箱保持 internal 网络（后续无外网）")
            if wrote_launcher:
                launcher.unlink(missing_ok=True)
            _report_deps(container, task_log)
            return handle
        # 超时未就绪：取第一个映射端口兜底（由 POC 环节自行失败）
        if isinstance(handle.host_port, dict):
            val = next(iter(handle.host_port.values()))
            handle.host_port = val[1] if isinstance(val, tuple) else val
            handle.internal_port = cfg["ports"][0]
        if allow_egress and net is not None and not using_proxy:
            try:
                net.disconnect(container)
                task_log("沙箱未就绪，已断开外网，后续仅做本地请求")
            except Exception:
                pass
        elif using_proxy:
            task_log("沙箱未就绪；受控代理阶段结束，保持 internal 网络")
        _report_deps(container, task_log)
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
