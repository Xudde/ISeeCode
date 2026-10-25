"""OS 镜像基线检查 skill：支持 docker save 的 tar 镜像包与 Dockerfile 两种输入
参考 CIS Docker Benchmark 思路做基线检查
"""
import re

# ---------- Dockerfile 文本规则 ----------
DOCKERFILE_RULES = [
    (".from-latest", "MEDIUM", "基础镜像未固定版本：FROM 使用 latest 标签，构建不可复现且可能引入未知漏洞",
     r"(?im)^\s*FROM\s+\S+:latest(\s+AS\s+\S+)?\s*$"),
    (".from-digest-missing", "LOW", "基础镜像未用 digest 固定：建议 FROM image@sha256:... 保证不可变",
     r"(?im)^\s*FROM\s+\S+:[\w.\-]+\s*$"),
    (".user-root", "HIGH", "容器以 root 运行：未声明 USER 指令或 USER root，逃逸风险高",
     r"(?im)^\s*USER\s+(root|0)\s*$"),
    (".user-missing", "MEDIUM", "未声明 USER 指令：镜像默认以 root 运行",
     r"(?im)^(?![\s\S]*^\s*USER\s+)(?=[\s\S]*^\s*(CMD|ENTRYPOINT))"),
    (".curl-sh", "HIGH", "远程脚本直接执行：curl/wget 管道 sh，供应链投毒风险",
     r"(?i)(curl|wget)[^|&;]*\|\s*(ba)?sh"),
    (".add-url", "MEDIUM", "ADD 拉取远程 URL：不如 COPY 安全可控，建议改用 RUN curl + 校验",
     r"(?im)^\s*ADD\s+https?://"),
    (".chmod-777", "MEDIUM", "过宽文件权限：chmod 777 使任意用户可改可执行",
     r"(?im)chmod\s+(-R\s+)?777\s"),
    (".env-secret", "HIGH", "ENV 疑似硬编码密钥：镜像分层可被 history 提取，应使用 Build Secret",
     r"(?im)^\s*ENV\s+\S*(secret|password|token|api[_-]?key|access[_-]?key)\S*\s*[=:\s][\"']?[A-Za-z0-9+/=_\-]{8,}"),
    (".sudo-install", "LOW", "容器内使用 sudo：容器内通常无需 sudo，扩大攻击面",
     r"(?im)^\s*RUN.*\bsudo\b"),
    (".ssh-exposed", "HIGH", "暴露高危端口：EXPOSE 22(SSH)/2375(Docker API)/2376，易被利用",
     r"(?im)^\s*EXPOSE\s+(22|2375|2376)(\s|$)"),
    (".apt-no-clean", "LOW", "包管理缓存未清理：apt/yum 安装后未 rm 缓存，增大镜像与信息泄露面",
     r"(?im)^\s*RUN\s+(apt-get|yum|apk)\s+install(?![\s\S]{0,300}(rm\s+-rf\s+/var/lib/apt|yum\s+clean|rm\s+-rf\s+/var/cache))"),
]

# 高危暴露端口
HIGH_RISK_PORTS = {"22": "SSH", "2375": "Docker API(未加密)", "2376": "Docker API", "3389": "RDP"}

# ENV 疑似密钥
ENV_SECRET_RE = re.compile(r"(?i)(secret|password|passwd|token|api_key|apikey|access_key)[=:][\"']?([A-Za-z0-9+/=_\-]{8,})")


def scan_dockerfile(text: str) -> list[dict]:
    vulns = []
    has_user = any(re.match(r"(?im)^\s*USER\s+", line) for line in text.splitlines())
    for suffix, severity, message, pattern in DOCKERFILE_RULES:
        if suffix == ".user-root" and not re.search(r"(?im)^\s*USER\s+(root|0)\s*$", text):
            continue
        if suffix == ".user-missing" and has_user:
            continue
        m = re.search(pattern, text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            snippet = text.splitlines()[line_no - 1].strip()[:200] if line_no - 1 < len(text.splitlines()) else pattern
            vulns.append(_mk(suffix, severity, message, "Dockerfile", line_no, snippet))
    return vulns


def scan_image_tar(tar_path: str, log) -> tuple[dict, list[dict]]:
    """docker load 镜像包并做运行时配置基线检查"""
    import docker
    client = docker.from_env(timeout=120)
    log("docker load 镜像包…")
    with open(tar_path, "rb") as f:
        image = client.images.load(f.read())[0]

    info = {"image_tags": image.tags or ["<untagged>"], "image_id": image.short_id}
    cfg = image.attrs.get("Config", {})
    vulns = []

    # 1. 运行用户
    user = (cfg.get("User") or "").strip()
    if user in ("", "root", "0", "0:0"):
        vulns.append(_mk(".image-root-user", "HIGH",
                         "镜像默认以 root 运行（Config.User 为空或 root），容器逃逸影响大",
                         "image-config", 0, f'User: "{user}"'))

    # 2. ENV 敏感信息
    for env in cfg.get("Env") or []:
        m = ENV_SECRET_RE.search(env)
        if m:
            vulns.append(_mk(".image-env-secret", "HIGH",
                             "镜像 ENV 疑似硬编码密钥：docker inspect 可直接读取",
                             "image-config", 0, env[:120]))

    # 3. 暴露高危端口
    for port in (cfg.get("ExposedPorts") or {}):
        pnum = port.split("/")[0]
        if pnum in HIGH_RISK_PORTS:
            vulns.append(_mk(".image-risk-port", "HIGH",
                             f"镜像暴露高危端口 {port}（{HIGH_RISK_PORTS[pnum]}）",
                             "image-config", 0, f"ExposedPorts: {port}"))

    # 4. 健康检查
    if not cfg.get("Healthcheck"):
        vulns.append(_mk(".image-no-healthcheck", "LOW",
                         "未配置 HEALTHCHECK：无法自动检测容器内服务异常",
                         "image-config", 0, "Healthcheck: null"))

    # 5. 构建历史中的危险命令
    history = " ; ".join(h.get("created_by", "") for h in image.attrs.get("History", []))
    for suffix, severity, message, pattern in [
        (".image-curl-sh", "HIGH", "镜像构建历史中发现 curl/wget 管道 sh 执行", r"(?i)(curl|wget)[^|;&]*\|\s*(ba)?sh"),
        (".image-chmod-777", "MEDIUM", "镜像构建历史中发现 chmod 777", r"(?i)chmod\s+(-R\s+)?777\s"),
        (".image-password-cmd", "HIGH", "镜像构建历史中发现疑似密码/密钥写入命令", r"(?i)(echo[^\n]{0,60}(password|passwd|token|secret))|(ENV\s+\S*(password|token|secret|api_key))"),
    ]:
        m = re.search(pattern, history)
        if m:
            vulns.append(_mk(suffix, severity, message, "image-history", 0, m.group(0)[:200]))

    return info, vulns


def _mk(suffix, severity, message, file_path, line, snippet):
    return {
        "rule_id": f"image.rules{suffix}",
        "severity": severity,
        "file_path": file_path,
        "line": line,
        "code_snippet": snippet,
        "message": message,
    }
