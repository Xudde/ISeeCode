# -*- coding: utf-8 -*-
"""人工深挖 Top-N 文件清单（阶段二）：把批量预筛收敛成「先读哪几个文件」。

零 token：只用已有漏洞记录 + 路径启发式 + 候选文件头特征，不调用 LLM。
排序 = 命中严重性（同规则去重、verified 加权）+ 攻击面路径权重 + 入口/鉴权特征。
"""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from app.audit_labels import vuln_label

SKIP_DIRS = {
    "node_modules", "vendor", "third_party", "thirdparty", "bower_components",
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "dist", "build",
    "target", "obj", "coverage", ".next", ".nuxt",
}
SEV_WEIGHT = {"CRITICAL": 9.0, "ERROR": 7.0, "HIGH": 7.0,
              "WARNING": 3.5, "MEDIUM": 3.5, "INFO": 1.0, "LOW": 1.0}
SEV_ORDER = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "WARNING": 2,
             "MEDIUM": 2, "INFO": 3, "LOW": 4}

PATH_RULES = (
    (("auth", "login", "session", "token", "jwt", "sso", "oauth", "shiro",
      "security", "permission", "privilege", "acl"), 8, "鉴权/会话"),
    (("controller", "servlet", "handler", "endpoint", "action"), 5, "入口/控制器"),
    (("route", "router", "routing"), 4, "路由"),
    (("upload", "download", "import", "export"), 4, "文件操作"),
    (("exec", "command", "shell"), 4, "命令执行面"),
    (("sql", "jdbc", "dao", "mapper", "query"), 3, "数据访问"),
    (("admin", "manage", "console", "system"), 3, "后台管理"),
    (("filter", "interceptor", "config", "setting"), 3, "配置/过滤链"),
    (("template", "freemarker", "velocity", "thymeleaf", "ognl", "spel",
      "expression", "deserialize", "serial"), 3, "表达式/反序列化"),
    (("proxy", "ssrf", "redirect"), 2, "网络请求/跳转"),
)
CONFIG_NAMES = {"application.yml", "application.yaml", "application.properties",
                "bootstrap.yml", "bootstrap.yaml", "web.xml", "shiro.ini",
                "dockerfile", "nginx.conf", "appsettings.json", "web.config",
                ".env", "settings.py", "config.py", "config.js", "default.js",
                "environment.js", "application.conf"}
DEP_MANIFEST_NAMES = {"pipfile", "pipfile.lock", "poetry.lock", "uv.lock",
                      "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                      "npm-shrinkwrap.json", "composer.lock", "go.sum",
                      "gemfile.lock", "cargo.lock", "pom.xml", "build.gradle",
                      "build.gradle.kts", "gradle.lockfile", "packages.config",
                      "directory.packages.props", "pyproject.toml", "setup.py",
                      "setup.cfg", "go.mod", "package.json",
                      "build.properties", "build.properties.default"}


def _is_dep_manifest(fp: str) -> bool:
    name = fp.rsplit("/", 1)[-1].lower()
    return name in DEP_MANIFEST_NAMES or (
        name.startswith("requirements") and name.endswith(".txt"))
CODE_EXTS = {".java", ".cs", ".py", ".php", ".rb", ".go", ".js", ".mjs", ".ts",
             ".tsx", ".jsx", ".vue", ".kt", ".kts", ".jsp", ".jspx", ".aspx",
             ".ascx", ".ashx", ".c", ".cpp", ".cc", ".h", ".hpp", ".rs", ".swift",
             ".scala", ".dart"}
LOW_VALUE_EXTS = {".md", ".txt", ".rst", ".css", ".scss", ".less", ".png", ".jpg",
                  ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
                  ".eot", ".map", ".lock"}
LOW_VALUE_DIRS = {"test", "tests", "spec", "specs", "docs", "doc", "examples",
                  "example", "samples", "fixtures"}
# 混合包自动反编译时，第三方 DLL 会被展开到 decompiled_embedded/<组件名>/；
# 人工深挖应优先应用自身代码，已知运行库/协议库降权（否则 IKVM/BouncyCastle 会霸榜）。
DECOMPILED_PREFIX = "decompiled_embedded/"
THIRD_PARTY_COMPONENTS = (
    "ikvm", "bouncycastle", "bouncy", "dotnetcasclient", "newtonsoft", "npoi",
    "log4net", "entityframework", "quartz", "castle", "autofac", "microsoft",
    "system", "oracle", "mysql", "icsharpcode", "antlr", "nlog", "grpc",
    "protobuf", "apache", "java", "javax", "spring", "hibernate", "jackson",
    "fastjson", "netty", "guava", "slf4j", "commons", "zookeeper", "jetty",
    "tomcat", "logback", "mybatis", "druid", "swagger", "knife4j",
    "aliyun", "aws", "azure", "tencent", "qcloud", "alipay", "wechatpay", "paypal",
)
FRONTEND_LIB_MARKERS = (
    "jquery", "amazeui", "bootstrap", "lodash", "underscore", "moment",
    "angular", "backbone", "zepto", "layui", "easyui", "kindeditor",
    "ueditor", "swiper", "echarts", "highcharts", "modernizr",
    "ajaxfileupload", "font-awesome", "ext-all", "jquery-ui", "bootstrap-table",
)

ENTRY_PATTERNS = (
    (re.compile(r"@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b"), 6, "Spring 入口"),
    (re.compile(r"extends\s+HttpServlet\b|void\s+do(Get|Post)\s*\("), 5, "Servlet 入口"),
    (re.compile(r"\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b|class\s+\w+Controller\b"), 5, ".NET 入口"),
    (re.compile(r"@(app|router)\.(route|get|post|put|delete|patch)\s*\("), 5, "Python Web 入口"),
    (re.compile(r"\b(app|router)\.(get|post|put|delete|patch|use)\s*\("), 4, "Node 路由"),
    (re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b"), 3, "PHP 入口"),
)
AUTH_RE = re.compile(
    r"@(PreAuthorize|RequiresPermissions|RequiresRoles|Secured)\b|checkPermission|login_required|isAuthenticated|authenticate\s*\(",
    re.I)
COMMENTED_AUTH_RE = re.compile(
    r"(?://|#|\*)[^\n]*@(RequiresPermissions|PreAuthorize|RequiresRoles)", re.I)


def _get(obj, name, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _is_fp(v) -> bool:
    return _get(v, "agent_status") == "false_positive" or _get(v, "llm_is_real") is False


def _line(f) -> int:
    try:
        return int(_get(f, "line", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _norm_path(fp, ws) -> str:
    fp = str(fp or "").replace("\\", "/").strip()
    if not fp or fp.startswith("("):
        return ""
    if ws:
        try:
            p = Path(fp)
            if p.is_absolute():
                return str(p.resolve().relative_to(Path(ws).resolve())).replace("\\", "/")
        except Exception:
            pass
    return fp.lstrip("./")


def _path_meta(fp: str) -> tuple[float, list[str]]:
    low = fp.lower()
    name = low.rsplit("/", 1)[-1]
    ext = Path(name).suffix
    score = 0.0
    tags: list[str] = []
    if name in CONFIG_NAMES:
        score += 6
        tags.append("关键配置")
    elif ext in (".yml", ".yaml", ".properties", ".xml", ".config", ".conf",
                 ".ini", ".toml", ".env"):
        score += 3
        tags.append("配置")
    if ext in CODE_EXTS:
        score += 2
    if ext == ".sys":
        score += 10
        tags.append("Windows 驱动")
    if name.endswith(".min.js") or name.endswith(".min.css") or ".min." in name or "-min." in name:
        score -= 5
    if any(k in name for k in FRONTEND_LIB_MARKERS):
        score -= 8
        tags.append("前端第三方库降权")
    if ext in LOW_VALUE_EXTS:
        score -= 5
    if any(x in LOW_VALUE_DIRS for x in low.split("/")[:-1]):
        score -= 7
        tags.append("测试/文档降权")
    stem = name.rsplit(".", 1)[0]
    if (re.search(r"(^|[_\-.])(test|tests|spec|fixtures?|examples?)([_\-.]|$)", stem)
            or "/.github/" in f"/{low}/"):
        score -= 5
        tags.append("测试/CI 降权")
    if ("/compiled/" in f"/{low}/" or "/ci/" in f"/{low}/"
            or low.startswith(".github/") or low.startswith("github/")
            or "/github/workflows/" in f"/{low}/"
            or "/github/actions/" in f"/{low}/"):
        score -= 10
        tags.append("编译产物/CI 降权")
    if low.startswith(DECOMPILED_PREFIX):
        comp = low[len(DECOMPILED_PREFIX):].split("/", 1)[0]
        if any(comp.startswith(m) for m in THIRD_PARTY_COMPONENTS):
            score -= 15
            tags.append("第三方库降权")
    for keys, weight, tag in PATH_RULES:
        if any(k in low for k in keys):
            score += weight
            if tag not in tags:
                tags.append(tag)
    return score, tags


def _head_text(path: Path, limit=8192, max_size=2 * 1024 * 1024) -> str:
    try:
        if not path.is_file() or path.stat().st_size > max_size:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def _entry_features(text: str) -> tuple[float, list[str]]:
    if not text:
        return 0.0, []
    bonus, tags = 0.0, []
    for rx, weight, tag in ENTRY_PATTERNS:
        if rx.search(text):
            bonus += weight
            tags.append(tag)
            break
    if AUTH_RE.search(text):
        bonus += 2
        tags.append("含鉴权校验")
    if COMMENTED_AUTH_RE.search(text):
        bonus += 5
        tags.append("疑似权限注解被注释")
    return bonus, tags


def _focus(rule_ids: list[str], labels: list[str]) -> str:
    txt = (" ".join(rule_ids) + " " + " ".join(labels)).lower()
    if "driver" in txt or "驱动" in txt:
        if "unsigned" in txt or "签名" in txt:
            return "核对嵌入签名/目录签名（Windows Get-AuthenticodeSignature）与加载策略；无签名按 BYOVD 风险处理"
        if "device" in txt or "设备" in txt:
            return "定位设备创建后的 DACL/SDDL 与 IRP_MJ_CREATE 处理，确认低权限用户能否打开设备"
        if "ioctl" in txt or "irp" in txt:
            return "审查 IOCTL 控制码、输入/输出长度与调用者权限，寻找未校验的缓冲区操作"
        if "mmio" in txt or "物理内存" in txt or "process-memory" in txt or "跨进程" in txt:
            return "确认高危原语仅管理员可达，并复核地址/进程来源与边界校验"
        return "按设备入口 → IOCTL 分发 → 参数校验顺序人工复核，必要时结合反汇编/动态测试"
    if any(k in txt for k in ("shiro", "anon", "permission", "auth", "unauth",
                              "idor", "越权", "匿名", "权限")):
        return "核对鉴权链、匿名放行范围与权限注解是否真实生效"
    if any(k in txt for k in ("sql", "sqli", "注入")):
        return "从入口追踪参数到 SQL sink，确认预编译/过滤是否可绕过"
    if any(k in txt for k in ("secret", "key", "token", "password", "密钥", "口令")):
        return "确认密钥是否可用于生产环境；若有效立即轮换并排查泄露路径"
    if "cookie" in txt:
        return "检查 Cookie 的 HttpOnly/Secure/SameSite 属性与跨站可利用场景"
    if "csrf" in txt:
        return "检查 CSRF Token、SameSite 与关键写操作的来源校验"
    if "redirect" in txt:
        return "确认跳转目标是否白名单校验，构造外部域名跳转"
    if any(k in txt for k in ("upload", "上传")):
        return "检查上传类型/大小白名单、落盘路径与访问权限"
    if any(k in txt for k in ("deserial", "反序列化")):
        return "确认反序列化输入来源与可用利用链（gadget）"
    if any(k in txt for k in ("rce", "command", "exec", "命令")):
        return "确认命令拼接参数是否可被外部控制"
    if any(k in txt for k in ("file", "read", "download", "traversal", "文件", "读取")):
        return "验证路径穿越、越权读取与下载权限"
    if "xss" in txt:
        return "检查输出编码与 CSP，构造回显 payload"
    return "阅读入口与权限校验，确认可达性与利用链"


def resolve_workspace(task) -> str:
    ws = str(_get(task, "workspace_path", "") or "")
    if _get(task, "project_type") == "decompile":
        try:
            from app.config import WORKSPACE_DIR
            dec = WORKSPACE_DIR / f"task_{_get(task, 'id')}" / "decompiled"
            if dec.is_dir():
                return str(dec)
        except Exception:
            pass
    return ws


def build(task, vulns, workspace: str | None = None, top_n: int = 20) -> dict:
    ws = workspace if workspace is not None else resolve_workspace(task)
    top_n = max(1, min(int(top_n or 20), 50))

    grouped = defaultdict(list)
    for v in (vulns or []):
        if _is_fp(v):
            continue
        fp = _norm_path(_get(v, "file_path", ""), ws)
        if not fp:
            continue
        if any(part.lower() in SKIP_DIRS for part in fp.split("/")[:-1]):
            continue
        grouped[fp].append(v)

    meta: dict[str, dict] = {}
    for fp, fs in grouped.items():
        by_rule = defaultdict(list)
        for f in fs:
            by_rule[str(_get(f, "rule_id", ""))].append(f)
        base = 0.0
        for group in by_rule.values():
            best = max((str(_get(x, "severity", "INFO")).upper() for x in group),
                       key=lambda s: SEV_WEIGHT.get(s, 1.0))
            w = SEV_WEIGHT.get(best, 1.0)
            base += w + min(len(group) - 1, 3) * 0.25 * w
        if any(_get(f, "agent_status") == "verified" for f in fs):
            base *= 1.5
        poc_hit = any(_get(f, "poc_verified") is True for f in fs)
        if poc_hit:
            base *= 2.5
        dep_manifest = _is_dep_manifest(fp)
        if dep_manifest:
            base = min(base, 12.0)
        name = fp.rsplit("/", 1)[-1].lower()
        ext = Path(name).suffix
        is_config = name in CONFIG_NAMES or ext in (
            ".yml", ".yaml", ".properties", ".xml", ".config", ".conf", ".ini")
        if is_config:
            base = min(base, 12.0)
        sink_hit = any(
            any(k in str(_get(f, "rule_id", "")).lower() for k in (
                "exec", "eval", "command", "injection", "deserialization",
                "traversal", "zipslip", "path-injection", "ssrf", "xxe",
                "upload", "template", "jndi", "authz", "unauth"))
            for f in fs)
        if sink_hit:
            base *= 1.3
        ps, tags = _path_meta(fp)
        if poc_hit:
            tags.append("POC 已复现")
        if dep_manifest:
            tags.append("依赖清单（CVE 汇总，降权）")
        if is_config:
            tags.append("配置基线（降权）")
        if sink_hit:
            tags.append("危险 sink")
        meta[fp] = {"base": base, "path_score": ps, "tags": list(tags),
                    "findings": fs, "entry_bonus": 0.0}

    total_files = 0
    if ws and os.path.isdir(ws):
        path_only = []
        for dirpath, dirnames, filenames in os.walk(ws):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            for name in filenames:
                total_files += 1
                fp = os.path.relpath(os.path.join(dirpath, name), ws).replace("\\", "/")
                if fp in meta:
                    continue
                ps, tags = _path_meta(fp)
                if ps >= 5 and "第三方库降权" not in tags:
                    path_only.append((ps, fp, tags))
        path_only.sort(key=lambda x: -x[0])
        for ps, fp, tags in path_only[:300]:
            meta[fp] = {"base": 0.0, "path_score": ps, "tags": list(tags),
                        "findings": [], "entry_bonus": 0.0}

    ranked = sorted(meta.items(), key=lambda kv: -(kv[1]["base"] + kv[1]["path_score"]))
    if ws and os.path.isdir(ws):
        for fp, m in ranked[:60]:
            text = _head_text(Path(ws) / fp)
            bonus, tags = _entry_features(text)
            m["entry_bonus"] = bonus
            for t in tags:
                if t not in m["tags"]:
                    m["tags"].append(t)

    ranked = sorted(meta.items(), key=lambda kv: -(
        kv[1]["base"] + kv[1]["path_score"] + kv[1]["entry_bonus"]))

    def _emit(fp, m):
        fs = sorted(m["findings"], key=lambda f: (
            SEV_ORDER.get(str(_get(f, "severity", "INFO")).upper(), 4), -_line(f)))
        labels, rids = [], []
        for f in fs[:8]:
            rid = str(_get(f, "rule_id", ""))
            rids.append(rid)
            lab = _get(f, "title") or vuln_label(rid) or "疑似漏洞"
            if lab not in labels:
                labels.append(lab)
        verified = sum(1 for f in fs if _get(f, "agent_status") == "verified")
        reasons = []
        if fs:
            reasons.append(f"{len(fs)} 条静态命中（{'、'.join(labels[:3])}）")
            if verified:
                reasons.append(f"{verified} 条 Agent 已确认")
        else:
            reasons.append("无静态命中，但属于高价值审计面")
        reasons.extend(m["tags"][:4])
        findings = [{
            "rule_id": str(_get(f, "rule_id", "")),
            "title": _get(f, "title") or vuln_label(str(_get(f, "rule_id", ""))),
            "severity": str(_get(f, "severity", "INFO")).upper(),
            "line": _line(f),
            "source": _get(f, "source", ""),
            "agent_status": _get(f, "agent_status"),
        } for f in fs[:5]]
        return {
            "rank": 0,
            "file_path": fp,
            "score": round(m["base"] + m["path_score"] + m["entry_bonus"], 1),
            "reasons": reasons[:6],
            "tags": m["tags"][:6],
            "findings": findings,
            "focus": _focus(rids, labels),
        }

    selected, per_mod, used = [], Counter(), set()
    for fp, m in ranked:
        if len(selected) >= top_n:
            break
        mod = "/".join(fp.split("/")[:2]) if "/" in fp else fp
        if per_mod[mod] >= 4:
            continue
        selected.append(_emit(fp, m))
        per_mod[mod] += 1
        used.add(fp)
    if len(selected) < top_n:
        for fp, m in ranked:
            if len(selected) >= top_n:
                break
            if fp in used:
                continue
            selected.append(_emit(fp, m))
            used.add(fp)
    for i, item in enumerate(selected, 1):
        item["rank"] = i

    return {
        "task_id": _get(task, "id"),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files_considered": total_files or len(meta),
        "items": selected,
    }


def to_markdown(task, data: dict) -> str:
    items = data.get("items") or []
    lines = [
        f"# 任务 #{_get(task, 'id')} · 人工深挖 Top {len(items)}",
        "",
        f"- **目标**：{_get(task, 'filename', '')}",
        f"- **技术栈**：{_get(task, 'tech_stack', '')}",
        f"- **生成时间**：{data.get('generated_at', '')}",
        f"- **候选文件**：{data.get('total_files_considered', 0)}",
        "",
        "> 平台已完成批量预筛；下面按「命中严重性 + 攻击面位置 + 入口特征」排序。",
        "> 请从第 1 个文件开始读，逐条确认可达性、鉴权前提与利用链；不需要重新扫全仓。",
        "",
    ]
    for it in items:
        lines += [f"## {it['rank']}. `{it['file_path']}`（优先级 {it['score']}）", "",
                  f"- **为什么先看**：{'；'.join(it.get('reasons') or [])}"]
        for f in (it.get("findings") or [])[:5]:
            lines.append(f"- **命中**：{f['severity']} {f['title']}（第 {f['line']} 行 · {f['source']}）")
        lines += [f"- **建议动作**：{it.get('focus', '')}", ""]
    return "\n".join(lines)
