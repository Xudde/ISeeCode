"""技术栈识别 skill：根据特征文件与扩展名判断语言栈（阶段 1 扩展：主栈 + 次栈多列表）"""
import os
from pathlib import Path

# (技术栈, 特征文件集合——命中任一即算)
TECH_MARKERS = [
    ("python", {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "manage.py"}),
    ("java", {"pom.xml", "build.gradle", "build.gradle.kts"}),
    ("kotlin", {"build.gradle.kts", "settings.gradle.kts", "gradle.properties"}),
    ("php", {"composer.json", "composer.lock"}),
    ("javascript", {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}),
    ("typescript", {"tsconfig.json", "package.json"}),
    ("go", {"go.mod", "go.sum"}),
    ("csharp", {".csproj", ".sln", "global.json"}),
    ("cpp", {"CMakeLists.txt", "Makefile", "configure.ac", "meson.build"}),
    ("c", {"CMakeLists.txt", "Makefile"}),
    ("rust", {"Cargo.toml", "Cargo.lock"}),
    ("ruby", {"Gemfile", "Gemfile.lock", "Rakefile"}),
    ("swift", {"Package.swift", "Podfile", "*.xcodeproj"}),
    ("dart", {"pubspec.yaml", "pubspec.lock"}),
    ("scala", {"build.sbt", "build.sc"}),
    ("html", {"index.html"}),
]

# 特征文件：后缀即算命中（针对 .csproj/.sln 这类带后缀的项目文件）
EXT_NAME_MARKERS = {
    ".csproj": "csharp",
    ".sln": "csharp",
    ".xcodeproj": "swift",
}

# 扩展名兜底判定
EXT_MARKS = {
    ".py": "python", ".java": "java", ".php": "php",
    ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".cs": "csharp", ".cshtml": "csharp",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "cpp",
    ".kt": "kotlin", ".rb": "ruby", ".rs": "rust", ".swift": "swift",
    ".dart": "dart", ".scala": "scala", ".html": "html",
}

# semgrep 语言映射（semgrep 支持的语言）
SEMGREP_LANG = {
    "python": "python", "java": "java", "php": "php", "javascript": "javascript",
    "go": "go", "csharp": "csharp", "c": "c", "cpp": "cpp", "kotlin": "kotlin",
    "ruby": "ruby", "rust": "rust", "swift": "swift", "dart": "dart",
    "scala": "scala", "typescript": "typescript", "html": "generic",
}

# ts 文件计入 javascript 项目的兼容映射（扫描时共用 ts 规则）
_SCAN_ALIAS = {"javascript": ["javascript", "typescript"], "typescript": ["typescript", "javascript"]}

# 扩展名兜底：出现 1 个即可识别（小项目/单文件样本也能审计；
# 多栈时按文件数排序，主栈仍在前，误判成本远低于漏判导致跳过）
_EXT_MIN_COUNT = 1


def _walk(workspace: str):
    """遍历，返回 (top_files 集合, 扩展名计数, 所有文件名集合)"""
    root = Path(workspace)
    top_files: set[str] = set()
    exts: dict[str, int] = {}
    all_names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d not in
                       ("node_modules", ".git", "venv", ".venv", "__pycache__", "vendor", "target", "build", "dist")]
        depth_ok = (Path(dirpath) == root) or (len(Path(dirpath).parts) - len(root.parts) <= 3)
        for name in filenames:
            all_names.add(name)
            ext = Path(name).suffix.lower()
            exts[ext] = exts.get(ext, 0) + 1
            if depth_ok:
                top_files.add(name)
    return top_files, exts, all_names


def _match_stack(tech: str, top_files: set, all_names: set, exts: dict) -> bool:
    """判断某个技术栈是否命中"""
    markers = dict(TECH_MARKERS).get(tech, set())
    for m in markers:
        if m.startswith("."):  # 如 .csproj —— 任意层级的此类文件都算
            if any(n.endswith(m) for n in all_names):
                return True
        elif m in top_files:
            return True
    # 扩展名兜底
    if tech in EXT_MARKS.values():
        for ext, t in EXT_MARKS.items():
            if t == tech and exts.get(ext, 0) >= _EXT_MIN_COUNT:
                return True
    return False


def run_tech_detect(workspace: str) -> str:
    """兼容旧接口：返回主技术栈，无法识别返回 'unknown'"""
    stacks = run_tech_detect_multi(workspace)
    return stacks[0] if stacks else "unknown"


def run_tech_detect_multi(workspace: str) -> list[str]:
    """返回识别到的技术栈列表（主栈在前，最多 4 个）"""
    if not os.path.isdir(workspace):
        return []
    top_files, exts, all_names = _walk(workspace)

    hits: list[tuple[int, str]] = []
    for idx, (tech, _) in enumerate(TECH_MARKERS):
        if _match_stack(tech, top_files, all_names, exts):
            # 加权：命中扩展名文件数越多排序越靠前
            weight = sum(exts.get(e, 0) for e, t in EXT_MARKS.items() if t == tech)
            hits.append((-weight, idx, tech))

    hits.sort()
    seen, ordered = set(), []
    for _, _, tech in hits:
        if tech not in seen:
            seen.add(tech)
            ordered.append(tech)
        if len(ordered) >= 4:
            break
    return ordered


def get_scan_stacks(stacks: list[str]) -> list[str]:
    """返回实际参与 semgrep 扫描的语言列表（含别名展开、去重、过滤不支持语言）"""
    out: list[str] = []
    for t in stacks:
        for s in _SCAN_ALIAS.get(t, [t]):
            if s not in out and s in SEMGREP_LANG:
                out.append(s)
    return out
