"""漏洞规则 → 人类可读名称映射：让报告/列表显示"SQL 注入/任意文件读取"而非晦涩 rule_id"""

# 精确规则名 → 中文名（按子串匹配，放前面的优先）
EXACT_LABELS = [
    ("php-command-injection", "命令注入"),
    ("php-command-sink", "命令执行（敏感点）"),
    ("php-sql-injection", "SQL 注入"),
    ("php-sql-query-sink", "SQL 注入（敏感点）"),
    ("php-code-injection", "代码注入 (eval)"),
    ("php-file-inclusion", "文件包含 LFI/RFI"),
    ("php-unsafe-deserialization", "不安全反序列化"),
    ("php-file-read-sink", "任意文件读取"),
    ("php-file-delete-sink", "任意文件删除"),
    ("php-ssrf-sink", "SSRF / 任意文件读取"),
    ("php-xss-reflected", "反射型 XSS"),
    ("echoed-request", "回显型注入"),
]
# 关键字 → 中文名（覆盖 agent-discovered-*、二进制特征等）
KEYWORD_LABELS = [
    ("sqli", "SQL 注入"),
    ("sql-injection", "SQL 注入"),
    ("rce", "远程命令执行"),
    ("command-injection", "命令注入"),
    ("command", "命令注入"),
    ("file-read", "任意文件读取"),
    ("file-delete", "任意文件删除"),
    ("file-write", "任意文件写入"),
    ("file-upload", "任意文件上传"),
    ("file-inclusion", "文件包含 LFI/RFI"),
    ("unauth", "未授权访问"),
    ("idor", "越权访问 IDOR"),
    ("ssrf", "SSRF"),
    ("xxe", "XXE 外部实体注入"),
    ("deserialization", "不安全反序列化"),
    ("ssti", "模板注入 SSTI"),
    ("logic", "业务逻辑漏洞"),
    ("xss", "XSS 跨站脚本"),
    ("native-str", "二进制特征"),
]


def vuln_label(rule_id: str) -> str:
    """根据 rule_id 返回人类可读漏洞名；未知规则返回「疑似漏洞」"""
    if not rule_id:
        return "疑似漏洞"
    rid = str(rule_id).lower()
    last = rid.split(".")[-1]
    for key, label in EXACT_LABELS:
        if last == key or key in rid:
            return label
    for key, label in KEYWORD_LABELS:
        if key in rid:
            return label
    return "疑似漏洞"
