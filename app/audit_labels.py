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
    ("concatenated-sql-query", "SQL 注入（拼接查询）"),
    ("tainted-sql", "SQL 注入"),
    ("sql-string", "SQL 注入"),
    ("sql-query", "SQL 注入"),
    ("sql-concat", "SQL 注入"),
    ("sql-execute", "SQL 注入"),
    ("rce", "远程命令执行"),
    ("command-injection", "命令注入"),
    ("tainted-exec", "命令注入"),
    ("tainted-callable", "动态函数调用（RCE）"),
    ("render-template-string", "模板注入 SSTI"),
    ("template-injection", "模板注入 SSTI"),
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
    ("xml-external", "XXE 外部实体注入"),
    ("deserialization", "不安全反序列化"),
    ("ssti", "模板注入 SSTI"),
    ("path-traversal", "路径穿越"),
    ("path-injection", "路径注入"),
    ("command-line-injection", "命令注入"),
    ("unsafe-deserialization", "不安全反序列化"),
    ("hardcoded-credentials", "硬编码凭据"),
    ("cleartext-storage", "明文存储"),
    ("cleartext-transmission", "明文传输"),
    ("zip-slip", "Zip Slip"),
    ("template-injection", "模板注入"),
    ("open-redirect", "开放重定向"),
    ("csrf", "CSRF 跨站请求伪造"),
    ("cookie-missing", "Cookie 安全属性缺失"),
    ("ldap-injection", "LDAP 注入"),
    ("xpath", "XPath 注入"),
    ("hardcoded", "硬编码敏感信息"),
    ("secret", "疑似密钥泄露"),
    ("insecure-random", "不安全随机数"),
    ("weak-crypto", "弱加密算法"),
    ("logic", "业务逻辑漏洞"),
    ("xss", "XSS 跨站脚本"),
    ("driver-unsigned", "驱动未嵌入签名"),
    ("driver-device-exposure", "驱动设备对象暴露"),
    ("driver-symbolic-link", "驱动用户态接口暴露"),
    ("driver-wdf-device", "WDF 设备对象"),
    ("driver-ioctl-surface", "IOCTL 攻击面"),
    ("driver-mmio", "内核物理内存映射"),
    ("driver-process-memory", "跨进程内存操作"),
    ("driver-callbacks", "内核回调"),
    ("driver-writable-code", "可写可执行节"),
    ("driver-missing-mitigations", "驱动缓解措施缺失"),
    ("driver-pdb-path", "PDB 路径泄露"),
    ("driver-device-names", "驱动设备名线索"),
    ("driver-network-indicators", "驱动网络地址线索"),
    ("driver-summary", "驱动静态画像"),
    ("driver-parse-error", "驱动 PE 解析异常"),
    ("driver-not-kernel", "非标准内核驱动"),
    ("driver-imports-none", "驱动无导入表"),
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
