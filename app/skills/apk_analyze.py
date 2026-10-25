"""APK 静态分析 skill：androguard 解析 Manifest + DEX 字符串特征扫描"""
import re

from app.config import TASK_TIMEOUT

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "读取短信（可获验证码）",
    "android.permission.RECEIVE_SMS": "接收短信（可获验证码）",
    "android.permission.READ_CONTACTS": "读取通讯录",
    "android.permission.READ_CALL_LOG": "读取通话记录",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.CAMERA": "拍照",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.READ_EXTERNAL_STORAGE": "读取外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "android.permission.INSTALL_PACKAGES": "静默安装应用",
}

DEX_PATTERNS = [
    (".trust-all-certs", "HIGH", "证书校验禁用：实现信任所有证书的 TrustManager，可被中间人攻击",
     r"(checkServerTrusted|checkClientTrusted)\s*\([^)]*\)\s*\{\s*\}"),
    (".hostname-verifier-allow-all", "HIGH", "主机名校验关闭：ALLOW_ALL_HOSTNAME_VERIFIER，可被中间人攻击",
     r"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier"),
    (".js-interface", "MEDIUM", "JSBridge 暴露：addJavascriptInterface 且开启 JS，API<17 可被注入执行",
     r"setJavaScriptEnabled\s*\(\s*true\s*\)[\s\S]{0,200}addJavascriptInterface|addJavascriptInterface[\s\S]{0,200}setJavaScriptEnabled\s*\(\s*true"),
    (".http-cleartext", "MEDIUM", "明文 HTTP 通信：硬编码 http:// URL，数据可被窃听篡改",
     r"http://(?!127\.0\.0\.1|localhost|schemas\.android\.com|ns\.adobe\.com|apache\.org|w3\.org)[a-zA-Z0-9.\-]+"),
    (".hardcoded-secret", "MEDIUM", "硬编码密钥：DEX 中发现疑似密钥字符串（accesskey/secret 等）",
     r"(?i)(access[_-]?key|api[_-]?key|secret[_-]?key|app[_-]?secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=_\-]{12,}[\"']"),
    (".weak-random", "LOW", "弱随机数：使用 java.util.Random 生成安全相关值可被预测",
     r"new\s+java\.util\.Random|java\.util\.Random\."),
    (".sensitive-log", "LOW", "敏感信息日志：Log 输出疑似密码/token",
     r"(?i)Log\.[deiw]\s*\([^)]*(password|passwd|token|secret)[^)]*\)"),
    (".sql-concat", "HIGH", "SQL 注入风险：rawQuery/.execSQL 拼接变量",
     r"(rawQuery|execSQL)\s*\([^)]*\+\s*[a-zA-Z_]"),
    (".webview-file-access", "MEDIUM", "WebView 文件域访问：setAllowFileAccess(true) 可被本地文件读取利用",
     r"setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true"),
]


def run_apk_analysis(apk_path: str) -> tuple[dict, list[dict]]:
    """分析 APK，返回 (基本信息, 漏洞列表)"""
    from androguard.core.apk import APK

    a = APK(apk_path)
    info = {
        "package": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "main_activity": a.get_main_activity(),
    }

    vulns = []

    # ---- Manifest 静态检查 ----
    def _app_attr(name):
        try:
            return a.get_attribute_value("application", name)
        except Exception:
            return None

    if str(_app_attr("debuggable")).lower() in ("true", "0x1", "1"):
        vulns.append(_mk(".manifest-debuggable", "HIGH",
                         "应用可调试：android:debuggable=true，攻击者可 attach 调试器提取数据",
                         "AndroidManifest.xml", 0, "android:debuggable=\"true\""))
    if str(_app_attr("allowBackup")).lower() in ("true", "0x1", "1"):
        vulns.append(_mk(".manifest-allowbackup", "MEDIUM",
                         "允许应用数据备份：android:allowBackup=true，可被 adb backup 提取私有数据",
                         "AndroidManifest.xml", 0, "android:allowBackup=\"true\""))
    if str(_app_attr("usesCleartextTraffic")).lower() in ("true", "0x1", "1"):
        vulns.append(_mk(".manifest-cleartext", "MEDIUM",
                         "允许明文流量：usesCleartextTraffic=true，网络数据未强制 TLS",
                         "AndroidManifest.xml", 0, "usesCleartextTraffic=\"true\""))

    # 危险权限
    for perm in a.get_permissions():
        if perm in DANGEROUS_PERMISSIONS:
            vulns.append(_mk(".manifest-dangerous-permission", "LOW",
                             f"申请高危权限：{perm}（{DANGEROUS_PERMISSIONS[perm]}），需评估最小化原则",
                             "AndroidManifest.xml", 0, perm))

    # 导出组件未加权限保护：解析 manifest XML
    try:
        xml = a.get_android_manifest_axml().get_xml_obj()
        import lxml.etree as ET
        ns = "{http://schemas.android.com/apk/res/android}"
        for tag, cname in (("activity", "Activity"), ("service", "Service"),
                           ("receiver", "Receiver"), ("provider", "Provider")):
            for el in xml.iter(tag):
                name = el.get(f"{ns}name", "")
                exported = el.get(f"{ns}exported")
                has_intent = el.find("intent-filter") is not None
                perm = el.get(f"{ns}permission")
                if exported == "true" or (exported is None and has_intent):
                    if not perm:
                        vulns.append(_mk(
                            ".manifest-exported-component", "MEDIUM",
                            f"导出组件未授权访问：{cname} {name} 无 permission 保护，可被第三方应用调用",
                            "AndroidManifest.xml", 0, f"<{tag} {name} exported>"))
    except Exception:
        pass

    # ---- DEX 字符串特征扫描 ----
    try:
        from androguard.core.dex import DEX
        dex_data = b""
        import zipfile
        with zipfile.ZipFile(apk_path) as zf:
            for n in zf.namelist():
                if n.endswith(".dex"):
                    dex_data += zf.read(n)
        text = dex_data.decode("latin-1", errors="ignore")
        for suffix, severity, message, pattern in DEX_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                snippet = str(matches[0])[:200] if isinstance(matches[0], str) else pattern
                vulns.append(_mk(suffix, severity, message, "classes.dex", 0, snippet))
    except Exception:
        pass

    return info, vulns


def _mk(suffix: str, severity: str, message: str, file_path: str, line: int, snippet: str) -> dict:
    return {
        "rule_id": f"apk.rules{suffix}",
        "severity": severity,
        "file_path": file_path,
        "line": line,
        "code_snippet": snippet,
        "message": message,
    }
