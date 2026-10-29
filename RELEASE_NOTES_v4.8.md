# ISeeCode v4.8 发布说明

对比 v3.0，v4.8 把审计流水线、沙箱安全、审计/RBAC、CLI 和自定义规则完整收口。

## 主要变化

- **审计闭环**：多引擎静态扫描、候选去重、LLM 研判（可选）、沙箱 POC、报告
- **阶段 0–7**：补丁差分/利用链/四阶段 Agent/OSV 情报/ffuf 路径发现/Engine 注册表
- **沙箱安全**：
  - cap-drop ALL（保留 `NET_BIND_SERVICE`）
  - `no-new-privileges`、`init`、只读根
  - 依赖安装日志可见；Python/npm/Maven/Go 依赖落到 tmpfs
  - 端口只绑定 `127.0.0.1`
  - 依赖阶段 egress 白名单代理（GitHub 域名族、PyPI、npm、Maven、Go），直连外网被 internal 网络阻断
- **审计与 RBAC**：`audit_events` + `/audit` 页面；admin/auditor/viewer 令牌角色
- **CLI**：`tools/iseecode_cli.py`
- **自定义规则**：`data/rules/*.yaml`，Semgrep 校验后自动加载
- **Engine 注册表**：`GET /api/engines`，引擎顺序/开关/Docker 依赖可见

## 升级注意

1. 不再内置默认密码/token：启动前必须设置 `AUTH_TOKEN`；浏览器登录需设置 `AUTH_USER` / `AUTH_PASS`
2. 需要 Python 3.10+、Docker；先创建 `.venv` 并安装 `requirements.txt`
3. 旧数据库可直接启动，新增表/列会自动创建；`data/master.key` 用于配置密钥加密，需与数据库分开备份
4. 沙箱默认只读根 + egress 白名单；如网络受限，可调整 `data/egress_allowlist.txt`、`AUDIT_EGRESS_ALLOW_EXTRA`、`AUDIT_GOPROXY`

## 安全边界

`verified` 只代表沙箱内验证，不代表生产可利用或 0day；静态规则有误报/漏报。详见 README 与 `docs/ROADMAP.md`。
