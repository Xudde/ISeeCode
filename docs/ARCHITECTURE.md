# ISeeCode 架构与运行边界

## 1. 组件

- `app/main.py`：FastAPI 入口、鉴权/审计中间件、worker 启动
- `app/queue_worker.py`：任务优先级队列、流水线编排、沙箱 POC、全量审计
- `app/skills/`：扫描引擎、沙箱、报告、OSV、补丁差分、利用链等
- `app/agent/`：内部 ReAct Agent（四阶段）和外部 Agent 协议
- `app/routes/`：任务、配置、审计、情报、引擎、验证库 API
- `templates/ static/`：Jinja2 页面与主题
- `tools/iseecode_cli.py`：命令行客户端

## 2. 任务流水线

```
上传/解压
  → 技术栈识别
  → semgrep 规则包 + 自定义规则
  → gitleaks / trivy / CodeQL / JS 情报 / OSV
  → 候选去重与严重性映射
  → 可选 LLM 研判（无 key 则跳过）
  → Docker 沙箱部署 + POC 验证
  → 可选 Agent 深挖/全量审计
  → 报告（HTML / Markdown / JSON）
```

任务状态通过 `tasks.status` 记录。`verified`、`poc_verified` 和 `llm_is_real` 是不同维度，报告会分别展示，不互相冒充。

## 3. 数据

SQLite WAL，核心表：

| 表 | 用途 |
|---|---|
| `tasks` | 任务、沙箱、token、日志 |
| `vulnerabilities` | 候选/验证结果、证据、POC |
| `agent_runs` | 外部 Agent 租约、阶段、checkpoint |
| `exploit_chains` | 利用链节点/边与验证状态 |
| `authz_endpoints` | 鉴权语义清单 |
| `patch_features` | 补丁差分特征 |
| `intel_watchlist/intel_events` | OSV 监控与事件 |
| `audit_events` | 操作审计 |

## 4. 引擎

`app/skills/engines.py` 定义 `EngineSpec`/`EngineContext` 注册表；内置引擎：

1. `jsintel`：JS 端点、密钥、sourcemap
2. `codeql`：security-extended 数据流（小仓库）
3. `semgrep`：内置 authz/config 规则 + `data/rules`
4. `gitleaks`：密钥熵（Docker）
5. `trivy`：配置/密钥（Docker）
6. `trivy_cve`：依赖 CVE（Docker）
7. `self_cve`：OSV 包级查询

`data/rules/*.yaml|*.yml` 会在每次扫描前用 `semgrep --validate` 校验；无效规则跳过并写任务日志。最多 50 个，`AUDIT_MAX_CUSTOM_RULES` 可调。

## 5. 沙箱安全

- 容器资源：512MB / 1 CPU / 128 pids
- `cap_drop=ALL`，仅保留 `NET_BIND_SERVICE`（PHP 80）
- `no-new-privileges`、`init`
- 只读根文件系统，可写仅 tmpfs：`/tmp`、`/var/tmp`、`/run`、`/root`
- Python 依赖安装到 `/tmp/pydeps`；npm/Maven/Go 缓存到 `/tmp`
- 宿主端口只绑定 `127.0.0.1`
- 依赖阶段使用 `egress_proxy.py`：代理双网卡（internal + egress），只允许 HTTP/HTTPS 到包管理器/代码托管白名单，拒绝私网 IP；沙箱只连 internal，不会直连外网
- 依赖安装失败会写任务日志，不静默

边界：Docker bind mount 不能在运行中切换，`/app` 在依赖阶段及之后就绪后仍为读写；只读根保护系统目录，不保护工作区。代理白名单默认包含 GitHub 域名族、PyPI、npm、Maven、Go 镜像；新根域名可写入 `data/egress_allowlist.txt` 或 `AUDIT_EGRESS_ALLOW_EXTRA`，下一个沙箱任务自动重建代理。

## 6. 关键环境变量

| 变量 | 作用 |
|---|---|
| `AUTH_TOKEN` | 必填，admin Bearer/cookie token |
| `AUTH_USER` / `AUTH_PASS` | 浏览器登录账号 |
| `AUTH_TOKEN_AUDITOR` / `AUTH_TOKEN_VIEWER` | 可选只读角色 token |
| `AUDIT_SANDBOX_EGRESS` | `0/1/auto` 沙箱外网策略 |
| `AUDIT_SANDBOX_EGRESS_PROXY` | `0` 关闭白名单代理，回退普通 egress |
| `AUDIT_EGRESS_ALLOW_EXTRA` | 追加允许域名（逗号分隔） |
| `AUDIT_GOPROXY` | Go 模块代理，默认 `https://goproxy.cn,direct` |
| `AUDIT_GIANTS` | `0` 关闭组合引擎 |
| `AUDIT_CODEQL_BIN` | CodeQL CLI 路径 |
| `AUDIT_MAX_CUSTOM_RULES` | 自定义规则上限，默认 50 |

## 7. 报告与 AI

报告有三种格式：自包含 HTML、Markdown、结构化 JSON。LLM 配置通过平台设置页写入数据库；`api_key` 使用 AES-256-GCM 加密，主密钥来自 `ISEECODE_MASTER_KEY` 或 `data/master.key`（0600）。**master.key 必须与数据库分开备份**。
