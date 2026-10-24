# 源码自动化审计平台（V2）

上传项目源码 → 自动化代码审计（semgrep + 官方规则包）→ Agent 深度研判（ReAct 全量审计）→ Docker 沙箱部署 → 自动/手动 POC 验证 → 生成可视化审计报告。

> 当前版本：**V2**（阶段 3.5 已完成，可交付使用）。支持 Web 源码 / APK / 二进制反编译审计、Agent 全量审计（覆盖未授权访问等逻辑漏洞）、沙箱保留手工验证、任务分区管理与一键停止/删除。

## 启动说明

环境要求：Ubuntu 22.04、Python 3.10+

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务
uvicorn app.main:app --reload

# 3. 浏览器访问
#   首页（上传入口 + 任务列表）: http://127.0.0.1:8000/
#   LLM 配置页:               http://127.0.0.1:8000/config
#   API 文档:                 http://127.0.0.1:8000/docs
```

## 目录结构

- `app/` 后端代码（FastAPI 入口、模型、路由、任务队列、skills 模块）
- `app/agent/` Agent 审计引擎（ReAct 循环、工具集、orchestrator 调度）
- `app/skills/` 审计能力模块（semgrep 扫描、反编译、沙箱、POC、报告生成）
- `app/audit_labels.py` 中文漏洞名映射（SQL 注入 / RCE / 未授权访问…）
- `templates/` Jinja2 页面
- `static/` 静态资源
- `docs/` 架构设计文档与归档
- `data/` 运行时数据（uploads / workspaces / reports / app.db，已加入 .gitignore）

## API 一览

| 方法     | 路径                                 | 功能                                                         |
| -------- | ------------------------------------ | ------------------------------------------------------------ |
| POST     | /api/tasks/upload                    | 上传 zip/apk/二进制创建任务（SHA-256 去重，重复返回 409）    |
| GET      | /api/tasks                           | 任务列表                                                     |
| GET      | /api/tasks/{id}                      | 任务详情                                                     |
| GET      | /api/tasks/{id}/report               | 下载审计报告                                                 |
| POST     | /api/tasks/{id}/stop                 | 停止任务（立即销毁沙箱容器）                                 |
| DELETE   | /api/tasks/{id}                      | 删除任务（彻底清理漏洞/上传/工作区/报告）                    |
| POST     | /api/tasks/{id}/poc-test             | 手工验证：在保留的沙箱容器内发起 payload 请求并回显          |
| GET      | /api/tasks/{id}/poc-script/{vuln_id} | 下载独立可运行的 Python POC 脚本                             |
| GET/POST | /api/config                          | 获取 / 更新 LLM 配置（base_url / api_key / model，任意 OpenAI 兼容接口） |


## 升级改造（阶段0 P0 修复完成）

- **鉴权**：设置环境变量 `AUTH_TOKEN=xxx` 后所有接口/页面需认证（`Authorization: Bearer <token>`、`?token=` 或 cookie）；未配置则启动时告警，建议仅本机/内网使用。登录入口 `/login?token=<AUTH_TOKEN>`
- **沙箱安全**：容器运行于 internal 网络 `audit-sandbox-net`（禁出网），工作区只读挂载，512MB/1CPU/128pids 限制保留；POC 通过 `docker exec` 在容器内发请求
- **队列恢复**：服务重启自动将非终态任务重置为 pending 重新入队
- **SQLite WAL**：已启用，降低长事务锁冲突
- **日志**：`data/server.log`（含 worker 异常堆栈）
- **go 规则**：`app/skills/rules/go.yaml`（7 条），不再依赖 `--config auto`
- **LLM 布尔容错**：严格 `isinstance(x, bool)` 校验，`"false"` 字符串不再误判

### 启动

```
export AUTH_TOKEN=你的访问令牌
pip install -r requirements.txt && uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 升级改造（阶段1 多语言规则扩充完成）

- **新增 11 个语言规则集**（各 5~7 条）：`csharp / c / cpp / kotlin / ruby / rust / swift / dart / scala / typescript / html`，覆盖 SQL 注入、命令注入、eval 代码执行、反序列化、硬编码密钥、路径穿越、SSRF、弱加密、XSS 等类型；规则目录共 16 个语言文件
- **tech_detect 多栈识别**：返回主栈 + 次栈列表（最多 4 个），marker 扩展至 `.csproj/.sln/CMakeLists.txt/Makefile/Cargo.toml/pubspec.yaml/build.sbt/Gemfile/Package.swift/tsconfig.json` 等；扩展名兜底覆盖 .cs/.c/.cpp/.kt/.rb/.rs/.swift/.dart/.scala/.tsx 等
- **sast 多栈扫描**：一次任务按识别到的栈分别用对应规则扫描并去重合并；单栈扫描失败自动降级不中断任务
- **官方规则集**：对 python/java/javascript/typescript/go/php 主栈自动附加 `p/security-audit` + `p/owasp-top-ten`（首次联网拉取约数秒，semgrep 本地缓存后离线可用；探测结果记录于 `data/official_rules.flag`，不可用时自动降级内置规则）。可用 `AUDIT_OFFICIAL_RULES=0` 关闭
- **验收结果**：
  - 10 种语言迷你漏洞样本全部命中对应规则（可复现：`/tmp/langtest` 生成逻辑见升级文档）
  - JeecgBoot 3.9.5 全量扫描（984 Java + 1749 前端文件）：识别 java/typescript/javascript/html 四栈，88 秒检出 **1255 条**（含官方规则集贡献的 spring-sqli、unrestricted-request-mapping、insecure-trust-manager 等），远超 ≥20 条验收线
  - 回归：test_vuln_app.zip 任务 completed，POC 验证 4/4 通过

## 升级改造（阶段2 反编译支持完成）

- **新增上传类型 `decompile`**：`.jar/.war/.class`（cfr→Java 源码）、`.dex`（jadx→Java 源码）、`.dll/.exe`（ilspycmd→C#，需 dotnet-sdk）、`.pyc`（pycdc/decompyle3→Python）、`.so/.elf/.bin`（原生二进制，仅字符串特征）
- **流程**：上传 → sha256 缓存检查（`data/decompiled_cache/{kind}_{hash32}/`）→ 反编译产物落 `data/workspaces/task_N/decompiled/`（标注“反编译代码，行号仅供参考”）→ 按产物语言 tech_detect + semgrep 多栈扫描 → 报告
- **失败降级**：工具缺失或反编译失败时自动降级为字节码字符串特征扫描（Runtime.exec/ObjectInputStream/DexClassLoader/JNDI 等 10 类危险 API 特征），任务不中断
- **工具安装**：`bash scripts/install_decompilers.sh`（自动装 openjdk/cfr/jadx/apktool，可选 ilspycmd 与 decompyle3；本环境已装 cfr 0.152 + jadx 1.5.0）
- **安全**：Zip Slip 防护保留；反编译目标数上限 200；缓存按内容 hash 复用
- **验收结果**：
  - vuln.jar（编译期注入 SQL 拼接+命令执行）：cfr 反编译 → 检出 3 条（官方 formatted-sql-string + 自研 sql-concat/command-concat），二次上传缓存秒级命中
  - 真 dex（r8 编译生成）：jadx 反编译 → 检出 2 条（SQL 拼接 + 命令注入）
  - fake_native.so（无源二进制）：正确降级字符串特征扫描，任务 completed 不中断
  - 回归：web zip 任务 completed，POC 4/4；`.apk` 仍走原有 androguard 移动分析路径

## 升级改造（阶段3 Agent 审计引擎完成）

- **架构**：保留 semgrep 预筛层，新增 Agent 深度研判层（`app/agent/`：react.py ReAct 循环 + tools.py 10 工具集 + orchestrator.py 调度）
- **ReAct 循环**：Thought→ToolCall→Observation，每步一个 JSON；结论工具 `write_finding` 输出 verdict/evidence/payload/confidence；步数达上限或预算耗尽自动标记 `unverified`
- **工具集**：read_file / search / list_dir / call_chain（Python AST 符号索引）/ route_map / run_semgrep_subset + 动态验证 http_request / sandbox_exec（沙箱存活期间可用）
- **预算与并发**（均可环境变量覆盖）：单条 10 步硬上限、每任务 1.5M token 软上限、Agent 并发 3、沙箱动态验证全局并发 ≤2、候选数上限 20（严重性优先）
- **数据模型**：Vulnerability 新增 agent_status/agent_evidence/agent_confidence/agent_reason/analyzed_at，旧库自动 ALTER TABLE 迁移；报告按 agent_status 分组，标注“Agent 深度验证 / 仅静态疑似”
- **设计文档**：`docs/ARCHITECTURE.md`
- **验收**：工具集冒烟（读文件/搜索/调用链/路由图/局部复扫全部正常）；Mock LLM 端到端（3 步完成 verified 结论，预算耗尽正确 unverified）；真实流水线回归（未配置 LLM 时 Agent 段正确跳过，web 任务 POC 4/4）

## 整改复查记录（四阶段联合复查后修复）

1. **[Bug] 沙箱过早销毁**：原实现 POC 结束即 `handle.cleanup()`，导致 Agent 深度研判的动态验证工具（http_request/sandbox_exec）拿到已销毁容器。已改为 Agent 段结束后统一销毁，并加异常保护
2. **[Bug] exploitability 未落库**：Agent 结论中的可利用性评级原被丢弃，现写入 agent_evidence 前缀 `[exploitability=xxx]`
3. **[Bug] 相对路径依赖**：反编译缓存与官方规则 flag 使用相对 `data/` 路径，工作目录不同时会写到错误位置；已改为 `DATA_DIR` 绝对路径
4. **[Bug] route_map 重复条目**：同文件被多 pattern 重复命中，已去重
5. **[清理] 历史文件归档**：`111.txt` 归档至 `docs/`；历史阶段 zip 包移至 `/workspace/archive/`

## V2 版本（阶段 3.2~3.5：全 Agent 智能审计 + 可用性完善）

### 阶段 3.2 Agent 全量审计（根治静态漏报）

- 新增 `agent_full_audit` 流水线阶段：Agent 不依赖 semgrep 命中行，自主遍历全部源码发现静态规则难以覆盖的漏洞（未授权访问 / 越权 / 逻辑 / 链式漏洞），rule_id 前缀 `agent-discovered-`
- 多轮迭代审计（默认 3 轮，`FULL_AUDIT_ROUNDS` 可调），允许第一轮漏报、后续轮次补全
- 与静态命中按 文件+行号 去重，避免重复消耗 token

### 阶段 3.3 沙箱保留 + 手工验证 + 任务管理

- Web 任务完成后沙箱容器**保留**（`sandbox_cid`/`sandbox_port` 落库），任务详情页可"手动验证"：编辑 payload 一键在沙箱内发请求查看回显；"下载 POC 脚本"导出独立可运行的 Python 脚本
- **停止**任务立即销毁沙箱并终止 Agent；**删除**任务彻底清理漏洞记录/上传/工作区/报告；运行中任务需先停止再删除
- 任务列表按"进行中 / 已完成"分区展示；漏洞类型显示人类易读中文名（SQL 注入 / 远程命令执行 / 未授权访问…），内部规则 ID 悬浮展示

### 阶段 3.4 POC payload 格式规范化 + UI 优化

- POC payload 统一为干净请求包格式：`POST /route?action=xxx` + `注入参数=k`（action 进 query、注入参数进 body），去除用户困惑的 `body:` 前缀；解析器兼容新旧两种形态
- 生成的 Python POC 脚本同步新格式（URL 含 action、data 含注入参数）
- 页面优化：文件选择按钮修复（原生 input 隐藏，仅一个按钮）、主容器加宽、非全居中布局

### 阶段 3.5 落库统一清洗

- 所有 payload 落库前经 `normalize_payload()` 统一规范化，彻底清除 Agent 自由提交的 `body:` 残留
- 清洗 semgrep 官方规则包注入的 "requires login" 页脚（`_clean_text`），报告不再出现该字符串

### 推理模型兼容

- deepseek-reasoner / o3 等推理模型不支持 `temperature` 参数，`_chat` 自动省略，可在配置页直接切换
