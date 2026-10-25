# 源码自动化审计平台

上传项目源码 → 自动化代码审计（semgrep）→ LLM 误报研判 → Docker 沙箱自动部署 → POC 自动验证 → 生成 Markdown 审计报告。

> 当前进度：**阶段 0（项目骨架）已完成**。上传/扫描/沙箱/POC 功能将在后续阶段实现。

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
- `templates/` Jinja2 页面
- `static/` 静态资源
- `semgrep_rules/` 内置扫描规则（阶段 1 填充）
- `docker_templates/` 沙箱镜像模板（阶段 2 填充）
- `data/` 运行时数据（uploads / workspaces / reports，已加入 .gitignore）

## API 一览

| 方法 | 路径 | 功能 |
|---|---|---|
| POST | /api/tasks | 上传 zip 创建任务（阶段 1 实现） |
| GET | /api/tasks | 任务列表 |
| GET | /api/tasks/{id} | 任务详情 |
| GET | /api/tasks/{id}/report | 下载 Markdown 报告（阶段 1 实现） |
| GET | /api/config | 获取配置（api_key 脱敏为 sk-***xxxx） |
| POST | /api/config | 更新 LLM 配置 |


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


## 升级改造（2026-10-25 大版本：报告双版本 + AI 命名/复现条件 + A/B/C 级修复）

### 报告双版本
- **人看版**：自包含 HTML（主）+ Markdown（存档），面向审计人员
- **AI 版**：`task_{id}_report.json`（schema `source-audit-report/1.0`），结构化 task/summary/findings，附 `caveats` 数组显式说明「POC 未动态验证」「N 条未研判」等限定条件，供下游 AI/工单系统消费
- 下载：`GET /api/tasks/{id}/report`（html）/ `?format=md` / `?format=json`

### AI 漏洞命名与复现条件
- 报告生成前自动批量（20 条/批）为漏洞生成**中文漏洞名**（如「SQL注入（订单号拼接查询）」）与**复现条件**（如「需登录学生账号」「匿名可达，需有效订单号」）
- 落库字段 `title` / `precondition`；前端漏洞表、三种报告均优先展示；Agent 研判结论（write_finding.precondition）优先于批量生成

### UI 2.x
- 深浅双主题（白天蓝白 / 夜间黑灰，侧边栏切换按钮，记忆+跟随系统）；左侧导航布局
- 任务列表/详情 SPA 式免刷新轮询；实时日志终端（时间戳着色/自动滚动/一键复制）；漏洞多维筛选（结论/等级/搜索）；拖拽上传+进度条
- 自托管 Lato / Fira Code 字体，内网零外部 CDN 依赖

### 稳定性修复（A 级，均经真实任务回归）
1. **反编译缓存 v2**：修复「共享输出目录被后处理二进制 rmtree 冲掉」的严重 bug（曾致 ASP.NET 发布包任务丢失全部控制器/鉴权源码，Agent 只能瞎猜路由与登录要求）；现在每个二进制私有临时目录 → 只缓存自身产物 → 合并进共享目录；v1 污染缓存自动失效
2. **续跑去重**：重扫按 `(file_path, line, rule_id)` 复用已有漏洞记录，已研判条目不重复分析、不重复消耗 token；修复续跑预处理 `Is a directory` 崩溃（解压源改用 upload_path）
3. **停止生效**：修复 worker 读取 ORM 缓存导致 API 写入的停止请求不可见的问题（db.refresh）
4. **多栈沙箱**：tech_stack 逗号串按序逐栈尝试部署，多栈任务恢复 POC 与动态验证
5. **tokens_used 落库**：Agent 研判与全量审计两阶段累计写入任务表

### 修复（B 级）
- http_request 工具：method 真正透传（原 POST 静默变 GET）、params/body 正确解析与 URL 编码
- 全局沙箱并发闸唯一定义（原先两把信号量上限翻倍）
- 删除任务仅限终态（封死「删除运行中任务 + rowid 复用 → 双跑」竞态）
- token 估算 CJK 感知（中文 0.7 token/字）；POC 脚本 GET 参数 URL 编码；官方规则探测超时 90s→20s

### 修复（C 级）与安全
- **AUTH_TOKEN 默认启用**（start.sh 内置，浏览器访问 `http://<host>:8000/login?token=<AUTH_TOKEN>` 一次即写入 cookie；API 可带 `Authorization: Bearer <token>`）。修改 token 编辑 start.sh 后重启
- 上传改流式落盘 + 增量哈希（不再整包进内存）；沙箱 exec 参数改 argv 传递（防特殊字符破坏脚本）；call_chain 过滤语言关键字噪音；移除未使用的 paramiko 依赖与空 semgrep_rules 目录；auth.py 登录死代码清理
- 已知残留：LLM API Key 明文存于 SQLite（data/app.db），请确保平台仅部署于可信内网并保管服务器权限


### 登录方式（2026-10-25 更新）
- 浏览器访问 `http://<host>:8000/login`，使用账号密码登录（默认 `Xudde / 123456`，可在 `start.sh` 修改 `AUTH_USER/AUTH_PASS`）
- 脚本/API 二选一：请求头 `Authorization: Bearer <AUTH_TOKEN>`，或 `GET /login?token=<AUTH_TOKEN>` 写 cookie
- 登录失败有 1.2s 延时与日志记录；会话过期后页面自动跳回登录页
