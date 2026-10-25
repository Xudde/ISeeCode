# 架构文档（升级阶段 3：Agent 审计引擎）

## 总体数据流

```
上传(zip/apk/image/反编译文件)
  → 预筛层（快、便宜，保留原有实现）
      preprocess → tech_detect(多栈) → semgrep 多语言规则 + 官方规则集
      → 候选漏洞落库（Vulnerability 表）
  → POC 层（web 项目）：Docker 沙箱禁网部署 + 容器内动态验证
  → 深度研判层（新增 Agent 引擎，需配置 LLM）
      Orchestrator：按严重性挑选候选（≤ AGENT_MAX_VULNS 条）
        → 线程池并发（AGENT_CONCURRENCY=3）执行 ReAct Agent
        → 结论写回 agent_status/agent_evidence/agent_confidence/agent_reason/analyzed_at
  → 报告：按 agent_status 分组（深度验证/误报/未定）+ LLM 研判 + POC 结果
```

## Agent 引擎设计

### ReAct 循环（app/agent/react.py）
- 每步输出一个 JSON：`{"thought", "tool", "args"}`；执行工具获得 Observation 追加对话
- 终止条件：调用 `write_finding`、步数达 `AGENT_MAX_STEPS`（默认 10）、token 预算耗尽
- 达限未结论 → `unverified`，禁止编造
- 上下文管理：超过 18 条消息裁剪为 system+首条 user+最近 16 条

### 工具集（app/agent/tools.py，10 个）
静态：`read_file`（带行号、路径越界防护、单次≤200行）、`search`（正则+glob、上限 50 命中）、
`list_dir`（跳过 node_modules/vendor 等）、`call_chain`（Python AST 符号索引，其他语言正则兜底）、
`route_map`（框架路由提取）、`run_semgrep_subset`（单文件局部复扫）
动态（需沙箱）：`http_request`（容器内请求）、`sandbox_exec`（容器内命令）
产出：`write_finding`（最终结论）、`finalize`（由 write_finding 承担，循环即结束）

### 预算与并发（app/config.py 环境变量可调）
| 参数 | 默认 | 说明 |
| --- | --- | --- |
| AGENT_MAX_STEPS | 10 | 单条漏洞 Agent 步数硬上限 |
| AGENT_TOKEN_BUDGET | 1,500,000 | 每任务 token 软上限（估算 len/3），超限停止新开 Agent、已有 Agent 收尾 |
| AGENT_CONCURRENCY | 3 | Agent 分析线程池并发 |
| SANDBOX_CONCURRENCY | 2 | 沙箱动态验证全局信号量（http_request/sandbox_exec 共用） |
| AGENT_MAX_VULNS | 20 | 单任务深度研判候选上限（ERROR/WARNING 优先） |

### 数据模型扩展（Vulnerability，兼容旧库自动 ALTER TABLE 迁移）
`agent_status`(verified/false_positive/unverified/error)、`agent_evidence`（证据链：source→中间处理→sink→动态结果）、
`agent_confidence`、`agent_reason`、`analyzed_at`。报告按 agent_status 分组并标注“Agent 深度验证 / 仅静态疑似”。

## 安全红线
- Agent 仅能访问任务 workspace 内路径（`_safe_path` 越界防护）
- 动态验证仅面向禁网沙箱容器；`http_request` 走容器内部请求，禁止外网
- 全部工具调用有 try/except，异常不中断任务；Agent 段失败不影响报告生成
- LLM 请求只发往平台配置的 base_url，token 记账全局锁内累计
