# 自定义 Semgrep 规则

把 `.yaml` / `.yml` 文件放进 `data/rules/`。每个新任务扫描时会自动加载，无需重启服务。

## 示例

```yaml
rules:
  - id: my-danger-call
    languages: [python]
    message: "调用了危险函数"
    severity: WARNING
    pattern: dangerous_func(...)
```

## 规则校验

平台在执行扫描前会先运行：

```bash
semgrep scan --validate --config data/rules/my-rule.yaml
```

- 校验失败的文件会被跳过，并把错误写入任务日志
- 有效规则与内置 `app/skills/giants_rules/authz-config.yaml` 一起扫描
- 默认最多 50 个文件；`AUDIT_MAX_CUSTOM_RULES` 可调整

## 结果映射

Semgrep 的 `check_id` 会映射为平台漏洞的 `rule_id=giants:<id>`，然后进入统一的去重、严重性映射、AI 命名（可选）、报告流程。

## 建议

- 规则尽量窄，避免把示例/测试代码全部命中
- 复杂逻辑放在 `message` 与 metadata 中说明，不要把攻击载荷写进规则
- 新增规则先在少量样本上跑通，再放入 `data/rules/`
- 规则目录不应提交真实业务源码或密钥
