# 自定义 Semgrep 规则包

把 `.yaml` / `.yml` 规则文件放到本目录，下一次静态扫描会自动加载（无需重启服务）。
每个文件加载前会执行 `semgrep scan --validate`，无效规则会被跳过并写入任务日志。

示例：

```yaml
rules:
  - id: my-danger-func
    languages: [python]
    message: "调用了危险函数"
    severity: WARNING
    pattern: dangerous_func()
```

规则命中的 `check_id` 会保存为 `giants:<id>`；结果进入既有落库/去重/报告流程。
