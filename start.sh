#!/bin/bash
# 平台启动脚本：AUTH_TOKEN 启用后所有页面/接口需登录
# 浏览器：http://<host>:8000/login 账号密码登录（AUTH_USER / AUTH_PASS）
# 脚本/API：请求头 Authorization: Bearer <AUTH_TOKEN>
export AUTH_TOKEN="${AUTH_TOKEN:-Audit-r9wtmwdcpf}"
export AUTH_USER="${AUTH_USER:-Xudde}"
export AUTH_PASS="${AUTH_PASS:-123456}"
cd /opt/source-audit-platform
source .venv/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > uvicorn.log 2>&1 < /dev/null &
echo "PID=$!"
