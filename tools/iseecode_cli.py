#!/usr/bin/env python3
"""ISeeCode 命令行客户端（阶段 7 v3）。
用法：ISEECODE_TOKEN=... python tools/iseecode_cli.py list
全部接口走 Bearer Token；不保存密码。"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

if os.name == "nt" and os.environ.get("MSYSTEM"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

FINAL = {"completed", "failed", "skipped", "cancelled"}


class ApiError(Exception):
    def __init__(self, status: int, detail):
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


class Api:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base = (base_url or "").rstrip("/")
        self.token = token or ""
        self.timeout = timeout

    def request(self, method: str, path: str, data: bytes | None = None,
                headers: dict | None = None, timeout: int | None = None,
                raw: bool = False):
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                body = r.read()
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                detail = json.loads(body.decode("utf-8", "replace")).get("detail", body)
            except Exception:
                detail = body.decode("utf-8", "replace")[:500]
            raise ApiError(e.code, detail)
        except urllib.error.URLError as e:
            raise ApiError(0, f"Connection failed: {e.reason}")
        if raw:
            return body
        if not body:
            return {}
        return json.loads(body.decode("utf-8", "replace"))

    def get(self, path: str, **kw):
        return self.request("GET", path, **kw)

    def upload(self, path: Path, audit_mode: str) -> dict:
        boundary = "----iseecode" + uuid.uuid4().hex
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.name) or "upload.zip"
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"audit_mode\"\r\n\r\n"
            f"{audit_mode}\r\n".encode(),
            (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
             f"filename=\"{safe}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode(),
            path.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        body = b"".join(parts)
        return self.request(
            "POST", "/api/tasks/upload", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=max(self.timeout, 300),
        )


def _print_json(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _table(rows: list[dict], cols: list[tuple[str, str]]) -> None:
    if not rows:
        print("(empty)")
        return
    print("\t".join(label for _, label in cols))
    for r in rows:
        print("\t".join(str(r.get(key, "") or "") for key, _ in cols))


def cmd_list(api: Api, args) -> int:
    rows = api.get("/api/tasks")
    if args.status:
        rows = [r for r in rows if r.get("status") == args.status]
    if args.mode:
        rows = [r for r in rows if r.get("audit_mode") == args.mode]
    rows = rows[:max(1, args.limit)]
    if args.json:
        _print_json(rows)
    else:
        _table(rows, [("id", "ID"), ("status", "STATUS"), ("audit_mode", "MODE"),
                      ("project_type", "TYPE"), ("tokens_used", "TOKENS"),
                      ("filename", "FILE"), ("created_at", "CREATED")])
    return 0


def _status_line(t: dict) -> str:
    return (f"#{t.get('id')} {t.get('status')} mode={t.get('audit_mode')} "
            f"tokens={t.get('tokens_used', 0)} {t.get('filename', '')}")


def cmd_status(api: Api, args) -> int:
    t = api.get(f"/api/tasks/{args.task_id}")
    if args.json:
        _print_json(t)
        return 0
    for key in ("id", "filename", "status", "project_type", "tech_stack",
                "audit_mode", "tokens_used", "error_msg", "sandbox_cid",
                "sandbox_port", "created_at", "updated_at"):
        print(f"{key:16} {t.get(key, '')}")
    if args.log:
        lines = str(t.get("log") or "").splitlines()
        print("\nLog (last %d lines):" % max(1, args.log))
        print("\n".join(lines[-max(1, args.log):]))
    return 0


def cmd_wait(api: Api, args) -> int:
    deadline = time.time() + max(1, args.timeout)
    last = None
    while True:
        t = api.get(f"/api/tasks/{args.task_id}")
        status = str(t.get("status") or "")
        if status != last:
            print(_status_line(t), flush=True)
            last = status
        if status in FINAL:
            return 0 if status == "completed" else 1
        if time.time() >= deadline:
            print(f"Timeout after {args.timeout}s; task is still {status}", file=sys.stderr)
            return 2
        time.sleep(max(1, args.interval))


def cmd_submit(api: Api, args) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 2
    try:
        t = api.upload(path, args.mode)
    except ApiError as e:
        if e.status == 409:
            print(f"Duplicate file: {e.detail}", file=sys.stderr)
        else:
            raise
        return 3
    print(_status_line(t))
    if args.wait:
        args.task_id = int(t["id"])
        args.timeout = args.wait_timeout
        args.interval = args.interval
        return cmd_wait(api, args)
    return 0


def cmd_report(api: Api, args) -> int:
    fmt = args.format
    body = api.get(f"/api/tasks/{args.task_id}/report?format={fmt}", raw=True)
    out = Path(args.out) if args.out else Path(f"task_{args.task_id}.{fmt}")
    out.write_bytes(body)
    print(f"Saved {out} ({len(body)} bytes)")
    return 0


def cmd_vulns(api: Api, args) -> int:
    rows = api.get(f"/api/tasks/{args.task_id}/vulns")
    if args.verified:
        rows = [v for v in rows if v.get("poc_verified")
                or v.get("agent_status") == "verified" or v.get("llm_is_real") is True]
    rows = rows[:max(1, args.limit)]
    if args.json:
        _print_json(rows)
        return 0
    out = []
    for v in rows:
        verdict = "verified" if (v.get("poc_verified") or v.get("agent_status") == "verified"
                                 or v.get("llm_is_real") is True) else (
            "fp" if (v.get("agent_status") == "false_positive" or v.get("llm_is_real") is False)
            else "-")
        out.append({
            "id": v.get("id"), "severity": v.get("severity"),
            "verdict": verdict, "source": v.get("source"),
            "loc": f"{v.get('file_path', '')}:{v.get('line', 0)}",
            "title": v.get("title") or v.get("rule_id"),
        })
    _table(out, [("id", "ID"), ("severity", "SEVERITY"), ("verdict", "VERDICT"),
                 ("source", "SOURCE"), ("loc", "LOCATION"), ("title", "TITLE")])
    return 0


def cmd_audit(api: Api, args) -> int:
    if args.summary:
        d = api.get(f"/api/audit/summary?hours={args.hours}")
        _print_json(d)
        return 0
    q = [f"limit={max(1, args.limit)}"]
    if args.action:
        q.append("action=" + urllib.parse.quote(args.action))
    if args.target:
        q.append("target=" + urllib.parse.quote(args.target))
    d = api.get("/api/audit/events?" + "&".join(q))
    _print_json(d)
    return 0


def cmd_stats(api: Api, args) -> int:
    _print_json(api.get("/api/tasks/stats"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=argparse.SUPPRESS)
    common.add_argument("--token", default=argparse.SUPPRESS)
    common.add_argument("--token-file", default=argparse.SUPPRESS)

    p = argparse.ArgumentParser(description="ISeeCode CLI")
    p.add_argument("--url", default=os.environ.get("ISEECODE_URL", "http://127.0.0.1:8000"),
                   help="platform URL (default $ISEECODE_URL or http://127.0.0.1:8000)")
    p.add_argument("--token", default=os.environ.get("ISEECODE_TOKEN", ""),
                   help="Bearer token (default $ISEECODE_TOKEN)")
    p.add_argument("--token-file", default="", help="read token from a file")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", parents=[common], help="list tasks")
    s.add_argument("--status", default="")
    s.add_argument("--mode", default="", choices=["", "full", "static", "poc"])
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("status", parents=[common], help="task detail")
    s.add_argument("task_id", type=int)
    s.add_argument("--log", type=int, default=0, help="include last N log lines")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("wait", parents=[common], help="wait until a task reaches a final state")
    s.add_argument("task_id", type=int)
    s.add_argument("--interval", type=int, default=10)
    s.add_argument("--timeout", type=int, default=7200)
    s.set_defaults(func=cmd_wait)

    s = sub.add_parser("submit", parents=[common], help="upload a source archive and create a task")
    s.add_argument("file")
    s.add_argument("--mode", default="full", choices=["full", "static", "poc"])
    s.add_argument("--wait", action="store_true")
    s.add_argument("--interval", type=int, default=10)
    s.add_argument("--wait-timeout", type=int, default=7200)
    s.set_defaults(func=cmd_submit)

    s = sub.add_parser("report", parents=[common], help="download a report")
    s.add_argument("task_id", type=int)
    s.add_argument("--format", default="html", choices=["html", "md", "json"])
    s.add_argument("--out", default="")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("vulns", parents=[common], help="list task vulnerabilities")
    s.add_argument("task_id", type=int)
    s.add_argument("--verified", action="store_true")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_vulns)

    s = sub.add_parser("audit", parents=[common], help="audit events")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--action", default="")
    s.add_argument("--target", default="")
    s.add_argument("--summary", action="store_true")
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("stats", parents=[common], help="overview stats")
    s.set_defaults(func=cmd_stats)
    return p


def main() -> int:
    args = build_parser().parse_args()
    token = args.token
    if not token and args.token_file:
        try:
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"Failed to read token file: {e}", file=sys.stderr)
            return 2
    api = Api(args.url, token)
    try:
        return args.func(api, args)
    except ApiError as e:
        print(f"Request failed (HTTP {e.status}): {e.detail}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
