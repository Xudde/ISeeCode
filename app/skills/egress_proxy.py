#!/usr/bin/env python3
"""阶段 7 v6：沙箱依赖阶段的最小 egress 代理。
只允许 HTTP/HTTPS 到包管理器/代码托管白名单域名，拒绝其他目标和私网 IP。
沙箱只连 internal 网络，代理双网卡（internal + egress），不发布宿主端口。"""
import ipaddress
import os
import select
import socket
import socketserver
import sys
import urllib.parse

DEFAULT_ALLOW = (
    "pypi.org,pythonhosted.org,pypi.python.org,"
    "registry.npmjs.org,registry.yarnpkg.com,npmjs.org,npmjs.com,"
    "repo.maven.apache.org,maven.apache.org,repo1.maven.org,maven.org,"
    "plugins.gradle.org,proxy.golang.org,sum.golang.org,storage.googleapis.com,"
    "goproxy.io,goproxy.cn,mirrors.aliyun.com,"
    "github.com,githubusercontent.com,githubassets.com"
)
_BASE = os.environ.get("AUDIT_EGRESS_ALLOW") or DEFAULT_ALLOW
_EXTRA = os.environ.get("AUDIT_EGRESS_ALLOW_EXTRA", "")
ALLOW = tuple(dict.fromkeys(
    x.strip().lower() for x in (_BASE + "," + _EXTRA).split(",") if x.strip()))
PORT = int(os.environ.get("AUDIT_EGRESS_PORT", "3128"))


def _allowed(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOW)


def _resolve_public(host: str, port: int):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    v4, v6 = [], []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    return v4 + v6


class Handler(socketserver.BaseRequestHandler):
    def _deny(self, code: int = 403, reason: str = "Forbidden") -> None:
        body = b"blocked by ISeeCode egress allowlist\n"
        self.request.sendall(
            f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)

    def _connect(self, host: str, port: int):
        if not _allowed(host) or port not in (80, 443):
            print(f"[proxy] DENY {host}:{port}", flush=True)
            return None
        ips = _resolve_public(host, port)
        if not ips:
            print(f"[proxy] DENY private/unresolved {host}:{port}", flush=True)
            return None
        last = None
        for ip in ips:
            try:
                return socket.create_connection((ip, port), timeout=15)
            except OSError as e:
                last = e
        print(f"[proxy] FAIL {host}:{port} {last}", flush=True)
        return None

    def _relay(self, upstream) -> None:
        peers = [self.request, upstream]
        while True:
            try:
                ready, _, _ = select.select(peers, [], [], 60)
            except OSError:
                return
            if not ready:
                return
            for src in ready:
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                dst = upstream if src is self.request else self.request
                try:
                    dst.sendall(data)
                except OSError:
                    return

    def handle(self) -> None:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        if not data:
            return
        head, sep, rest = data.partition(b"\r\n\r\n")
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, _, port_s = target.rpartition(":")
            if not host:
                host, port_s = target, "443"
            try:
                port = int(port_s)
            except ValueError:
                return
            upstream = self._connect(host.strip("[]"), port)
            if upstream is None:
                self._deny(); return
            print(f"[proxy] ALLOW CONNECT {host}:{port}", flush=True)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay(upstream)
            upstream.close()
            return
        if method == "GET" and target.startswith("http://"):
            u = urllib.parse.urlsplit(target)
            host = u.hostname or ""
            port = u.port or 80
            upstream = self._connect(host, port)
            if upstream is None:
                self._deny(); return
            print(f"[proxy] ALLOW HTTP {host}:{port}", flush=True)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            headers = [h for h in head.split(b"\r\n")[1:]
                       if not h.lower().startswith(b"proxy-connection:")]
            req = f"{method} {path} HTTP/1.1\r\n".encode() + b"\r\n".join(headers) + b"\r\n\r\n" + rest
            upstream.sendall(req)
            self._relay(upstream)
            upstream.close()
            return
        print(f"[proxy] DENY {method} {target[:120]}", flush=True)
        self._deny()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"[proxy] listening :{PORT}; allow={','.join(ALLOW)}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
