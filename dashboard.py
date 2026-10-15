#!/usr/bin/env python3
"""Read-only proxy/server monitor. Run on the server being monitored."""
import base64
import collections
import hmac
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil

HOST = os.getenv("PROXYDASH_HOST", "127.0.0.1")
PORT = int(os.getenv("PROXYDASH_PORT", "18090"))
PORTS = {int(p) for p in os.getenv("PROXYDASH_PROXY_PORTS", "443").split(",")}
PROCESSES = set(os.getenv("PROXYDASH_PROCESSES", "xray,sing-box,v2ray").split(","))
SERVICE = os.getenv("PROXYDASH_SERVICE", "xray")
INTERFACES = set(filter(None, os.getenv("PROXYDASH_INTERFACES", "").split(",")))
INTERVAL = 2


def clean_ip(value):
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        return str(address.ipv4_mapped or address) if address.version == 6 else str(address)
    except ValueError:
        return value


def summarize_connections(connections, proxy_pids, ports):
    clients = collections.Counter()
    destinations = collections.Counter()
    listeners = set()
    for c in connections:
        if c.status == psutil.CONN_LISTEN and c.laddr.port in ports:
            listeners.add(c.laddr.port)
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        if c.laddr.port in ports:
            clients[clean_ip(c.raddr.ip)] += 1
        elif c.pid in proxy_pids:
            destinations[clean_ip(c.raddr.ip)] += 1
    return clients, destinations, sorted(listeners)


def network_rates(previous, current, elapsed):
    if previous is None or elapsed <= 0:
        return None, None
    rx = tx = 0
    for name in current.keys() & previous.keys():
        rx += max(0, current[name].bytes_recv - previous[name].bytes_recv)
        tx += max(0, current[name].bytes_sent - previous[name].bytes_sent)
    return rx / elapsed, tx / elapsed


class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.snapshot = None
        self.history = collections.deque(maxlen=300)
        self.previous_net = None
        self.previous_time = None
        self.first_seen = {}
        self.error = None
        self.stop = threading.Event()

    def collect(self):
        now = time.time()
        monotonic = time.monotonic()
        warnings = []
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        proxy_pids = set()
        for process in psutil.process_iter(["pid", "name"]):
            if process.info["name"] in PROCESSES:
                proxy_pids.add(process.info["pid"])
        clients = destinations = listeners = None
        try:
            connections = psutil.net_connections(kind="tcp")
            clients, destinations, listeners = summarize_connections(connections, proxy_pids, PORTS)
            if platform.system() == "Linux" and os.geteuid() != 0:
                warnings.append("当前非 root 运行，连接及代理进程归属可能不完整。")
        except (psutil.AccessDenied, OSError) as exc:
            warnings.append("无法读取系统连接：需要在目标服务器上以 root 运行。" + type(exc).__name__)

        service_state = "unavailable"
        services = []
        if platform.system() == "Linux":
            for service in SERVICE.split(","):
                try:
                    result = subprocess.run(["systemctl", "is-active", "--", service],
                                            capture_output=True, text=True, timeout=2)
                    state = result.stdout.strip() or "unknown"
                except (OSError, subprocess.TimeoutExpired):
                    state = "unknown"
                    warnings.append("无法查询 systemd 服务状态：" + service)
                services.append({"name": service, "state": state})
            service_state = "active" if all(s["state"] == "active" for s in services) else "inactive"
        else:
            warnings.append("本地预览：显示当前电脑状态；Linux 服务器部署后可读取完整连接。")

        counters = psutil.net_io_counters(pernic=True)
        stats = psutil.net_if_stats()
        names = INTERFACES or {n for n in counters if n in stats and stats[n].isup
                              and not n.startswith(("lo", "docker", "veth", "br-", "utun", "awdl", "llw"))}
        net = {n: counters[n] for n in names if n in counters}
        if not net:
            warnings.append("未找到统计网卡，请设置 PROXYDASH_INTERFACES。")
        if not INTERFACES and len(net) > 1:
            warnings.append("已汇总多个网卡，可能重复计数；建议指定服务器出口网卡。")
        elapsed = monotonic - self.previous_time if self.previous_time is not None else 0
        rx, tx = network_rates(self.previous_net, net, elapsed)
        if not net:
            rx = tx = None
        self.previous_net, self.previous_time = net, monotonic
        devices = None
        if clients is not None:
            self.first_seen = {ip: self.first_seen.get(ip, now) for ip in clients}
            devices = [{"ip": ip, "connections": count, "since": self.first_seen[ip]}
                       for ip, count in clients.most_common()]
        data = {
            "ts": now, "hostname": socket.gethostname(), "platform": platform.system(),
            "uptime": max(0, now - psutil.boot_time()), "cpu": psutil.cpu_percent(),
            "cores": psutil.cpu_count(), "load": list(os.getloadavg()),
            "memory": {"total": memory.total, "used": memory.total - memory.available, "percent": memory.percent},
            "disk": {"total": disk.total, "used": disk.used, "percent": disk.percent},
            "network": {"rx": rx, "tx": tx, "received": sum(c.bytes_recv for c in net.values()),
                        "sent": sum(c.bytes_sent for c in net.values()), "interfaces": sorted(net)},
            "proxy": {"service": SERVICE, "state": service_state, "process_count": len(proxy_pids),
                      "ports": sorted(PORTS), "listening_ports": listeners, "services": services},
            "device_count": len(clients) if clients is not None else None,
            "connections": sum(clients.values()) if clients is not None else None,
            "upstream_connections": sum(destinations.values()) if destinations is not None else None,
            "devices": devices, "destinations": [{"ip": ip, "connections": n}
                          for ip, n in destinations.most_common(12)] if destinations is not None else None,
            "warnings": warnings,
        }
        with self.lock:
            self.history.append({"ts": now, "rx": rx, "tx": tx, "cpu": data["cpu"], "devices": data["device_count"]})
            self.snapshot = data
            self.error = None

    def run(self):
        psutil.cpu_percent()
        while not self.stop.wait(INTERVAL):
            try:
                self.collect()
            except Exception as exc:
                with self.lock:
                    self.error = type(exc).__name__ + ": " + str(exc)

    def get(self):
        with self.lock:
            if self.snapshot is None:
                return {"error": self.error or "正在采样"}, 503
            data = dict(self.snapshot)
            data["history"] = list(self.history)
            data["sample_error"] = self.error
            data["stale"] = time.time() - data["ts"] > INTERVAL * 3
            return data, 200


def make_handler(monitor, username, password):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if password:
                expected = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied.encode(), expected.encode()):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="ProxyDash", charset="UTF-8"')
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    return
            route = self.path.split("?", 1)[0]
            if route == "/api":
                data, status = monitor.get()
                body, content_type = json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8"
            elif route in ("/", "/index.html"):
                status = 200
                body = Path(__file__).with_name("index.html").read_bytes()
                content_type = "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
    return Handler


def main():
    password = os.getenv("PROXYDASH_PASSWORD", "")
    if HOST not in ("127.0.0.1", "localhost", "::1") and not password:
        raise SystemExit("非本机监听必须设置 PROXYDASH_PASSWORD。")
    monitor = Monitor()
    threading.Thread(target=monitor.run, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), make_handler(monitor, os.getenv("PROXYDASH_USER", "admin"), password))
    print(f"ProxyDash: http://{HOST}:{PORT} (ports: {sorted(PORTS)})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
