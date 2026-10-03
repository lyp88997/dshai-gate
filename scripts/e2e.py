#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dshai-gate 端到端测试台（入库版）。

历史教训：早期测试台写在 /tmp，容器一重启就没了、也没入库，永远无法复跑。
本文件必须随仓库提交。覆盖：
  1. 五项 1.8.0 新功能——历史日志落盘、健康巡检（DSH 就绪/不可达/重启）、
     后台体检页、插件操作转发（第二层）、踢光设备（会话代数）；
  2. 既有回归——未登录 401、口令登录、401 换登录页、回环身份改写、
     点段不给回环、XFF 追加与 restart 剥离、市场 20 写路由第二层、
     市场读路由不进第二层、101 升级直通。

用法（在仓库根目录）：
    python3 scripts/e2e.py
环境变量：GATE_E2E_GO 指定 go 可执行文件；GOCACHE 建议指向可写目录。
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "e2e-session-secret-0123456789"
PASSWORD = "e2e-pass-86"
PW_HASH = hashlib.sha256(("dshai-gate-v1:" + PASSWORD).encode()).hexdigest()
HOST_NAME = "gate.test"  # 模拟 nginx 传进来的域名 Host

results = []


def check(name, cond, detail=""):
    mark = "✔" if cond else "✘"
    results.append(bool(cond))
    line = f"  {mark} {name}"
    if not cond and detail:
        line += f" —— {detail}"
    print(line, flush=True)
    return bool(cond)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------- 桩上游 ----------------

class StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # 静音
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body: bytes):
        rec = {
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "xff": self.headers.get("X-Forwarded-For", ""),
            "cookie": self.headers.get("Cookie", ""),
            "body": body.decode("utf-8", "replace"),
        }
        with STUB_LOCK:
            STUB_POSTS.append(rec)

    def do_GET(self):
        sp = urlsplit(self.path)
        if sp.path == "/":
            if "token=" in (sp.query or ""):  # dshPair 换票
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", "dsh-auth-e2e=1; Path=/; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if "dsh-auth-e2e" in (self.headers.get("Cookie") or ""):
                self._text(200, "dsh ok")
            else:
                self._text(401, "no dsh session")
            return
        if sp.path == "/auth-required":  # 触发门禁 401 换登录页
            body = b"<html><body>upstream-401-page</body></html>"
            self.send_response(401)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("WWW-Authenticate", "Basic realm=x")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.headers.get("Upgrade"):  # 101 升级 + echo
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            try:
                self.connection.settimeout(8)
                while True:
                    line = self.rfile.readline()
                    if not line:
                        break
                    self.wfile.write(line)
                    self.wfile.flush()
                    if len(line) > 8192:
                        break
            except Exception:
                pass
            return
        # 其余一律回显「上游看到的事实」：Host 有没有被改成回环、XFF 长什么样
        self._json(200, {
            "path": sp.path,
            "host": self.headers.get("Host", ""),
            "xff": self.headers.get("X-Forwarded-For", ""),
            "loopback": (self.headers.get("Host") or "").startswith(("127.0.0.1", "localhost")),
        })

    def do_POST(self):
        body = self._read_body()
        self._record(body)
        self._json(200, {"path": urlsplit(self.path).path, "ok": True,
                         "host": self.headers.get("Host", "")})

    def _text(self, code, s):
        data = s.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


STUB_POSTS = []
STUB_LOCK = threading.Lock()


class Stub:
    def __init__(self, port):
        self.port = port
        self.server = None
        self.thread = None
        self.start()

    def start(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), StubHandler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):  # 模拟 DSH 宕机：端口不再监听
        self.server.shutdown()
        self.server.server_close()


# ---------------- HTTP 辅助（不自动跟随重定向，可自定义 Host） ----------------

def call(method, path, cookie="", body=None, headers=None, host=HOST_NAME, timeout=10):
    h = {"Host": host}
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    conn = http.client.HTTPConnection("127.0.0.1", GATE_PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        # 重复头（多个 Set-Cookie）用 \n 拼起来，dict 化只留一个会丢 Cookie
        hd = {}
        for k, v in r.getheaders():
            hd[k] = hd[k] + "\n" + v if k in hd else v
        return r.status, hd, data
    finally:
        conn.close()


def extract_cookie(headers, name):
    for raw in headers.get("Set-Cookie", "").split("\n"):
        raw = raw.strip()
        if raw.startswith(name + "="):
            return name + "=" + raw.split(";", 1)[0].split("=", 1)[1]
    return None


def poll(desc, fn, timeout=8, interval=0.3):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def hist_kinds():
    try:
        with open(HIST_PATH, encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


# ---------------- 主流程 ----------------

def find_go():
    cands = [os.environ.get("GATE_E2E_GO", ""), shutil.which("go") or "",
             "/usr/local/go/bin/go", "/tmp/dshai-work/go/bin/go"]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def build_gate(workdir):
    go = find_go()
    if not go:
        print("找不到 go 编译器（设置 GATE_E2E_GO 指向它）", file=sys.stderr)
        sys.exit(2)
    out = os.path.join(workdir, "e2e-gate")
    env = dict(os.environ)
    cmd = [go, "build", "-o", out, "main.go"]
    r = subprocess.run(cmd, cwd=os.path.join(REPO, "gate"), env=env,
                       capture_output=True, text=True)
    if r.returncode != 0 and "permission denied" in (r.stderr or ""):
        env["GOCACHE"] = os.path.join(workdir, "gocache")  # 默认缓存目录不可写时降级
        r = subprocess.run(cmd, cwd=os.path.join(REPO, "gate"), env=env,
                           capture_output=True, text=True)
    if r.returncode != 0:
        print("编译失败：\n" + r.stderr, file=sys.stderr)
        sys.exit(2)
    return out


def main():
    global GATE_PORT, HIST_PATH
    workdir = tempfile.mkdtemp(prefix="gate-e2e-")
    GATE_PORT = free_port()
    stub_port = free_port()
    HIST_PATH = os.path.join(workdir, "log.jsonl")
    stub = Stub(stub_port)
    binary = build_gate(workdir)

    env = dict(os.environ)
    env.update({
        "GATE_LISTEN": f"127.0.0.1:{GATE_PORT}",
        "GATE_UPSTREAM": f"http://127.0.0.1:{stub_port}",
        "GATE_INJECT": "1",
        "GATE_SITE_TITLE": "E2E",
        "GATE_PASSWORD_HASH": PW_HASH,
        "GATE_SESSION_SECRET": SECRET,
        "GATE_STATE": os.path.join(workdir, "state.json"),
        "GATE_LOG": HIST_PATH,
        "GATE_HEALTH_INTERVAL": "1",
    })
    glog = open(os.path.join(workdir, "gate.log"), "wb")
    gate = subprocess.Popen([binary], env=env, stdout=glog, stderr=subprocess.STDOUT)

    def wait_listen():
        """等门禁真正能应答；进程早夭或 8 秒没起来都算失败。"""
        end = time.time() + 8
        while time.time() < end:
            if gate.poll() is not None:
                raise RuntimeError(f"门禁进程提前退出 code={gate.returncode}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", GATE_PORT, timeout=2)
                c.request("GET", "/__gate/login")
                r = c.getresponse()
                r.read()
                c.close()
                return
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        raise RuntimeError("门禁 8 秒内没起来")

    try:
        wait_listen()

        print("== 1.8.0 e2e 测试台 ==")
        # ---- 未登录 ----
        st, _, _ = call("GET", "/")
        check("未登录导航 → 401", st == 401, f"实际 {st}")

        # ---- 口令 + 启动令牌登录 ----
        from urllib.parse import urlencode
        form = urlencode({"password": PASSWORD, "dstoken": "e2e-token"})
        st, hdr, _ = call("POST", "/__gate/login", body=form,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        c1 = extract_cookie(hdr, "dshai_gate")
        check("登录 → 303", st == 303, f"实际 {st}")
        check("登录下发门禁 Cookie", c1 is not None, hdr.get("Set-Cookie", ""))
        if c1:
            check("旧代 Cookie 是三段式（v1.exp.sig）", len(c1.split(".")[-2:]) == 2 and c1.count(".") == 2,
                  c1)

        dshc = "dsh-auth-e2e=1"  # 浏览器携带的 DSH 会话
        both = "; ".join(x for x in [c1, dshc] if x)

        # ---- 401 换登录页（有门禁会话、无 DSH 会话） ----
        st, hdr, body = call("GET", "/auth-required", cookie=c1 or "",
                             headers={"Accept": "text/html"})
        page = body.decode("utf-8", "replace")
        check("上游 401 → 就地换登录页", st == 401 and 'name="dstoken"' in page,
              f"status={st}")
        check("换页时剥掉 WWW-Authenticate", "WWW-Authenticate" not in hdr,
              str(hdr.get("WWW-Authenticate")))

        # ---- 回环身份：白名单改写 / 非白名单保留 ----
        st, _, body = call("GET", "/api/task-board/list", cookie=both)
        d = json.loads(body)
        check("白名单前缀 → 上游看到回环 Host", d.get("loopback") is True, str(d))
        st, _, body = call("GET", "/api/other/x", cookie=both)
        d = json.loads(body)
        check("非白名单 → Host 保留域名", d.get("host") == HOST_NAME, str(d))

        # ---- 点段不给回环 ----
        st, hdr, body = call("GET", "/api/task-board/../../../etc/passwd", cookie=both)
        if st in (301, 308):
            loc = hdr.get("Location", "/")
            st, hdr, body = call("GET", loc, cookie=both)
        d = json.loads(body) if body[:1] == b"{" else {}
        check("点段路径不给回环身份", d.get("host") == HOST_NAME and d.get("loopback") is False,
              str(d))

        # ---- dsh-ssh 第二层 ----
        st, _, body = call("GET", "/api/dsh-ssh/list", cookie=c1 or "")
        check("dsh-ssh 缺 DSH 会话 → 403", st == 403 and "DSH 会话" in body.decode("utf-8", "replace"),
              f"status={st}")
        st, _, body = call("GET", "/api/dsh-ssh/list", cookie=both)
        check("dsh-ssh 带 DSH 会话 → 放行且回环", st == 200 and json.loads(body).get("loopback") is True,
              f"status={st} {body[:120]}")

        # ---- 市场写路由第二层 + 身份改写 + XFF ----
        tform = urlencode({"name": "foo", "enabled": "1"})
        targs = {"body": tform, "headers": {"Content-Type": "application/x-www-form-urlencoded",
                                            "X-Forwarded-For": "9.9.9.9"}}
        st, _, body = call("POST", "/dsh-market/toggle", cookie=c1 or "", **targs)
        check("市场写路由缺 DSH 会话 → 403", st == 403 and "DSH 会话" in body.decode("utf-8", "replace"),
              f"status={st}")
        st, _, body = call("POST", "/dsh-market/toggle", cookie=both, **targs)
        check("市场写路由带 DSH 会话 → 放行", st == 200, f"status={st} {body[:120]}")
        with STUB_LOCK:
            last = STUB_POSTS[-1] if STUB_POSTS else {}
        check("写路由上游 Host 改回环", last.get("host", "").startswith("127.0.0.1"), str(last.get("host")))
        # Go 反代 Rewrite 模式会先抹掉入站 XFF（reverseproxy.go:422，防伪造），
        # 再由 SetXForwarded 统一写成门禁自己的回环地址：上游看不到客户端痕迹。
        check("XFF 被门禁改写为自身回环（客户端伪造痕迹不透传）",
              last.get("xff") == "127.0.0.1", last.get("xff", ""))

        # ---- 市场读路由不进第二层、不改写 ----
        st, _, body = call("GET", "/dsh-market/installed", cookie=c1 or "")
        d = json.loads(body)
        check("市场读路由缺 DSH 会话照样通（只读不拦）", st == 200 and d.get("path") == "/dsh-market/installed",
              f"status={st}")
        check("市场读路由 Host 不改写", d.get("host") == HOST_NAME, str(d.get("host")))

        # ---- restart 剥 XFF（连门禁自己补的都擦掉，市场按「无转发头=本机直连」放行）----
        st, _, _ = call("POST", "/dsh-market/restart", cookie=both,
                        headers={"Content-Type": "application/json", "X-Forwarded-For": "9.9.9.9"},
                        body="{}")
        with STUB_LOCK:
            last = STUB_POSTS[-1] if STUB_POSTS else {}
        check("restart 转发前剥掉全部转发头",
              st == 200 and last.get("xff", "") == "" and "9.9.9.9" not in str(last),
              repr(last.get("xff")))

        # ---- 101 直通（裸 socket，避免 http.client 解升级流） ----
        try:
            s = socket.create_connection(("127.0.0.1", GATE_PORT), timeout=5)
            s.sendall((f"GET /ws HTTP/1.1\r\nHost: {HOST_NAME}\r\nCookie: {both}\r\n"
                       "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = s.recv(4096)
                if not chunk:
                    break
                head += chunk
            ok101 = head.startswith(b"HTTP/1.1 101")
            s.sendall(b"ping-e2e\n")
            s.settimeout(5)
            echo = s.recv(1024)
            s.close()
        except Exception as e:  # noqa: BLE001
            ok101, echo = False, repr(e).encode()
        check("101 升级响应直通（不被包装成 502）", ok101, head[:80].decode("latin1", "replace"))
        check("升级后数据双向透传", b"ping-e2e" in echo, echo[:80].decode("latin1", "replace"))

        # ---- 后台页与历史日志卡 ----
        def hist_slice(html):
            """切出历史日志卡内部（模板按钮上也写着「踢光」，整页匹配会误报）。"""
            if 'id="histsec"' not in html:
                return ""
            return html.split('id="histsec"', 1)[1].split("</details>", 1)[0]

        st, _, body = call("GET", "/__gate/admin", cookie=c1 or "")
        page = body.decode("utf-8", "replace")
        check("后台页含新卡片", st == 200 and "插件管理" in page and "历史日志" in page,
              f"status={st}")
        rows_all = hist_slice(page).count("<tr data-tone")
        st, _, body = call("GET", "/__gate/admin?q=" + quote("登录"), cookie=c1 or "")
        hq = hist_slice(body.decode("utf-8", "replace"))
        rows_q = hq.count("<tr data-tone")
        check("历史日志关键词过滤只留命中行",
              st == 200 and rows_q >= 1 and rows_q < rows_all and "登录成功" in hq
              and "DSH 就绪" not in hq,
              f"all={rows_all} q={rows_q}")
        st, _, body = call("GET", "/__gate/admin?q=zzzznohit", cookie=c1 or "")
        check("历史日志过滤无命中提示",
              st == 200 and "没有匹配" in hist_slice(body.decode("utf-8", "replace")),
              f"status={st}")

        # ---- 插件操作转发（异步） ----
        mform = urlencode({"op": "toggle", "name": "foo", "enabled": "0"})
        st, _, _ = call("POST", "/__gate/market", cookie=both, body=mform,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("插件操作受理 → 303 回后台", st == 303, f"实际 {st}")

        def got_toggle():
            with STUB_LOCK:
                return next((p for p in STUB_POSTS
                             if p["path"] == "/dsh-market/toggle" and '"enabled":false' in p["body"]),
                            None)
        rec = poll("toggle", got_toggle, timeout=6)
        check("插件操作真转给了市场", rec is not None, "桩没收到 toggle")
        if rec:
            check("插件操作转发带会话 Cookie", "dshai_gate" in rec.get("cookie", ""), rec.get("cookie", "")[:80])
        ev = poll("插件操作日志", lambda: any("插件操作" == e.get("kind") for e in hist_kinds()), timeout=6)
        check("插件操作记进历史日志", ev is not None)

        # ---- 踢光设备 ----
        st, hdr, _ = call("POST", "/__gate/logout-all", cookie=both)
        c2 = extract_cookie(hdr, "dshai_gate")
        check("踢光 → 303 且本机换新代", st == 303 and c2 is not None, f"status={st}")
        check("新代 Cookie 是四段式（含代数）", c2 is not None and c2.count(".") == 3, str(c2))
        st, _, body = call("GET", "/", cookie=c1 or "")
        check("踢光后旧 Cookie 作废", st == 401, f"status={st}")
        both2 = "; ".join(x for x in [c2, dshc] if x)
        st, _, body = call("GET", "/", cookie=both2)
        check("踢光后本机新代可用", st == 200 and b"dsh ok" in body, f"status={st}")
        ev = poll("踢光日志", lambda: any(e.get("kind") == "踢光设备" for e in hist_kinds()), timeout=4)
        check("踢光记进历史日志", ev is not None)

        # ---- 历史日志文件本体 ----
        rows = hist_kinds()
        kinds = {e.get("kind") for e in rows}
        check("历史日志落盘为 JSONL", len(rows) >= 3, f"只有 {len(rows)} 行")
        check("落盘含登录成功与会话事件", "登录成功" in kinds and "踢光设备" in kinds, str(kinds))

        # ---- 健康巡检三态（放最后：要杀桩） ----
        ev = poll("DSH 就绪", lambda: any(e.get("kind") == "DSH 就绪" for e in hist_kinds()), timeout=6)
        check("巡检首通记「DSH 就绪」", ev is not None)
        stub.close()
        ev = poll("DSH 不可达", lambda: any(e.get("kind") == "DSH 不可达" for e in hist_kinds()),
                  timeout=8)
        check("巡检连续不通记「DSH 不可达」", ev is not None)
        stub.start()
        ev = poll("DSH 重启", lambda: any(e.get("kind") == "DSH 重启" for e in hist_kinds()),
                  timeout=8)
        check("巡检恢复记「DSH 重启」", ev is not None)

    finally:
        gate.terminate()
        try:
            gate.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gate.kill()
        glog.close()
        try:
            stub.close()
        except Exception:  # noqa: BLE001
            pass

    passed = sum(results)
    total = len(results)
    print(f"\n结果：{passed}/{total} 通过", flush=True)
    if passed != total:
        print("—— 门禁日志尾部 ——", flush=True)
        try:
            with open(os.path.join(workdir, "gate.log"), "rb") as f:
                data = f.read()[-4000:]
            print(data.decode("utf-8", "replace"), flush=True)
        except OSError:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
