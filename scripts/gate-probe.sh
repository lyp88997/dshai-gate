#!/bin/sh
# 门禁链路探针 v2：同时携带「门禁会话 Cookie」与「DSH 会话 Cookie」，
# 走完整链路（门禁 -> DSH）验证各接口。不打印任何密钥或 Cookie 值。
set -eu

ENVF=/opt/dshai/.env
GATE=http://127.0.0.1:2299
DSH=http://127.0.0.1:3082
HOSTHDR="dsh.example.com"
JAR=/tmp/dsh.jar

# 1) 自签门禁会话 Cookie
SECRET=$(grep -E '^GATE_SESSION_SECRET=' "$ENVF" | cut -d= -f2-)
GATECOOKIE=$(SECRET="$SECRET" python3 - <<'PY'
import base64, hashlib, hmac, os, time
secret = os.environ["SECRET"].encode()
exp = int(time.time()) + 600
p = "v1." + str(exp)
sig = base64.urlsafe_b64encode(hmac.new(secret, p.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print("dshai_gate=" + p + "." + sig)
PY
)

# 2) 向 DSH 换取会话 Cookie（用容器启动令牌，值不回显）
TOKEN=$(docker logs dshai-web 2>&1 | grep -o 'token=[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2)
rm -f "$JAR"
curl -s -c "$JAR" -o /dev/null -H "Host: $HOSTHDR" "$DSH/?token=$TOKEN" || true
if ! grep -q 'dsh-auth-' "$JAR" 2>/dev/null; then
  echo "!! 未能取得 DSH 会话 Cookie，核心接口对照将不可用"
fi

get() { # get <path>
  curl -s -o /tmp/probe.out -w '%{http_code}' -H "Host: $HOSTHDR" \
    -b "$JAR" -b "$GATECOOKIE" -H 'Sec-Fetch-Site: same-origin' \
    -H "Origin: https://$HOSTHDR" "$GATE$1"
}
post() { # post <path>
  curl -s -o /tmp/probe.out -w '%{http_code}' -H "Host: $HOSTHDR" \
    -b "$JAR" -b "$GATECOOKIE" -H 'Content-Type: application/json' \
    -H "Origin: https://$HOSTHDR" -X POST -d '{}' "$GATE$1"
}

echo "== ① 仅回环类插件接口（修复目标：应全部 200）=="
for p in /api/task-board/state /api/dsh-skill-explorer/list \
         /api/dsh-provider-usage/ui-config /modlens/config /modsearch/config; do
  printf '  %-42s [%s] %s\n' "$p" "$(get "$p")" "$(head -c 60 /tmp/probe.out)"
done

echo "== ② 核心接口（必须不受影响：应 200）=="
for p in /api/subagents/list /api/agentPresets/list; do
  printf '  %-42s [%s] %s\n' "POST $p" "$(post "$p")" "$(head -c 60 /tmp/probe.out)"
done
printf '  %-42s [%s] %s\n' "GET /manifest.webmanifest" "$(get /manifest.webmanifest)" "$(head -c 40 /tmp/probe.out)"

echo "== ③ 门禁拦截（未登录应 401；登录页应是 HTML）=="
printf '  %-42s [%s]\n' "无 Cookie /api/task-board/state" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" "$GATE/api/task-board/state")"
printf '  %-42s [%s]\n' "无 Cookie / (浏览器导航)" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" -H 'Accept: text/html' "$GATE/")"

rm -f /tmp/probe.out "$JAR"
