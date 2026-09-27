#!/bin/sh
# 门禁链路探针 v2：同时携带「门禁会话 Cookie」与「DSH 会话 Cookie」，
# 走完整链路（门禁 -> DSH）验证各接口。不打印任何密钥或 Cookie 值。
# 用法：gate-probe.sh [门禁地址]   默认 http://127.0.0.1:2299
set -eu

ENVF=/opt/dshai/.env
GATE=${1:-http://127.0.0.1:2299}
DSH=http://127.0.0.1:3082
# Host 头必须落在 DSH 的 --trusted-host 名单里（也决定 nginx 选哪个 vhost），
# 所以从 .env 的 DSH_TRUSTED_HOST 取，而不是写死占位域名。
HOSTHDR=$(grep -m1 '^DSH_TRUSTED_HOST=' "$ENVF" 2>/dev/null | cut -d= -f2- || true)
[ -n "${HOSTHDR:-}" ] || HOSTHDR="dsh.example.com"
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

echo "== ④ 门禁后台与短地址（/gate）=="
printf '  %-42s [%s]\n' "无 Cookie /__gate/admin（应 401）" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" "$GATE/__gate/admin")"
ADMCODE=$(curl -s -o /tmp/admin.out -w '%{http_code}' -H "Host: $HOSTHDR" -b "$GATECOOKIE" "$GATE/__gate/admin")
if [ "$ADMCODE" = "200" ] && grep -q '安全日志' /tmp/admin.out; then
  printf '  %-42s [%s] 含日志标题 ✓\n' "带 Cookie /__gate/admin" "$ADMCODE"
else
  printf '  %-42s [%s] ✗ 后台页异常\n' "带 Cookie /__gate/admin" "$ADMCODE"
fi
for t in "进入 DSH" "立即刷新" "退出登录"; do
  if grep -q "$t" /tmp/admin.out; then
    printf '  %-42s ✓\n' "后台页操作区含「$t」"
  else
    printf '  %-42s ✗ 缺失\n' "后台页操作区含「$t」"
  fi
done
printf '  %-42s [%s] -> %s\n' "/gate 短地址（应 302 到后台页）" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" "$GATE/gate")" \
  "$(curl -s -o /dev/null -w '%{redirect_url}' -H "Host: $HOSTHDR" "$GATE/gate")"
printf '  %-42s %s 处\n' "登录页含可复制命令块" \
  "$(curl -s -H "Host: $HOSTHDR" -H 'Accept: text/html' "$GATE/__gate/login" | grep -c 'data-copy=')"

echo "== ⑥ X-Forwarded-For 信任方向（防爆破「按 IP 锁定」依赖它）=="
# 上游 nginx 用 $proxy_add_x_forwarded_for，语义是「客户端自带值 + 真实 IP」，
# 即「不可信前缀 + 可信后缀」。门禁必须取最后一个；取第一个等于把攻击者
# 随手写的字符串当成客户端身份，于是每次换个伪造值就能绕过按 IP 锁定。
SPOOF=203.0.113.7; LAST=198.51.100.9
curl -s -o /dev/null -H "Host: $HOSTHDR" -H "X-Forwarded-For: $SPOOF, $LAST" "$GATE/__gate/ipcheck"
LINE=$(docker logs dshai-gate 2>&1 | grep '未鉴权拦截' | tail -1)
case "$LINE" in
  *"$LAST"*) printf '  %-42s ✓ 取到最后一跳 %s\n' "伪造 $SPOOF + 真实 $LAST" "$LAST";;
  *"$SPOOF"*) printf '  %-42s ✗ 取了伪造的第一个值！\n' "伪造 $SPOOF + 真实 $LAST";;
  *) printf '  %-42s ? 日志未命中：%s\n' "XFF 信任方向" "$LINE";;
esac

echo "== ⑦ 市场围栏是否恢复（只带门禁会话、不带 DSH 会话）=="
# 1.5.1 曾用前缀 /dsh-market/ 擦转发头，结果只带门禁会话就能导出 profile 配置、
# 自卸载市场插件（把「门禁 + DSH 令牌」压成一层）。1.5.3 收窄成只擦精确的重启
# 路径后，这两个接口必须重新被市场自己的严门挡住（403）。
BK=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" -b "$GATECOOKIE" \
  -H "Origin: https://$HOSTHDR" "$GATE/dsh-market/backup")
if [ "$BK" = "403" ]; then printf '  %-42s [%s] ✓ 需要 DSH 令牌\n' "/dsh-market/backup（应 403）" "$BK"
else printf '  %-42s [%s] ✗ 围栏失效！\n' "/dsh-market/backup（应 403）" "$BK"; fi
ST=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" -b "$GATECOOKIE" \
  -H "Origin: https://$HOSTHDR" "$GATE/dsh-market/status")
if [ "$ST" = "200" ]; then printf '  %-42s [%s] ✓ 市场未被整体挡住\n' "/dsh-market/status（应 200）" "$ST"
else printf '  %-42s [%s] ✗ 市场不可达\n' "/dsh-market/status（应 200）" "$ST"; fi

echo "== ⑧ 市场变更路由是否放行（修复目标：不再 403 untrusted origin）=="
# dshmarket 1.56.0 起 sameOrigin 要求 Host 必须是回环，经域名一律 403
# "untrusted origin"，安装/卸载/更新/启停全部失效。门禁对 marketMutationPaths
# 列出的精确路由呈现回环身份后，这些接口应落到**业务错误**而不是 403。
for p in /dsh-market/uninstall /dsh-market/toggle /dsh-market/update; do
  C=$(post "$p")
  if [ "$C" = "403" ] && grep -q 'untrusted origin' /tmp/probe.out; then
    printf '  %-42s [%s] ✗ 仍被市场围栏挡住\n' "POST $p" "$C"
  else
    printf '  %-42s [%s] ✓ %s\n' "POST $p" "$C" "$(head -c 44 /tmp/probe.out)"
  fi
done

echo "== ⑨ 排除清单必须仍被挡（这些接口不需要 DSH 会话）=="
# ★ 这几个接口**不带任何 DSH 会话**就能拿到 profile 配置 / 卸载市场，
#   它们唯一的门就是 trustedDownloadRequest / sameOrigin。门禁绝不能给它们回环身份。
#   /dsh-market/restart 不要放进探针：它会真的重启 DSH。
C=$(get /dsh-market/backup)
if [ "$C" = "403" ]; then printf '  %-42s [%s] ✓ 保持拒绝\n' "GET /dsh-market/backup（应 403）" "$C"
else printf '  %-42s [%s] ✗ 围栏失效！\n' "GET /dsh-market/backup（应 403）" "$C"; fi
C=$(post /dsh-market/self-uninstall)
if [ "$C" = "403" ]; then printf '  %-42s [%s] ✓ 保持拒绝\n' "POST /dsh-market/self-uninstall（应 403）" "$C"
else printf '  %-42s [%s] ✗ 围栏失效！\n' "POST /dsh-market/self-uninstall（应 403）" "$C"; fi
# 已知上游缺口（非门禁引入，实测改动前后都是 200）：/dsh-market/logs 在 dshmarket
# 里**没有任何围栏**，只带门禁会话即可读到（内容由市场自身脱敏）。仅记录事实。
printf '  %-42s [%s] 上游未设防（已知，与门禁无关）\n' "GET /dsh-market/logs（上游无围栏）" "$(get /dsh-market/logs)"

rm -f /tmp/probe.out /tmp/admin.out "$JAR"
