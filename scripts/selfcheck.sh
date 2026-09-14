#!/bin/sh
# dshai 一键自检（全部只读探测）
# 注意：门禁之后，"注入是否生效"必须登录后目视确认，脚本无法代替（见末尾提示）。
set -u
cd /opt/dshai || exit 1
ok=0; ng=0
chk() {
  if [ "$2" = "$3" ]; then printf '  ✓ %-28s %s\n' "$1" "$2"; ok=$((ok+1))
  else printf '  ✗ %-28s 实测=%s 期望=%s\n' "$1" "$2" "$3"; ng=$((ng+1)); fi
}

chk "DSH 容器健康" "$(docker inspect -f '{{.State.Health.Status}}' dshai-web 2>/dev/null || echo none)" "healthy"
chk "gate 容器运行中" "$(docker inspect -f '{{.State.Status}}' dshai-gate 2>/dev/null || echo none)" "running"
chk "DSH 直连 :3082" "$(curl -s -o /dev/null -m 6 -w '%{http_code}' http://127.0.0.1:3082/)" "401"

code=$(curl -s -o /tmp/.sc_login -m 8 -w '%{http_code}' -H 'Accept: text/html' http://127.0.0.1:2299/)
chk "未登录首页状态" "$code" "401"
chk "未登录返回登录页" "$(grep -c 'action="/__gate/login"' /tmp/.sc_login 2>/dev/null)" "1"
chk "登录页不泄露DSH内容" "$(grep -c 'dsh web auth\|__DSH_TRANSPORT__' /tmp/.sc_login 2>/dev/null)" "0"
chk "登录页含 DSH 令牌框" "$(grep -c 'name="dstoken"' /tmp/.sc_login 2>/dev/null)" "1"
chk "未登录 API 被拦" "$(curl -s -o /dev/null -m 8 -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:2299/api/settings.describe)" "401"
chk "开放路由已被门禁挡" "$(curl -s -o /dev/null -m 8 -w '%{http_code}' http://127.0.0.1:2299/plugins/events)" "401"
chk "门禁已启用(启动日志)" "$(docker logs dshai-gate 2>&1 | grep -c 'dshai-gate 启动')" "1"
chk "旧实例已清除" "$(docker ps -a --filter name=^dsh-web$ --format {{.Names}} | grep -q . && echo 仍存在 || echo removed)" "removed"

echo "  ── 通过 $ok 项，失败 $ng 项"
echo "  提示：登录后的注入效果（设置项能否存住）需在浏览器目视确认一次。"
[ "$ng" = "0" ] || exit 1
