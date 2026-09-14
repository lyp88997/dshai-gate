#!/bin/sh
# 设置 / 修改 dshai-gate 的访问口令
# 安全设计：明文口令不落盘、不进 shell 历史、不经过任何网络；磁盘上只留 sha256 哈希。
# 用法：在交互式终端里执行  bash /opt/dshai/scripts/set-password.sh
set -eu
ENV=/opt/dshai/.env
PW=""
if [ "${1:-}" != "" ]; then
  PW="$1"
  echo "⚠️  从命令行参数读入口令会留在 shell 历史里，建议改用交互式输入。"
else
  printf '请输入新的访问口令（输入时不显示）：'
  if [ -t 0 ]; then stty -echo 2>/dev/null || true; fi
  read -r PW
  if [ -t 0 ]; then stty echo 2>/dev/null || true; fi
  echo
  printf '请再输入一次确认：'
  if [ -t 0 ]; then stty -echo 2>/dev/null || true; fi
  read -r PW2
  if [ -t 0 ]; then stty echo 2>/dev/null || true; fi
  echo
  [ "$PW" = "$PW2" ] || { echo "两次输入不一致，已取消。"; exit 1; }
  unset PW2
fi
[ -n "$PW" ] || { echo "口令不能为空，已取消。"; exit 1; }

H=$(printf 'dshai-gate-v1:%s' "$PW" | sha256sum | awk '{print $1}')
S=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
unset PW

umask 077
{
  echo "GATE_PASSWORD_HASH=$H"
  echo "GATE_SESSION_SECRET=$S"
} > "$ENV"
chmod 600 "$ENV"

echo "已写入 $ENV （权限 600，只含哈希与随机密钥）"
echo "下一步：cd /opt/dshai && docker compose up -d gate"
