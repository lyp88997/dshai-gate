#!/bin/sh
# 设置 / 更换 TOTP 动态验证码（Google Authenticator、Microsoft Authenticator、Aegis… 通用）
# 安全设计：
#   ① 密钥由服务器随机生成，不落 shell 历史、不经网络、不经过任何第三方
#   ② 先让你在手机上验证一次能出正确码，验证通过才写配置 —— 避免把自己锁在门外
#   ③ 写入后为 TOTP 单因子模式（移除口令哈希），保留原有会话密钥
set -eu
ENV=/opt/dshai/.env
VERIFY=/opt/dshai/scripts/verify-totp.py
LABEL="Harness:dsh.example.com"

SEC=$(head -c 20 /dev/urandom | base32 | tr -d '=\n')
GROUPED=$(printf '%s' "$SEC" | fold -w4 | paste -sd' ' -)

cat <<TXT

────────────────────────────────────────────────────────
请用手机上的 TOTP App 手动添加（以 Google Authenticator 为例）：
  1. 打开 App → 右下角「+」→ 选「输入设置密钥 / Enter a setup key」
  2. 账户名：$LABEL
  3. 密钥（按 4 位一组输入，空格不用输）：
        $GROUPED
  4. 类型选「基于时间 / Time-based」，位数 6，周期 30 秒

如果你的 App 支持粘贴链接（⚠️ 不要把这个链接发给任何人）：
  otpauth://totp/$LABEL?secret=$SEC&issuer=Harness&algorithm=SHA1&digits=6&period=30
────────────────────────────────────────────────────────
TXT

printf '添加完成后，请输入 App 上当前显示的 6 位动态码：'
read -r CODE

if ! python3 "$VERIFY" "$SEC" "$CODE"; then
  echo
  echo "❌ 校验失败：密钥可能输错了，或者手机时间不准（请把手机设为「自动设置时间」）。"
  echo "   未做任何修改，请重新运行本脚本。"
  exit 1
fi

echo
echo "✅ 动态码验证通过"
umask 077
S=$(grep -m1 '^GATE_SESSION_SECRET=' "$ENV" 2>/dev/null | cut -d= -f2- || true)
[ -n "${S:-}" ] || S=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
{
  echo "GATE_SESSION_SECRET=$S"
  echo "GATE_TOTP_SECRET=$SEC"
} > "$ENV"
chmod 600 "$ENV"
echo "已写入 $ENV（TOTP 单因子模式，已移除口令）"
echo
echo "👉 下一步（重启后生效，之后只能用这个 6 位动态码登录）："
echo "     cd /opt/dshai && docker compose up -d gate"
echo
echo "⚠️  手机丢失时的恢复：重新运行本脚本可生成新密钥（前提是还能登录服务器）。"
