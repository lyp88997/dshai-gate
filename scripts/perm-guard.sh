#!/bin/sh
# 起容器前必跑：确认 data/ workspaces/ home/ 内没有 uid 1000 读不到的条目。
# 来历：旧部署铁律 8 —— 容器(uid 1000)读不到的文件会让 chokidar 抛未捕获 EACCES，
#       进程退出 -> 容器无限重启且不自愈（旧实例曾因此中断 37 分钟）。
# 判定标准：只报「uid 1000 真的读不到」的条目（按 other 位判定），避免误报挂载点。
# 用法：perm-guard.sh [--fix]
set -u
ROOT=${ROOT:-/opt/dshai}
FIX=0; [ "${1:-}" = "--fix" ] && FIX=1
bad=0
for d in "$ROOT/data" "$ROOT/workspaces" "$ROOT/home"; do
  [ -d "$d" ] || continue
  out=$(
    find "$d" -type f ! -uid 1000 ! -perm -0004 -printf 'NO_OTHER_READ %u:%g %m %p\n' 2>/dev/null
    find "$d" -type d ! -uid 1000 ! -perm -0005 -printf 'NO_OTHER_RX   %u:%g %m %p\n' 2>/dev/null
    find "$d" -type f ! -perm -0400 ! -perm -0040 ! -perm -0004 -printf 'NO_ANY_READ   %u:%g %m %p\n' 2>/dev/null
  )
  if [ -n "$out" ]; then
    bad=1; echo "[$d] 发现隐患："; echo "$out" | head -20
  else
    echo "[$d] 干净 ✓"
  fi
done
if [ "$bad" = "1" ]; then
  if [ "$FIX" = "1" ]; then
    echo "修复中：chown -R 1000:1000 + chmod -R u+rwX"
    chown -R 1000:1000 "$ROOT/data" "$ROOT/workspaces" "$ROOT/home"
    chmod -R u+rwX "$ROOT/data" "$ROOT/workspaces" "$ROOT/home"
    echo "修复完成，请重跑一次确认。"
  else
    echo "请先执行：bash $0 --fix"; exit 1
  fi
fi
exit 0
