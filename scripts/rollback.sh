#!/bin/sh
# dshai 回滚：不动旧实例(/opt/dsh)、不动 1Panel 旧站点
set -u
cd /opt/dshai || exit 1
echo "[1/3] 停止 gate（DSH 本体继续运行）"; docker compose stop gate
echo "[2/3] 停止整套"; docker compose stop dsh
echo "[3/3] 当前状态"; docker compose ps --all --format '{{.Name}} | {{.Status}}'
cat <<'TXT'

如需彻底移除：
  1) 在 1Panel 里停用/删除 dsh.example.com 站点（不要动 dsh.mzlp.eu.org）
  2) cd /opt/dshai && docker compose down
  3) 数据仍在 /opt/dshai/data，可先备份再删

重新启用：
  cd /opt/dshai && docker compose up -d
TXT
