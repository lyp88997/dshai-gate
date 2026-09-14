#!/bin/sh
# dshai 回滚：可只停门禁，或停整套；不删除任何数据
set -u
cd /opt/dshai || exit 1
echo "[1/3] 停止 gate（DSH 本体继续运行）"; docker compose stop gate
echo "[2/3] 停止整套"; docker compose stop dsh
echo "[3/3] 当前状态"; docker compose ps --all --format '{{.Name}} | {{.Status}}'
cat <<'TXT'

如需彻底移除：
  1) 在反向代理（面板 / nginx）里停用或删除本服务对应的站点
  2) cd /opt/dshai && docker compose down
  3) 数据仍在 /opt/dshai/data，请先备份再删除

重新启用：
  cd /opt/dshai && docker compose up -d
TXT
