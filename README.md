<div align="center">

# dshai-gate

**给 DeepSeek Harness 用的精简反向代理 + 身份门禁**

单个 Go 二进制 · 只用标准库 · 零第三方依赖

[![release](https://img.shields.io/github/v/release/lyp88997/dshai-gate?color=6d8bff&label=release)](https://github.com/lyp88997/dshai-gate/releases)
[![license](https://img.shields.io/github/license/lyp88997/dshai-gate?color=9b6dff)](LICENSE)
[![go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![deps](https://img.shields.io/badge/dependencies-0-brightgreen)](gate/main.go)

把**只肯监听回环**的 DSH，安全地接到公网 —— 顺便把远端访问会踩的五个坑一次填平。

<img src="docs/login.png" width="820" alt="dshai-gate 登录页：动态验证码 + DSH 令牌">

<sub>登录页：动态验证码（TOTP）+ DSH 令牌。已有会话时令牌可留空，没有时会自动变成必填。</sub>

</div>

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [架构](#架构)
- [快速开始](#快速开始)
- [身份门禁](#身份门禁)
- [DSH 令牌自动配对](#dsh-令牌自动配对)
- [安全日志与后台页](#安全日志与后台页)
- [配置项](#配置项)
- [常见坑](#常见坑)
- [运维脚本](#运维脚本)
- [安全设计](#安全设计)
- [许可与致谢](#许可与致谢)

## 它解决什么问题

DSH 出于安全考虑**不允许**监听全网卡 —— 那等于把远程代码执行能力交给整个网络：

```console
$ dsh web --host 0.0.0.0
error: --host 0.0.0.0 is intentionally not supported yet for safety:
       it would expose remote code execution to the network; use 127.0.0.1 instead
```

所以远端访问 = **DSH 只监听 127.0.0.1** + **前面加一层反向代理**。
而把 DSH 放到反代后面，会接连撞上五个坑 —— 本项目就是为它们而写：

| # | 现象 | 根因 | 本项目的处理 |
| :-: | --- | --- | --- |
| 1 | 设置 / 插件 / 凭据等接口返回 **403** | DSH 用 Host/Origin 做特权接口围栏（`isTrustedApiRequest`） | **原样透传 Host**，配合官方 `--trusted-host <域名>`。全局改写 Host 会引出 Cookie 归属错乱与重定向死循环，故默认不动它（唯一例外见第 5 行） |
| 2 | 设置改完**存不住** | 前端按 `location.hostname` 判断"是否本机"，远端被判为非本机，面板退化为内存模式 | 对 `text/html` 注入一行 `window.__DSH_TRANSPORT__={ownsHost:true}` |
| 3 | 长连接**每分钟断开** | nginx 默认 `proxy_read_timeout 60s` 会切断 SSE / WebSocket | 反代设 `proxy_buffering off` + `proxy_read_timeout 3600s`；本服务对 `text/event-stream` 补 `X-Accel-Buffering: no` |
| 4 | 裸反代**没有门禁**，扫描器可白嫖模型额度 | 反代本身不做身份校验 | 内置 TOTP 身份门禁 + 四层防爆破 |
| 5 | 任务看板 / 技能中心 / 用量统计 / **插件市场（dshmarket 1.56.0+）** 等**插件接口 403、400** | 这几个插件把接口**自己**围栏成 loopback-only（要求 `Host` 必须是 `127.0.0.1` / `localhost`）—— `--trusted-host` 是 DSH 的放行名单，管不到插件**自己**这道围栏 | 只对**点名**的接口**定向呈现回环身份**（Host 与 Origin 同步改写），其余路径一律保持原样：纯 API 插件走 `loopbackOnlyPrefixes`（前缀），插件市场走 `marketMutationPaths`（**精确匹配**，见[常见坑](#常见坑)） |

## 架构

```text
              浏览器
                │  https
                ▼
   ┌────────────────────────────┐
   │  nginx / OpenResty / Caddy │   ← TLS、证书、HTTP/2 交给它
   └──────────────┬─────────────┘
                  │ http  127.0.0.1:2299
   ┌──────────────▼─────────────┐
   │        dshai-gate          │   ← 本项目：门禁 · Host 透传 · 定向回环 · 注入
   └──────────────┬─────────────┘
                  │ http  127.0.0.1:3082
   ┌──────────────▼─────────────┐
   │   DSH（容器，仅监听回环）   │
   └────────────────────────────┘
```

- `2299` 与 `3082` **都只绑 `127.0.0.1`**，公网不可达
- 本项目**不碰 TLS**：因此没有自签证书、单端口多路复用、子路径适配那类复杂度

## 快速开始

### 1. DSH 以容器运行，并带上 `--trusted-host`

```yaml
command: ["web", "--no-open", "--port", "3082",
          "--trusted-host", "dsh.example.com",
          "--trusted-host", "dsh.example.com:443"]
```

### 2. 下载二进制并运行（作为第二个服务）

```bash
curl -L -o dshai-gate \
  https://github.com/lyp88997/dshai-gate/releases/latest/download/dshai-gate-linux-amd64
chmod +x dshai-gate

GATE_LISTEN=127.0.0.1:2299 \
GATE_UPSTREAM=http://127.0.0.1:3082 \
GATE_TOTP_SECRET=<你的 Base32 密钥> \
GATE_SESSION_SECRET=<32 字节随机 hex> \
./dshai-gate
```

> 也可以用仓库里的 `gate/Dockerfile` 自行构建镜像（多阶段静态编译，产物约 5 MB）。

### 3. 反向代理只需要最普通的这几行

```nginx
location / {
    proxy_pass http://127.0.0.1:2299;
    proxy_http_version 1.1;
    proxy_set_header Host $host;               # 必须原样透传
    proxy_set_header Upgrade $http_upgrade;    # WebSocket
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;                       # 流式必需
    proxy_read_timeout 3600s;                  # 长连接必需
}
```

然后打开你的域名，会看到登录页。

## 身份门禁

三种模式，由环境变量决定 —— **一个都不配则拒绝启动**（fail-closed）：

| 模式 | 需要的配置 | 登录方式 |
| --- | --- | --- |
| 口令 | `GATE_PASSWORD_HASH` | 输入口令 |
| 动态码 | `GATE_TOTP_SECRET` | 输入手机 TOTP App 的 6 位码 |
| 双因子 | 两者都配 | 口令 + 动态码 |

- 动态码为标准 **RFC 6238**（HMAC-SHA1 / 30 秒 / 6 位），与 Google Authenticator、Microsoft Authenticator、Aegis、1Password、Bitwarden 等通用
- 会话为服务端 **HMAC 签名 Cookie**：`HttpOnly; Secure; SameSite=Lax`，默认 30 天
- 登录页是单文件内嵌 HTML（**深色玻璃拟态、跟随系统深浅色、6 位码满位自动提交、`autocomplete="one-time-code"` 支持手机自动填码、取令牌命令一键复制**）

### 防爆破（四层）

| 层 | 规则 |
| --- | --- |
| 单 IP 连败 | 5 次 → 锁 **15 分钟** |
| 单 IP 小时累计 | 20 次 → 锁 **1 小时** |
| 全局限速 | 最近 10 分钟失败越多，响应越慢（上限 4 秒），削弱分布式尝试 |
| 防重放 | 同一时间片用过即作废；且**整轮登录全部成功才记账**，避免「码对了但后续步骤失败」白白浪费一个码 |

每次失败都会记录来源 IP 与剩余可尝试次数。

## DSH 令牌自动配对

DSH 启动时会打印一个一次性配对链接（`http://127.0.0.1:3082/?token=...`）。
本项目把这一步搬进了登录页：**动态码下方有一个「DSH 令牌」输入框**。

| 浏览器状态 | 令牌框行为 |
| --- | --- |
| 已有有效 DSH 会话 | **可留空**，页面会提示（日常就是这种情况） |
| 没有会话（首次 / 换设备 / 换浏览器） | **必填**，填对后由本服务完成换票，并把会话 Cookie 交给浏览器 —— 不用再手工拼带 `?token=` 的网址 |

> ⚠️ DSH 的启动令牌**每次重启都会变**，它不是固定密码。
> 但 DSH 的会话 Cookie 能扛住重启，所以日常并不需要反复输入。
> 取令牌：`docker logs <dsh容器名> 2>&1 | grep -o 'token=[^ ]*' | tail -1`

登录页把这条命令做成了**可点击复制的代码块**：点「复制」即整条入剪贴板（点代码本身也行），
省得手抄 —— 容器名按你的实际情况改一下即可。

## 安全日志与后台页

门禁把最近的安全事件记在内存里（最多 300 条），通过两个地址查看：

| 地址 | 用途 |
| --- | --- |
| `/gate` | 短地址，跳转到后台页 |
| `/__gate/admin` | 后台页本体，受同一套会话 Cookie 保护（未登录先跳登录页） |

后台页有四块内容：

- **当前状态**：登录方式、本设备会话剩余时间、监听 → 上游、事件计数、全局限流延迟、锁定中的 IP
- **DSH 控制**：`重启 DSH` 按钮 + 重启状态 / 最近一次发起 / 结果
- **操作区**：`进入 DSH ↗`（新标签打开主界面）、`立即刷新`、`退出登录`
- **最近事件**：时间 / 事件 / 来源 IP / 说明 / 次数，每 10 秒自动刷新

### 重启 DSH

装了插件、改了配置需要重启才生效时，用后台页的 `重启 DSH` 按钮，不必登服务器。

- 按钮由门禁**以回环身份**调用 DSH 自己的重启接口（`POST /dsh-market/restart`），
  并轮询确认它真的停下又起来，结果写在页面上（页面每 10 秒自动刷新，重启期间盯着看即可）。
- ⚠️ **本服务的 compose 必须是 `restart: unless-stopped`。** DSH 收到停止信号是
  **优雅退出、退出码 0**，而 `restart: on-failure` 只认非 0 退出码 —— 用 on-failure 时
  点一次重启就等于**把服务彻底停掉**（本仓库 compose.yaml 因此用 `unless-stopped`）。
- 这条路依赖 dshmarket 插件已加载（重启路由由它注册）。DSH 完全起不来时按钮也救不了，
  那种情况要登服务器用 `docker compose up -d` 拉。
- 同一时刻只允许一个重启在跑；按钮要求已登录（与后台页同一套会话 Cookie），
  并额外做**同源校验**（`Sec-Fetch-Site` 优先，缺省时比对 `Origin` 与 `Host`）。
  会话 Cookie 是 `SameSite=Lax`，跨站表单本来就带不上；同源校验是纵深防御。

> **为什么门禁反代要擦转发头**：市场自己那道「无转发头 = 本机直连」的严门会把经反代来的
> 合法请求一律 403，于是市场横幅上的「立即重启」按钮原先永远失败。门禁只对**两条精确路径**
> （`/dsh-market/restart`、`/dsh-market/api/v1/restart`）擦掉 `X-Forwarded-For` / `X-Real-IP` /
> `Forwarded`，不动 Host / Origin。
>
> ⚠️ **这里绝不能用前缀 `/dsh-market/` 一把梭。** 市场把「重启 / 导出配置 / 自卸载」放在
> **同一道严门**后面，而那些接口**不要求 DSH 会话**——它们的唯一访问控制就是这道门。
> 用前缀放行的实测后果是：**只带门禁会话**就能下载 profile 配置（市场自己把
> `pnpm-workspace.yaml` 列为「常含凭据」）、自卸载市场插件，把「门禁 + DSH 令牌」的
> 双层模型压成一层。只列重启这两条即可（它们的唯一能力就是重启）。
> 市场里「下载配置备份」「自卸载」两个按钮经门禁仍是 403，这是**有意保留**的。
> 探针第 ⑦⑨ 项就守着这条线。
>
> **1.5.4 起，插件市场的写操作另走一张精确表。** dshmarket 1.56.0（上游 commit `9be13bf`，
> 修 #678 DNS rebinding）给 `sameOrigin` 加了 `loopbackAuthority(host)`：Host 必须是
> `127.0.0.1` / `localhost` / `[::1]`，于是经门禁（Host 为域名）时**安装 / 卸载 / 更新 /
> 启停全部 403 `untrusted origin`**（1.55.0 只比对 `Origin == Host`，所以此前一直正常）。
> 门禁为此新增 `marketMutationPaths`：20 条**精确**路由，只呈现回环身份，**绝不用前缀**。
> 刻意排除的仍是「重启 / 导出配置 / 快照 / Gist / WebDAV / 自卸载」。

<img src="docs/admin.png" width="820" alt="dshai-gate 后台页：状态卡片 + DSH 控制 + 安全事件表">

**降噪**：同一 IP 的同类事件在 30 秒内合并为一条并累加次数，页面显示累计次数；
标准输出只在新建条目时打印一行，不会把 `docker logs` 刷爆。

> ⚠️ 事件只存在内存里（最多 300 条），**容器重启即清空**。
> 同一份事件也会写到标准输出，可用 `docker logs <容器名>` 回看（受 Docker 日志轮转限制）；
> 需要长期留存请接外部日志采集。

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `GATE_LISTEN` | `127.0.0.1:2299` | 监听地址（**务必保持回环**） |
| `GATE_UPSTREAM` | `http://127.0.0.1:3082` | DSH 地址 |
| `GATE_INJECT` | `1` | 是否注入 `ownsHost` |
| `GATE_SITE_TITLE` | `Harness` | 登录页标题 |
| `GATE_SESSION_DAYS` | `30` | 会话有效天数 |
| `GATE_PASSWORD_HASH` | — | `sha256("dshai-gate-v1:" + 口令)` 的 64 位十六进制 |
| `GATE_TOTP_SECRET` | — | Base32 的 TOTP 密钥（可含空格、大小写不敏感） |
| `GATE_SESSION_SECRET` | — | 会话签名密钥，至少 16 字节 |

生成凭据的两个小工具（见 [运维脚本](#运维脚本)）：

```bash
bash scripts/set-totp.sh        # 生成 TOTP 密钥，并先让你在手机上验证一次
bash scripts/set-password.sh    # 设置口令（明文不落盘、不进 shell 历史）
```

## 常见坑

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 设置面板能打开但**改完不保留** | 上游把 HTML 压缩了，注入没生效 | 本服务已对上游请求 `Accept-Encoding: identity`；若自行改造反代，务必保留这一点 |
| 日志里每分钟一条 `upstream timed out` | 反代没设 `proxy_read_timeout` | 按[第 3 步](#3-反向代理只需要最普通的这几行)补齐 |
| 特权接口 403 | 忘了 `--trusted-host`，或中间层改写了 Host | 让反代 **原样透传 Host**，并把域名加进 `--trusted-host` |
| 插件面板接口 **403 / 400**（任务看板、技能中心、用量统计…） | 该插件把接口围栏成 loopback-only，而 `--trusted-host` 管不到插件自己的围栏 | 把它的接口前缀加进 `gate/main.go` 的 `loopbackOnlyPrefixes`，重建后用 `scripts/gate-probe.sh` 回归 |
| **插件市场里安装 / 卸载 / 更新 / 启停全部 403 `untrusted origin`** | dshmarket **1.56.0** 起 `sameOrigin` 要求 Host 是回环；1.55.0 只比对 `Origin == Host`，所以此前正常 | 把**精确**路由加进 `gate/main.go` 的 `marketMutationPaths`（**不要**用前缀 `/dsh-market/`）。1.5.4 起已内置，探针第 ⑧ 项守着它 |
| DSH 容器反复重启 | 数据目录里有容器读不到的条目（文件监听会抛 EACCES） | 起容器前跑 `scripts/perm-guard.sh`，并把备份**放在数据目录之外** |
| 改了凭据后不生效 | 配置改动需要重启本服务 | `docker compose up -d gate`（会话密钥不变则已登录设备不受影响） |
| 把自己锁在门外 | 忘了动态码 / 丢了手机 | 在**服务器上**重跑 `scripts/set-totp.sh` 换新密钥 |

## 运维脚本

| 脚本 | 用途 |
| --- | --- |
| `scripts/selfcheck.sh` | 一键自检：容器健康、门禁是否拦住未授权、登录页是否正确、开放路由是否被挡、旧实例状态 |
| `scripts/gate-probe.sh` | **门禁链路探针**：自签会话走完整链路，逐项验证插件接口 200、核心接口未受影响、未登录仍是 401、后台页与 `/gate` 短地址正常，另有 ⑥ X-Forwarded-For 信任方向、⑦ 市场围栏是否恢复（`/dsh-market/backup` 应 403、`/dsh-market/status` 应 200）、⑧ 市场变更路由已放行（应回业务错误 400 而非 403）、⑨ 排除清单仍被挡（`backup` / `self-uninstall` 应 403）。**改过 `loopbackOnlyPrefixes` / `marketMutationPaths` / `processControlPaths` / `clientIP` 后必跑**；也可带一个公网 URL 参数，走 nginx 做全链路回归 |
| `scripts/perm-guard.sh` | **起容器前必跑**：检查数据目录里有没有容器读不到的条目（否则 DSH 崩溃重启） |
| `scripts/set-password.sh` | 设置 / 更换口令 |
| `scripts/set-totp.sh` | 生成 TOTP 密钥；**先验证一次再写配置**，避免把自己锁在门外 |
| `scripts/verify-totp.py` | 独立校验某个 TOTP 密钥与 6 位码是否匹配 |
| `scripts/rollback.sh` | 回滚（可只停门禁，或停整套；不动数据） |

## 安全设计

- **fail-closed**：没有任何认证配置时**拒绝启动**（宁可 502，也不留一扇没锁的门）
- **只绑回环**：`GATE_LISTEN` 默认 `127.0.0.1`，不要改成 `0.0.0.0`
- **密钥只从环境变量注入**：仓库与镜像里不含任何凭据；`.gitignore` 也挡掉了 `.env`、初始口令文件、数据目录
- **不伪造请求头**：Host / Origin / Sec-Fetch-* **默认**一律原样透传，因此不存在 Cookie 归属漂移与重定向死循环。三处例外：`loopbackOnlyPrefixes`（纯 API 插件接口，前缀匹配；含 `.`/`..` 段的路径**不**给身份，因为上游会把它归一化成别的路径，等于给白名单开后门）、`marketMutationPaths`（插件市场的 20 条**精确**变更路由——用精确匹配而不是前缀，是因为实测 `/dsh-market/backup` 与 `/dsh-market/logs` **不带任何 DSH 会话**就能读到 profile 配置与日志，前缀一把梭会把「门禁 + DSH 令牌」压成一层），以及 `processControlPaths`（两条精确重启路径，只**擦掉** `X-Forwarded-For` / `X-Real-IP` / `Forwarded`；1.5.4 起这两条同时也要回环身份，因为 `trustedRestartRequest` 除了「无转发头」还要求回环 Host）
- **按 IP 防爆破只信最后一跳**：`clientIP()` 取 `X-Forwarded-For` 的**最后一个**非空值。上游 nginx 用 `$proxy_add_x_forwarded_for`，语义是「客户端自带值 + 真实 IP」；取第一个等于把攻击者随手写的字符串当成客户端身份，按 IP 锁定会被每次换个伪造值绕过
- **不做多余的事**：不实现用户系统、不做 OAuth、不引入数据库 —— 一台机器一个人，够用即可

## 许可与致谢

MIT © 2026 lyp88997

反代适配的思路（尤其是「特权接口 403」「前端 isLoopback」「子路径与长连接」这几类坑）参考了
[yuexps/deepseek.harness.fnos](https://github.com/yuexps/deepseek.harness.fnos) 的
`REVERSE_PROXY_ADAPTATION.md`。

本仓库代码为**独立重写**：不含 fnOS 网关的子路径适配、不伪造 Host/Origin（仅对 loopback-only 插件接口定向呈现回环身份）、
不含自动换票的防环逻辑（改用官方 `--trusted-host` + 一次性配对），
因此代码量约为其反代部分的 1/6。
