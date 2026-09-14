# dshai-gate

面向 **DeepSeek Harness（DSH）** 的精简反向代理 + 身份门禁：单个 Go 二进制，**只用标准库、零第三方依赖**。

## 为什么需要它

DSH 出于安全考虑**不允许**监听全网卡 —— 那等于把远程代码执行能力交给整个网络：

```
$ dsh web --host 0.0.0.0
error: --host 0.0.0.0 is intentionally not supported yet for safety:
       it would expose remote code execution to the network; use 127.0.0.1 instead
```

所以远端访问必须「DSH 只监听回环 + 前面加反向代理」。而把 DSH 放到反代后面，会依次撞上下面这几个具体问题，本项目把它们一次性解决：

| 问题 | 现象 | 本项目的做法 |
|---|---|---|
| 服务端特权接口被拒 | 远端打开后，设置 / 插件 / 凭据 / 会话等接口返回 403 | **原样透传 Host**，配合 DSH 官方的 `--trusted-host <域名>`。不伪造 Host / Origin —— 伪造会连带引出 Cookie 归属错乱和重定向死循环 |
| 前端认为自己不在本机 | 设置面板退化为「内存模式」，改完存不住 | 对 `text/html` 响应注入一行 `window.__DSH_TRANSPORT__={ownsHost:true}` |
| 长连接被切断 | 事件流 / WebSocket 每分钟断开一次，页面频繁重连 | 注入侧禁用上游压缩；对 `text/event-stream` 补 `X-Accel-Buffering: no`；反代站点设 `proxy_buffering off` + `proxy_read_timeout 3600s` |
| 公网无门禁 | 任何扫描器都能直连、消耗模型额度 | 内置身份门禁 + 防爆破（见下） |

## 架构

```
浏览器 ──https──> 反向代理（nginx / OpenResty / Caddy，负责 TLS）
                    └─> 127.0.0.1:2299   dshai-gate（本项目）
                            └─> 127.0.0.1:3082   DSH（容器，仅回环）
```

- TLS、证书、HTTP/2 交给成熟的反代，本项目**不碰 TLS**（因此没有自签证书、cmux 单端口那类复杂度）
- `2299` 与 `3082` 都只绑 `127.0.0.1`，公网不可达

## 身份门禁

三种模式，由环境变量决定（**都不配则拒绝启动**，fail-closed）：

| 模式 | 需要的配置 | 登录方式 |
|---|---|---|
| 口令 | `GATE_PASSWORD_HASH` | 输入口令 |
| 动态码 | `GATE_TOTP_SECRET` | 输入手机 TOTP App 的 6 位码 |
| 双因子 | 两者都配 | 口令 + 动态码 |

- 动态码为标准 **RFC 6238**（HMAC-SHA1 / 30 秒 / 6 位），与 Google Authenticator、Microsoft Authenticator、Aegis、1Password、Bitwarden 等通用
- 会话是服务端 **HMAC 签名 Cookie**：`HttpOnly; Secure; SameSite=Lax`，默认 30 天
- 登录页为单文件内嵌 HTML（深色玻璃拟态、跟随系统深浅色、6 位码满位自动提交、`autocomplete="one-time-code"` 支持手机自动填码）

### 防爆破

- 单 IP 连续失败 **5 次 → 锁 15 分钟**；1 小时内累计 **20 次 → 锁 1 小时**
- **全局限速**：最近 10 分钟内失败越多，响应越慢（上限 4 秒），削弱分布式尝试
- **动态码防重放**：同一时间片用过即作废；且只有**整轮登录全部成功**才记账，避免「码对了但后续步骤失败」白白浪费一个码
- 每次失败记录来源 IP 与剩余次数

## DSH 令牌自动配对

DSH 启动时会打印一个一次性配对链接（`http://127.0.0.1:3082/?token=...`）。
本项目把这一步搬进登录页：动态码下方有一个「DSH 令牌」输入框。

| 浏览器状态 | 令牌框 |
|---|---|
| 已有有效 DSH 会话 | **可留空**，页面会提示 |
| 没有会话（首次 / 换设备 / 换浏览器） | **必填**，填对后由本服务完成换票并把会话 Cookie 交给浏览器 |

> DSH 的启动令牌**每次重启都会变**，它不是一个固定密码。但 DSH 的会话 Cookie 能扛住重启，所以日常并不需要反复输入。
> 取令牌：`docker logs <dsh容器名> 2>&1 | grep -o 'token=[^ ]*' | tail -1`

## 配置项

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `GATE_LISTEN` | `127.0.0.1:2299` | 监听地址（务必保持回环） |
| `GATE_UPSTREAM` | `http://127.0.0.1:3082` | DSH 地址 |
| `GATE_INJECT` | `1` | 是否注入 `ownsHost` |
| `GATE_SITE_TITLE` | `Harness` | 登录页标题 |
| `GATE_SESSION_DAYS` | `30` | 会话有效天数 |
| `GATE_PASSWORD_HASH` | — | `sha256("dshai-gate-v1:" + 口令)` 的 64 位十六进制 |
| `GATE_TOTP_SECRET` | — | Base32 的 TOTP 密钥（可含空格、大小写不敏感） |
| `GATE_SESSION_SECRET` | — | 会话签名密钥，至少 16 字节 |

## 部署要点

1. **DSH 以容器运行、只绑回环**，并带上 `--trusted-host <你的域名>`：
   ```yaml
   command: ["web", "--no-open", "--port", "3082",
             "--trusted-host", "dsh.example.com",
             "--trusted-host", "dsh.example.com:443"]
   ```
2. **本服务作为第二个 compose 服务**（host 网络，监听 `127.0.0.1:2299`），上游指向 DSH。
3. **反向代理只需最普通的配置**（nginx 例）：
   ```nginx
   location / {
       proxy_pass http://127.0.0.1:2299;
       proxy_http_version 1.1;
       proxy_set_header Host $host;              # 必须原样透传
       proxy_set_header Upgrade $http_upgrade;   # WebSocket
       proxy_set_header Connection $connection_upgrade;
       proxy_buffering off;                      # 流式必需
       proxy_read_timeout 3600s;                 # 长连接必需
   }
   ```
4. 不要给 `2299` / `3082` 开公网端口。

## 运维脚本

| 脚本 | 用途 |
|---|---|
| `scripts/selfcheck.sh` | 一键自检（容器健康 / 门禁是否拦住未授权 / 登录页是否正确 / 开放路由是否被挡） |
| `scripts/perm-guard.sh` | 起容器前必跑：检查数据目录里有没有容器读不到的条目（否则 DSH 的文件监听会抛 EACCES 导致崩溃重启） |
| `scripts/set-password.sh` | 设置/更换口令（明文不落盘、不进 shell 历史） |
| `scripts/set-totp.sh` | 生成 TOTP 密钥；**先让你在手机上验证一次能对上才写配置**，避免把自己锁在门外 |
| `scripts/verify-totp.py` | 独立校验某个 TOTP 密钥与 6 位码是否匹配 |
| `scripts/rollback.sh` | 回滚（停 gate → 停整套） |
| `scripts/github-publish.sh` | 脱敏后发布/更新本仓库 |

## 恢复通道（重要）

若手机丢失或口令遗忘：在**服务器上**重新执行 `set-totp.sh` / `set-password.sh` 换新凭据即可。
所以请确保至少保留一种服务器访问方式（SSH 或面板终端）。

## 致谢

反代适配的思路（尤其是「特权接口 403」「前端 isLoopback」「子路径/长连接」这几类坑）参考了
[yuexps/deepseek.harness.fnos](https://github.com/yuexps/deepseek.harness.fnos) 的
`REVERSE_PROXY_ADAPTATION.md`。本仓库代码为独立重写：不含 fnOS 网关子路径适配、不伪造 Host/Origin、
不含 token 自动换票的防环逻辑（改用官方 `--trusted-host` + 一次性配对）。

## 许可

MIT
