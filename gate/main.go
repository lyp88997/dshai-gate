// dshai-gate —— DSH 专用精简反向代理 + 身份门禁（口令 / 动态验证码 / 两者）
//
// 认证方式由配置决定（向后兼容）：
//   GATE_PASSWORD_HASH 有值 → 校验口令
//   GATE_TOTP_SECRET   有值 → 校验 RFC6238 动态验证码（30s/6位/SHA1，任何 TOTP App 通用）
//   两者都有 → 双因子；两者都没有 → 拒绝启动（fail-closed）
//
// 防爆破：单 IP 连续失败 5 次锁 15 分钟；1 小时内累计 20 次锁 1 小时；
//         全局限流：10 分钟内的失败次数会线性加大响应延迟（上限 4s），抵御分布式尝试；
//         动态码用过的窗口立即作废（防重放）。
//
// 安全日志：登录成功/失败、锁定、动态码重放、令牌换票、未鉴权拦截等事件
//         写 stdout 并留在内存环形缓冲中，由 /__gate/admin 查看（需已登录）。
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	// ★ 内嵌 IANA 时区库（标准库自带，不引入第三方依赖）。
	//   gate 镜像基于 alpine:3.20，里面没有 zoneinfo；发布产物又是脱离容器的单二进制。
	//   不内嵌的话 TZ=Asia/Shanghai 会被静默忽略，日志与后台页时间比本地时间早 8 小时
	//   （2026-09-27 实测：宿主 18:45:35 CST 而容器 10:45:35 UTC）。
	_ "time/tzdata"
)

//go:embed login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

const injection = `<script>try{window.__DSH_TRANSPORT__=Object.assign(window.__DSH_TRANSPORT__||{},{ownsHost:true})}catch(e){}</script><style>[data-slot="settings.action"]{display:none!important}</style>`

const (
	gatePrefix   = "/__gate"
	gateVersion  = "1.9.0"
	cookieName   = "dshai_gate"
	pwSalt       = "dshai-gate-v1"

	// dshStampName 记录「本设备上次与 DSH 完成配对的时间」。
	// 为什么需要它：DSH 自己的会话 Cookie 不带有效期信息，门禁无法知道它还剩多久；
	// 于是门禁在自己的会话体系里记一笔（GATE_DSH_SESSION_DAYS 天），
	// 过期后就算 DSH 还认这个会话，门禁也要求重新配对（见 dshSessionFresh）。
	dshStampName = "dshai_dsh"

	// oauthStateName 是 GitHub 登录的防重放票据（code 换票前必须对得上）。
	oauthStateName = "dshai_oauth"
	totpPeriod   = 30
	totpDigits   = 6
	totpSkew     = 1
	maxFailures  = 5
	lockDuration = 15 * time.Minute
	hardFails    = 20
	hardLock     = time.Hour
	failWindow   = time.Hour
	baseDelay    = 700 * time.Millisecond
	delayPerFail = 400 * time.Millisecond
	maxDelay     = 4 * time.Second
	globalWindow = 10 * time.Minute

	// 安全日志：内存环形缓冲的容量，与「同类事件合并窗口」
	secLogMax   = 300
	secCoalesce = 30 * time.Second

	// adminRowsMax 是后台页一次渲染的事件行数上限：页面每 10 秒自动刷新，
	// 把 secLogMax 行全塞进 DOM 纯属浪费。更早的记录仍在内存里（统计照算），
	// 只是不渲染。
	adminRowsMax = 100

	// 标准输出的限速：一个窗口最多 outBurst 行，多出来的只在窗口结束时
	// 汇总成一行。分布式扫描（每个新 IP 都会新建一条「未鉴权拦截」）在
	// 没有这道闸时能把 docker logs 刷爆，而按 IP 合并对它无效。
	outBurst      = 30
	outWindowLen  = 10 * time.Second
	outSuppressMg = "门禁：%d 秒内事件过多，另有 %d 条没往标准输出打（内存里仍保留，见后台页「最近事件」）"

	// ---------- 历史日志落盘（1.8.0） ----------
	//
	// 内存环形缓冲只有 secLogMax 条、容器一重启就清空 —— 而安全事件恰好是最该
	// 留证据的东西（谁在什么时候失败了多少次、踢没踢过设备）。所以事件另写一份
	// JSON Lines 到门禁自己的数据卷，并配三道闸防写爆：
	//
	//	histRotateBytes  单文件超限就轮转（.1 → .2 → .3，最多 histRotKeep 份）
	//	histBurst        每 histWindowLen 窗口最多几行，超出的窗口结束补汇总行
	//	histThrottle     合并事件（同 IP 同类 30 秒重复）最多多久补写一行
	histRotateBytes = 8 << 20 // 默认 8 MB 一份
	histRotKeep      = 3
	histBurst        = 100
	histWindowLen    = 10 * time.Second
	histThrottle     = 30 * time.Second
	histSuppressMg   = "历史日志：本窗口事件过多，另有 %d 条被限速合并（重启后仍可查最近一条）"

	// 后台「历史日志」卡片的读取上限：只读文件末尾 histTailBytes 字节、
	// 最多渲染 histRowsMax 行，防止把 24 MB 的日志整个搬进一次页面渲染。
	histTailBytes = 256 << 10 // 256 KB
	histRowsMax   = 200

	// ---------- DSH 健康巡检（1.8.0） ----------
	// 连续 healthFails 次探不通才算「不可达」，单次拨号超时（网络抖动）不记事件。
	healthFails = 3
)

var (
	upstreamURL *url.URL
	pwHash     string
	totpSecret []byte
	secret     string
	siteTitle  string
	sessionDs  int
	needPw     bool
	needTotp   bool
	listenAddr string
	startedAt  = time.Now()

	// dshSessionDs 是门禁认定的 DSH 会话有效期（天）。DSH 的会话 Cookie 不透露
	// 自己的有效期，配一次票能用到什么时候只有门禁自己说了算（GATE_DSH_SESSION_DAYS）。
	dshSessionDs int

	// GitHub 登录用到两个基地址。抽出变量只为自测：e2e 用一个桩服务器
	// 顶替 github.com 与 api.github.com，否则这条流程没法在本地跑通。
	githubOAuthBase string
	githubAPIBase   string

	// GATE_USERNAME（1.9.0）：设置后登录多一个用户名维度（用户名+口令+动态验证码）。
	// 必须与 GATE_PASSWORD_HASH 同时配置，启动时校验。gateUserHash 是常量时间比对用的
	// 摘要，避免每次比对裸字符串。
	gateUser     string
	gateUserHash string

	// dshAutoKey（1.9.0）：DSH browser-session 签名密钥（GATE_DSH_SESSION_KEY，
	// 即 .credentials.yaml 里 client-connection/browser-session 的 32 字节 base64url secret）。
	// 配上它，门禁自己签发 dsh-auth-* 会话 Cookie——登录页不再要求用户去拿 DSH 令牌
	// （需求②「取消网关首页的 DSH 令牌获取，改为自动获取」）。未配置时保持旧行为。
	dshAutoKey []byte

	replayMu   sync.Mutex
	lastUsedCt uint64
)

// setCookie 下发一枚门禁自家的 Cookie（HttpOnly + SameSite=Lax，Secure 跟随实际协议）。
// maxAge 传负数即删除。
func setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
}

// ---------- 工具 ----------

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func hashPassword(pw string) string {
	sum := sha256.Sum256([]byte(pwSalt + ":" + pw))
	return hex.EncodeToString(sum[:])
}

func sign(payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func issueCookie() (string, int) {
	exp := time.Now().Add(time.Duration(sessionDs) * 24 * time.Hour).Unix()
	return signSession("v1", exp, sessionEpoch()), sessionDs * 86400
}

// signSession 拼「版本.过期.代数」三段并签名（不加代数段那半截签名 = 旧格式）。
// epoch 传 0 时输出旧三段式，让升级前发出的 Cookie 与新格式天然同域可验。
func signSession(ver string, exp int64, epoch int64) string {
	p := ver + "." + strconv.FormatInt(exp, 10)
	if epoch > 0 {
		p += "." + strconv.FormatInt(epoch, 10)
	}
	return p + "." + sign(p)
}

// issueSigned 生成「版本号.过期时间.签名」三段式 Cookie 值。
// ver 把不同用途的 Cookie 隔开（门禁会话 v1 / DSH 配对记录 d1）：格式与算法相同，
// 域不同则互相不能冒用 —— 拿 DSH 配对记录当门禁会话用会验签失败。
func issueSigned(ver string, days int) (string, int) {
	exp := time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	p := ver + "." + strconv.FormatInt(exp, 10)
	return p + "." + sign(p), days * 86400
}

// cookieValid 验签门禁会话，并核对「代数」。
//
// 1.8.0 起 Cookie 有两种形状，签名都盖在自己的完整前缀上，互相不能冒用：
//
//	v1.<exp>.<sig>          旧格式，按代数 0 算（升级前发的，继续认）
//	v1.<exp>.<epoch>.<sig>  新格式，epoch 必须等于当前代数
//
// 「踢光所有设备」把代数 +1：旧 Cookie（含没到期的）当场全部作废，
// 只有拿到新代 Cookie 的设备还能进门 —— 这正是用户点那个按钮要的效果。
func cookieValid(v string) bool {
	exp, ok := sessionSignedExp(v)
	return ok && time.Now().Unix() <= exp
}

// sessionSignedExp 验签解出门禁会话 Cookie 的过期时间与代数（不判过期，
// 代数不符直接判假）。调用方据此拒绝旧代 Cookie。
func sessionSignedExp(v string) (int64, bool) {
	parts := strings.Split(v, ".")
	if len(parts) < 3 || len(parts) > 4 || parts[0] != "v1" {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, false
	}
	epoch := int64(0)
	if len(parts) == 4 { // 新格式：第三段是代数
		epoch, err = strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return 0, false
		}
	}
	sig := parts[len(parts)-1]
	if !hmac.Equal([]byte(sign(strings.Join(parts[:len(parts)-1], "."))), []byte(sig)) {
		return 0, false
	}
	if epoch != sessionEpoch() {
		return 0, false
	}
	return exp, true
}

// sessionEpoch 读当前会话代数（配置文件里持久化，门禁重启不丢）。
func sessionEpoch() int64 {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return cfg.SessionEpoch
}

// signedExp 验签并解出过期时间（不判断是否过期，交给调用方）。
func signedExp(v, ver string) (int64, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != ver {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, false
	}
	if !hmac.Equal([]byte(sign(parts[0]+"."+parts[1])), []byte(parts[2])) {
		return 0, false
	}
	return exp, true
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// clientIP 取真实客户端 IP。
//
// ★ 必须取 X-Forwarded-For 的**最后一个**非空值，绝不能取第一个。
//   上游 nginx 用的是 $proxy_add_x_forwarded_for，语义是「客户端自带的值 + 真实 IP」，
//   也就是「不可信前缀 + 可信后缀」。取第一个 = 把攻击者随手写的字符串当成客户端身份，
//   于是 noteFail / lockRemaining 的「按 IP 锁定」可以靠每次换一个伪造值绕过：
//   2026-09-20 实测，同一个外部客户端伪造两个不同 IP，门禁日志记成两条「第 1 次」，
//   永远累加不到 5 次锁定，只剩全局限流（且会按伪造 IP 分桶、把真实记录挤出环形缓冲）。
//   取最后一个 = 取最近一跳可信代理看到的地址，那才是可信的那一个。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := strings.TrimSpace(parts[i]); ip != "" {
				return ip
			}
		}
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func sanitizeNext(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") ||
		strings.ContainsAny(v, "\r\n") || strings.Contains(v, "\\") {
		return "/"
	}
	return v
}

func humanDur(d time.Duration) string {
	m := int(d.Minutes()) + 1
	if m >= 60 {
		return fmt.Sprintf("%d 小时 %d 分钟", m/60, m%60)
	}
	return fmt.Sprintf("%d 分钟", m)
}

// ---------- TOTP（RFC 6238：SHA1 / 30s / 6 位） ----------

func totpAt(counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, totpSecret)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// verifyTOTP 返回该验证码所属的时间片；成功时同时做防重放
func verifyTOTP(input, ip string) (uint64, bool) {
	c := strings.TrimSpace(strings.ReplaceAll(input, " ", ""))
	if len(c) != totpDigits {
		return 0, false
	}
	now := int64(time.Now().Unix() / totpPeriod)
	for _, d := range []int64{0, -1, 1} {
		if now+d < 0 {
			continue
		}
		ct := uint64(now + d)
		if subtle.ConstantTimeCompare([]byte(totpAt(ct)), []byte(c)) != 1 {
			continue
		}
		replayMu.Lock()
		replayed := ct <= lastUsedCt
		replayMu.Unlock()
		if replayed {
			secNote("动态码重放", ip, "时间片 %d 已被使用", ct)
			return 0, false
		}
		return ct, true
	}
	return 0, false
}

// markTotpUsed 仅在整轮登录全部成功后才记账，
// 避免"码对了但后面的 DSH 令牌没填"把这一码白白作废
func markTotpUsed(ct uint64) {
	replayMu.Lock()
	if ct > lastUsedCt {
		lastUsedCt = ct
	}
	replayMu.Unlock()
}

// ---------- 防爆破 ----------

type ipState struct {
	fails       int
	until       time.Time
	windowStart time.Time
	windowFails int
}

var (
	limMu    sync.Mutex
	limM     = map[string]*ipState{}
	glMu     sync.Mutex
	glFails  []time.Time
)

func lockRemaining(ip string) (bool, time.Duration) {
	limMu.Lock()
	defer limMu.Unlock()
	s := limM[ip]
	if s == nil || s.until.IsZero() {
		return false, 0
	}
	if time.Now().Before(s.until) {
		return true, time.Until(s.until)
	}
	s.until = time.Time{}
	s.fails = 0
	return false, 0
}

func noteFail(ip string) (int, bool, time.Duration) {
	limMu.Lock()
	defer limMu.Unlock()
	now := time.Now()
	s := limM[ip]
	if s == nil {
		s = &ipState{windowStart: now}
		limM[ip] = s
	}
	if now.Sub(s.windowStart) > failWindow {
		s.windowStart = now
		s.windowFails = 0
	}
	s.fails++
	s.windowFails++
	switch {
	case s.windowFails >= hardFails:
		s.until = now.Add(hardLock)
		return s.fails, true, hardLock
	case s.fails >= maxFailures:
		s.until = now.Add(lockDuration)
		return s.fails, true, lockDuration
	}
	if len(limM) > 5000 { // 防止被大量伪造来源撑爆内存
		for k, v := range limM {
			if now.Sub(v.windowStart) > failWindow && now.After(v.until) {
				delete(limM, k)
			}
		}
	}
	return s.fails, false, 0
}

func clearFail(ip string) {
	limMu.Lock()
	delete(limM, ip)
	limMu.Unlock()
}

// globalDelay 全局限流：最近 10 分钟的失败越多，响应越慢
func globalDelay() time.Duration {
	glMu.Lock()
	defer glMu.Unlock()
	cut := time.Now().Add(-globalWindow)
	kept := glFails[:0]
	for _, t := range glFails {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	glFails = kept
	n := len(kept)
	if n > 8 {
		n = 8
	}
	d := baseDelay + time.Duration(n)*delayPerFail
	if d > maxDelay {
		d = maxDelay
	}
	return d
}

func noteGlobalFail() {
	glMu.Lock()
	glFails = append(glFails, time.Now())
	glMu.Unlock()
}

// ---------- 安全日志（内存环形缓冲，供 /__gate/admin 查看） ----------
//
// ponytail: 只存在内存里——gate 容器没有任何挂载卷（docker inspect Mounts 为空），
// 重启即清空。需要长期历史就先给 compose 的 gate 服务加一个卷，再落盘
// （注意 gate 以 nobody(65534) 运行，写宿主文件要配属主，别踩铁律 2）。
//
// 噪声控制（两层，都是「合并 + 限速」，不丢数据）：
//  1. 同一 IP 的同类事件在 secCoalesce 内合并为一条并累加次数，stdout 只在
//     「新事件」时写一行、且写回的是最近那一条匹配条目（不是只比队尾）；
//  2. stdout 另有硬闸：outWindowLen 内最多 outBurst 行，超出的在窗口结束时
//     汇总一行说明被压掉多少条——分布式扫描每个新 IP 都是一条新事件，第 1 层
//     对它无效，只有第 2 层能保证 docker logs 不被刷爆。
// ponytail: 内存环形缓冲也仍会被挤掉旧记录（上限 secLogMax 条），这是设计选择。

type secEvent struct {
	Time  time.Time
	Kind  string // 登录成功 / 验证失败 / 锁定 / 未鉴权拦截 ...
	IP    string
	Text  string
	Count int
}

var (
	secMu   sync.Mutex
	secLog  []secEvent // 最新的在最后一个
	secSeen int64      // 累计事件数（含被合并的）
)

// 标准输出的限速状态（见 logNote）
var (
	outMu         sync.Mutex
	outWindowAt   time.Time
	outWindowN    int
	outSuppressed int
)

// secMergeScan 是「往回找可合并的那一条」的扫描深度。
// 实践中同一 IP 的同类事件总是挨着的，20 条足够覆盖交错；扫描深度有界，
// 极端刷屏时也不会让一次 secNote 变成 O(缓冲长度)。
const secMergeScan = 20

// outDecision 是限速的全部策略，抽成纯函数只为可测（调用点只有 logNote）。
// 返回：这一行放不放行；以及窗口刚翻篇时该补打的那行汇总（没有就是空串）。
// 改 outWindowAt/outWindowN/outSuppressed，调用前须持有 outMu。
func outDecision(now time.Time) (allow bool, summary string) {
	if outWindowAt.IsZero() {
		outWindowAt = now
	}
	if now.Sub(outWindowAt) >= outWindowLen {
		if outSuppressed > 0 {
			summary = fmt.Sprintf(outSuppressMg, int(outWindowLen/time.Second), outSuppressed)
		}
		outWindowAt, outWindowN, outSuppressed = now, 0, 0
	}
	outWindowN++
	if outWindowN > outBurst {
		outSuppressed++
		return false, summary
	}
	return true, summary
}

// logNote 往标准输出写一行新事件，带限速。
//
// 环形缓冲挡得住重复请求（同 IP 同类合并），挡不住分布式扫描：每个新 IP 都是
// 一条新事件，一个窗口内能有上千条。所以这里再加一道闸：窗口内只放 outBurst 行，
// 其余攒到窗口结束时用一行汇总说清楚——既不静默丢，也不让 docker logs 被刷爆
// （内存与后台页一直是完整的）。
func logNote(kind, ip, text string) {
	outMu.Lock()
	allow, summary := outDecision(time.Now())
	outMu.Unlock()
	if summary != "" {
		log.Print(summary)
	}
	if allow {
		log.Printf("门禁：%s ip=%s %s", kind, ip, text)
	}
}

// secNote 记一条安全事件：进内存环形缓冲（供后台页），新事件另写一行标准输出。
//
// 合并规则：同一个 IP 的同类事件在 secCoalesce 内并成一条，**并回最近的那一条
// 匹配条目**，而不是只比对队尾——否则 A、B、A 这种交错会让同一个 IP 的同一类
// 事件各占一行，扫描器稍微错开一下就能绕过合并、把 300 条缓冲挤满。
func secNote(kind, ip, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	secMu.Lock()
	secSeen++
	merged := false
	if n := len(secLog); n > 0 {
		for i := n - 1; i >= 0 && i >= n-secMergeScan; i-- {
			e := &secLog[i]
			if e.Kind == kind && e.IP == ip && time.Since(e.Time) < secCoalesce {
				e.Count++
				e.Time = time.Now()
				e.Text = text
				merged = true
				break
			}
		}
	}
	if !merged {
		secLog = append(secLog, secEvent{Time: time.Now(), Kind: kind, IP: ip, Text: text, Count: 1})
		if len(secLog) > secLogMax {
			secLog = secLog[1:]
		}
	}
	secMu.Unlock()
	if !merged {
		logNote(kind, ip, text)
	}
	histAppend(kind, ip, text, merged) // 1.8.0：同步落盘（未启用时是空操作）
}

func secSnapshot() ([]secEvent, int64) {
	secMu.Lock()
	defer secMu.Unlock()
	out := make([]secEvent, len(secLog))
	copy(out, secLog)
	return out, secSeen
}

func humanUptime(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天 %d 小时", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时 %d 分钟", int(d.Minutes())/60, int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
}

// ---------- 历史日志落盘（1.8.0） ----------

// histRow 是磁盘上一行 JSON Lines 的形状。字段缩写只为省磁盘：一天上万行时
// "kind"/"ip"/"text" 比全名省 30% 体积。
type histRow struct {
	Time  time.Time `json:"t"`
	Kind  string    `json:"kind"`
	IP    string    `json:"ip"`
	Text  string    `json:"text"`
	Count int       `json:"count"`
}

var (
	histMu   sync.Mutex
	histF    *os.File // nil = 没启用（没配路径 / 目录不可写 / 写坏了）
	histPath string   // "" = 显式关闭
	histSize int64
	histWErr string // 打不开/写失败的原因，显示在后台页

	// 合并事件的节流账本：kind+ip → 上次真正落盘的时间与被攒下的条数。
	histLast    map[string]time.Time
	histDelta   map[string]int
	histWindowN int
	histWindowAt   time.Time
	histSuppressed int
	histWarned     bool

	// histRotateSize 单文件轮转阈值，可用 GATE_LOG_BYTES 覆盖（测试用小值）。
	histRotateSize int64 = histRotateBytes
)

// histOpen 打开（或关闭，path 为空时）历史日志文件。与配置目录同款降级策略：
// 打不开就整段关掉并把原因留在 histWErr，门禁照常工作 —— 日志永远不该挡住门。
func histOpen(path string) error {
	histMu.Lock()
	defer histMu.Unlock()
	histPath = path
	histLast = map[string]time.Time{}
	histDelta = map[string]int{}
	histWindowAt = time.Time{}
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		histWErr = err.Error()
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		histWErr = err.Error()
		return err
	}
	if st, err := f.Stat(); err == nil {
		histSize = st.Size()
	}
	histF, histWErr = f, ""
	return nil
}

// histDecision 是落盘限速的全部策略（与 outDecision 同构，独立窗口——
// 标准输出限的是 docker logs，这里限的是磁盘文件，两者互不干扰）。
// 返回：这一行放不放行；窗口刚翻篇时该补写的那条汇总行文案（没有就是空串）。
// 改窗口状态，调用前须持有 histMu。
func histDecision(now time.Time) (allow bool, summary string) {
	if histWindowAt.IsZero() {
		histWindowAt = now
	}
	if now.Sub(histWindowAt) >= histWindowLen {
		if histSuppressed > 0 {
			summary = fmt.Sprintf(histSuppressMg, histSuppressed)
		}
		histWindowAt, histWindowN, histSuppressed = now, 0, 0
	}
	histWindowN++
	if histWindowN > histBurst {
		histSuppressed++
		return false, summary
	}
	return true, summary
}

// histWriteLocked 写一行并按需轮转。调用前须持有 histMu 且 histF != nil。
func histWriteLocked(e histRow) error {
	if e.Count <= 0 {
		e.Count = 1
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := histF.Write(b); err != nil {
		histSetErr(err)
		return err
	}
	histSize += int64(len(b))
	if histSize >= histRotateSize {
		histRotateLocked()
	}
	return nil
}

// histRotateLocked 把 log.jsonl 挪成 .1（旧的 .1→.2、.2→.3，最多保留
// histRotKeep 份），再重开一个空文件。rename 是原子的，读侧最坏看到一次空。
func histRotateLocked() {
	if histF != nil {
		_ = histF.Close()
		histF = nil
	}
	base := histPath
	for i := histRotKeep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", base, i)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, fmt.Sprintf("%s.%d", base, i+1))
		}
	}
	_ = os.Rename(base, base+".1")
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		histSetErr(err)
		return
	}
	histF, histSize, histWErr = f, 0, ""
}

// histSetErr 记录写错误并只向标准输出告警一次（磁盘满时不能每行喊一嗓子）。
func histSetErr(err error) {
	histWErr = err.Error()
	if !histWarned {
		histWarned = true
		log.Printf("⚠️ 历史日志写失败，后续不再重复告警：%v", err)
	}
}

// histAppend 落一条事件（secNote 唯一调用点）。
//
// merged=false（新事件）直接写；merged=true（同 IP 同类合并进来的重复）最多
// histThrottle 补写一行，攒下的次数记进本行 Count —— 既不逐条写爆磁盘，
// 也不静默丢计数。无论哪种，都先过 histDecision 这道窗口闸。
func histAppend(kind, ip, text string, merged bool) {
	histMu.Lock()
	defer histMu.Unlock()
	if histF == nil {
		return
	}
	key := kind + "\x00" + ip
	now := time.Now()
	histDelta[key]++
	if merged {
		if last, ok := histLast[key]; ok && now.Sub(last) < histThrottle {
			return // 还没到该补写的时候，次数已在账上
		}
	}
	allow, summary := histDecision(now)
	if summary != "" {
		_ = histWriteLocked(histRow{Time: now, Kind: "落盘限速", IP: "-", Text: summary, Count: 1})
	}
	if !allow {
		return // 超限：本条留在 histDelta 里，窗口翻篇后随下一次写盘带出去
	}
	if err := histWriteLocked(histRow{Time: now, Kind: kind, IP: ip, Text: text, Count: histDelta[key]}); err != nil {
		return
	}
	histLast[key] = now
	histDelta[key] = 0
}

// histCombinedTail 把当前文件与轮转出去的 .histRotKeep…\.1 拼起来读尾部
//（旧在前、新在后，各自最多 histTailBytes）。只读当前文件的话，轮转一发生
// 页面就只剩新文件那几行——24MB 的历史全躺在旁边看不见，等于白留。
func histCombinedTail(path string) ([]byte, error) {
	var buf []byte
	for i := histRotKeep; i >= 1; i-- {
		b, err := readFileTail(fmt.Sprintf("%s.%d", path, i), histTailBytes)
		if err == nil {
			buf = append(buf, b...)
			buf = append(buf, '\n') // 文件间补分隔，防边界粘行
		}
	}
	b, err := readFileTail(path, histTailBytes)
	if err != nil {
		if len(buf) == 0 {
			return nil, err
		}
		return buf, nil
	}
	return append(buf, b...), nil
}

// histReadRows 读当前与轮转文件的尾部，按 q 过滤（事件/IP/说明
// 三处包含即中），返回最新在前的最多 histRowsMax 行。任何失败都返回空切片：
// 这是后台页的一张卡片，不该让整页渲染失败。
func histReadRows(q string) []adminEvent {
	histMu.Lock()
	path := histPath
	histMu.Unlock()
	if path == "" {
		return nil
	}
	data, err := histCombinedTail(path)
	if err != nil {
		return nil
	}
	q = strings.ToLower(strings.TrimSpace(q))
	var out []histRow
	for _, ln := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		var e histRow
		if ln == "" || json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Kind+" "+e.IP+" "+e.Text), q) {
			continue
		}
		out = append(out, e)
	}
	if len(out) > histRowsMax {
		out = out[len(out)-histRowsMax:]
	}
	rows := make([]adminEvent, 0, len(out))
	for i := len(out) - 1; i >= 0; i-- { // 最新在最上面，与「最近事件」一致
		e := out[i]
		rows = append(rows, adminEvent{
			Time: e.Time.Local().Format("2006-01-02 15:04:05"),
			Kind: e.Kind, Tone: toneOf(e.Kind, e.Text),
			IP: e.IP, Text: e.Text, Count: e.Count,
		})
	}
	return rows
}

// readFileTail 读文件末尾至多 max 字节；从中间开始读时丢掉第一条可能不完整的行。
func readFileTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	if off > 0 {
		if i := strings.IndexByte(string(buf), '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return buf, nil
}

// histSizeDesc 给后台页的一句话（未启用就说清楚原因）。
func histSizeDesc() (path, desc string) {
	histMu.Lock()
	defer histMu.Unlock()
	if histPath == "" {
		return "", "未启用"
	}
	if histF == nil {
		return histPath, "不可写：" + histWErr
	}
	switch {
	case histSize >= 1<<20:
		return histPath, fmt.Sprintf("%.1f MB", float64(histSize)/(1<<20))
	default:
		return histPath, fmt.Sprintf("%d KB", histSize>>10)
	}
}

// ---------- DSH 健康巡检（1.8.0） ----------

// healthState 记录「DSH 通不通」的观察史。抽出来只为可测：判断一次探活该不该
// 发事件（以及发哪种），是这个功能唯一的逻辑。
type healthState struct {
	mu     sync.Mutex
	seenUp bool   // 见过至少一次「通」
	down   bool   // 正处在「不可达」中
	downAt time.Time
	fails  int
}

// step 处理一次探活结果，返回该记事件的种类与文案（空串 = 不记）。
//
//	从未通过 → 首次通：「DSH 就绪」（门禁自己起来时 DSH 早就在跑，不是重启）
//	通 → 连续 healthFails 次不通：「DSH 不可达」（拨号抖动不记，记一次就停）
//	不可达 → 通：「DSH 重启」，带真实离线时长（不管是被谁重启的，都能查到）
func (h *healthState) step(ok bool, now time.Time) (kind, text string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ok {
		h.fails = 0
		if h.down {
			h.down = false
			return "DSH 重启", fmt.Sprintf("DSH 恢复在线（离线 %s）", now.Sub(h.downAt).Round(time.Second))
		}
		if !h.seenUp {
			h.seenUp = true
			return "DSH 就绪", "DSH 已就绪（端口探通）"
		}
		return "", ""
	}
	h.fails++
	if h.fails < healthFails {
		return "", ""
	}
	if !h.down {
		h.down = true
		h.downAt = now
		return "DSH 不可达", fmt.Sprintf("DSH 端口探不通（连续 %d 次）", h.fails)
	}
	return "", ""
}

var healthMonitor healthState
var healthInterval = 5 * time.Second // GATE_HEALTH_INTERVAL 秒；0 = 关闭

// healthLoop 周期拨一次上游端口。放在 goroutine 里，探活永远不该拖慢请求路径。
func healthLoop() {
	for {
		time.Sleep(healthInterval)
		if upstreamURL == nil {
			continue
		}
		if kind, text := healthMonitor.step(dshListening(), time.Now()); kind != "" {
			secNote(kind, "-", "%s", text)
		}
	}
}

// ---------- 与 DSH 交互（会话探测 / 令牌换票） ----------

func dshCall(r *http.Request, target string, withBrowserCookies bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	// ★ 必须保留原域名 Host：DSH 按 Host 计算会话 Cookie 的归属
	req.Host = r.Host
	req.Header.Set("Accept", "text/html")
	if withBrowserCookies {
		if ck := r.Header.Get("Cookie"); ck != "" {
			req.Header.Set("Cookie", ck)
		}
	}
	client := &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client.Do(req)
}

// dshHasSession 用浏览器带来的 Cookie 探一次 DSH：非 401 即视为已有有效会话
func dshHasSession(r *http.Request) bool {
	resp, err := dshCall(r, upstreamURL.String()+"/", true)
	if err != nil {
		secNote("探测 DSH 失败", clientIP(r), "%v", err)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	return resp.StatusCode != http.StatusUnauthorized
}

// dshAcceptsCookie 用指定 Cookie（而不是浏览器带来的）探一次 DSH。
// 自动获取模式下签完立刻验一次：密钥配错当场报错，不把坏 Cookie 发给浏览器。
func dshAcceptsCookie(r *http.Request, c *http.Cookie) bool {
	if upstreamURL == nil {
		return false
	}
	req, err := http.NewRequest(http.MethodGet, upstreamURL.String()+"/", nil)
	if err != nil {
		return false
	}
	req.Host = r.Host // ★ 与 dshCall 同理：DSH 按 Host 计算 Cookie 归属
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Cookie", c.Name+"="+c.Value)
	client := &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		secNote("探测 DSH 失败", clientIP(r), "%v", err)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	return resp.StatusCode != http.StatusUnauthorized
}

// dshPair 用启动令牌向 DSH 换取浏览器会话 Cookie
func dshPair(r *http.Request, token string) (*http.Cookie, error) {
	u := *upstreamURL
	u.Path = "/"
	u.RawQuery = url.Values{"token": {token}}.Encode()
	resp, err := dshCall(r, u.String(), false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("DSH 返回 %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "dsh-auth-") && c.Value != "" {
			return &http.Cookie{
				Name: c.Name, Value: c.Value, Path: "/",
				MaxAge: c.MaxAge, HttpOnly: true, Secure: isHTTPS(r),
				SameSite: http.SameSiteLaxMode,
			}, nil
		}
	}
	return nil, fmt.Errorf("DSH 未下发会话 Cookie")
}

// dshAuthority 复刻 DSH 侧的 requestAuthority：new URL("http://"+Host).host ——
// 主机名小写、去掉 :80 默认端口。Cookie 名与签名 payload 都绑这个值。
func dshAuthority(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(h, ":80")
}

// dshAutoSign 用 GATE_DSH_SESSION_KEY 自签一枚 DSH 会话 Cookie（需求②自动获取）：
// v1.<base64url(JSON)>.<base64url(HMAC-SHA256)>，HMAC 只覆盖 body 段，
// 与 dsh-client-connection 的 BrowserAuth 完全同构（算法已在探针上验证可签可验）。
func dshAutoSign(r *http.Request) (*http.Cookie, error) {
	if len(dshAutoKey) != 32 {
		return nil, fmt.Errorf("GATE_DSH_SESSION_KEY 未配置")
	}
	if upstreamURL == nil {
		return nil, fmt.Errorf("上游未就绪")
	}
	authority := dshAuthority(r.Host)
	if authority == "" {
		return nil, fmt.Errorf("Host 为空")
	}
	days := dshSessionDs
	if days > 30 {
		days = 30 // DSH 默认 maxAge 30 天；超了会被 DSH 自己拒掉
	}
	now := time.Now().UnixMilli()
	payload, err := json.Marshal(map[string]any{
		"version": 1, "authority": authority,
		"issuedAt": now, "expiresAt": now + int64(days)*86400_000,
	})
	if err != nil {
		return nil, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	m := hmac.New(sha256.New, dshAutoKey)
	m.Write([]byte(body))
	sum := sha256.Sum256([]byte(authority))
	return &http.Cookie{
		Name:  "dsh-auth-" + base64.RawURLEncoding.EncodeToString(sum[:]),
		Value: "v1." + body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)),
		Path:  "/", MaxAge: days * 86400,
		Expires:  time.Now().Add(time.Duration(days) * 24 * time.Hour),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}, nil
}

// ---------- 登录页 ----------

type loginView struct {
	Title        string
	Subtitle     string
	Tip          string
	Next         string
	Error        string
	Locked       bool
	Remain       string
	NeedPassword bool
	NeedTOTP     bool
	NeedUsername bool // 需求②：GATE_USERNAME 配置后多一个用户名框
	HasGitHub    bool
	HasSession   bool
	TokenNeeded  bool
	AutoPair     bool // 需求②：配了 GATE_DSH_SESSION_KEY → 不再显示令牌输入框
}

// subtitleOf / tipOf 都由「此刻实际可用的登录方式」算出来，所以后台一关掉某种
// 方式，登录页与后台页的说明文案立刻跟着变（不用重启）。
func subtitleOf() string {
	pw, totp, _ := loginModes()
	switch {
	case pw && totp:
		if gateUser != "" {
			return "需要用户名 + 口令 + 动态验证码"
		}
		return "需要口令 + 动态验证码"
	case totp:
		return "需要动态验证码"
	case pw:
		if gateUser != "" {
			return "需要用户名 + 口令"
		}
		return "需要访问口令"
	default:
		return "需要 GitHub 账号"
	}
}

func tipOf() string {
	pw, totp, _ := loginModes()
	if pw && totp {
		return "双因子保护 · 仅限本人使用"
	}
	if totp {
		return "受动态验证码保护 · 仅限本人使用"
	}
	if pw {
		if gateUser != "" {
			return "受用户名与口令保护 · 仅限本人使用"
		}
		return "受口令保护 · 仅限本人使用"
	}
	return "受 GitHub 账号与白名单保护 · 仅限本人使用"
}

// newLoginView 组装登录页数据（口令/动态码/GitHub/令牌四块由全局配置与探测结果决定）
func newLoginView(errMsg string, locked bool, remain time.Duration, next string, hasSession bool) loginView {
	pw, totp, gh := loginModes()
	auto := len(dshAutoKey) == 32 // 需求②：自动获取 DSH 会话已配置 → 令牌框整个撤掉
	return loginView{
		Title: siteTitle, Subtitle: subtitleOf(), Tip: tipOf(),
		Next: sanitizeNext(next), Error: errMsg, Locked: locked,
		Remain: humanDur(remain), NeedPassword: pw, NeedTOTP: totp, HasGitHub: gh,
		HasSession: hasSession, TokenNeeded: !hasSession && !auto, AutoPair: auto,
		NeedUsername: gateUser != "",
	}
}

// loginBytes 渲染登录页。抽出来是为了让「上游 401 就地换成登录页」复用同一份模板，
// 避免出现第二处 template.Execute（见 sessionExpiredResponse）。
func loginBytes(v loginView) []byte {
	var b bytes.Buffer
	_ = loginTpl.Execute(&b, v)
	return b.Bytes()
}

func renderLogin(w http.ResponseWriter, status int, errMsg string, locked bool, remain time.Duration, next string, hasSession bool) {
	body := loginBytes(newLoginView(errMsg, locked, remain, next, hasSession))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	if r.Method != http.MethodPost {
		next := sanitizeNext(r.URL.Query().Get("next"))
		if locked, rem := lockRemaining(ip); locked {
			renderLogin(w, http.StatusTooManyRequests, "", true, rem, next, false)
			return
		}
		renderLogin(w, http.StatusOK, "", false, 0, next, dshHasSession(r))
		return
	}

	_ = r.ParseForm()
	next := sanitizeNext(r.FormValue("next"))

	if locked, rem := lockRemaining(ip); locked {
		secNote("锁定期间尝试", ip, "仍在锁定期内，剩余 %s", humanDur(rem))
		renderLogin(w, http.StatusTooManyRequests, "", true, rem, next, false)
		return
	}
	hasSession := dshHasSession(r)

	fail := func(msg string) {
		time.Sleep(globalDelay())
		noteGlobalFail()
		n, lockedNow, dur := noteFail(ip)
		if lockedNow {
			secNote("锁定", ip, "失败达上限，锁定 %s", humanDur(dur))
			renderLogin(w, http.StatusTooManyRequests, "", true, dur, next, hasSession)
			return
		}
		secNote("验证失败", ip, "第 %d 次：%s", n, msg)
		renderLogin(w, http.StatusUnauthorized, fmt.Sprintf("%s，还可尝试 %d 次", msg, maxFailures-n), false, 0, next, hasSession)
	}

	// GitHub-only 模式（口令与动态验证码都关掉）下，这个表单里没有任何本地凭据可验，
	// 只能拿 DSH 令牌补一次配对；★绝不能因为「提交了令牌」就发出门禁 Cookie，
	// 否则任何人只要拿到 DSH 令牌就能进后台（那等于把两层并成一层）。
	if pw, totp, _ := loginModes(); !pw && !totp {
		token := strings.TrimSpace(r.FormValue("dstoken"))
		if token == "" {
			if hasSession {
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
			// 需求②：自动获取（GitHub-only 模式下同样能自己签出会话）
			if c, err := dshAutoSign(r); err == nil {
				if !dshAcceptsCookie(r, c) {
					secNote("自动获取失败", ip, "自签的会话 Cookie 不被 DSH 接受（GATE_DSH_SESSION_KEY 与 DSH 不匹配？）")
					fail("自动获取 DSH 会话失败（GATE_DSH_SESSION_KEY 配置不匹配）")
					return
				}
				http.SetCookie(w, c)
				secNote("自动获取 DSH 会话", ip, "门禁自签会话 Cookie（GitHub-only 模式）")
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
			renderLogin(w, http.StatusUnauthorized, func() string {
				if len(dshAutoKey) == 32 {
					return "自动获取 DSH 会话失败（GATE_DSH_SESSION_KEY 未配置或上游未就绪）"
				}
				return "本设备还没有 DSH 会话，请在下方填写 DSH 令牌"
			}(), false, 0, next, false)
			return
		}
		pairCookie, err := dshPair(r, token)
		if err != nil {
			secNote("令牌换票失败", ip, "%v", err)
			fail("DSH 令牌不正确或已失效（DSH 重启后旧令牌即作废）")
			return
		}
		http.SetCookie(w, pairCookie)
		secNote("令牌换票成功", ip, "已换取 DSH 会话 Cookie（当前登录方式只认 GitHub，未发门禁 Cookie）")
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	if needPw {
		// 需求②：配了 GATE_USERNAME 就先验用户名；两项合成一句提示，不透露错在哪一项
		if gateUser != "" {
			gotUser := hashPassword("u:" + r.FormValue("username"))
			if subtle.ConstantTimeCompare([]byte(gotUser), []byte(gateUserHash)) != 1 {
				fail("用户名或口令不正确")
				return
			}
		}
		got := hashPassword(r.FormValue("password"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(pwHash)) != 1 {
			if gateUser != "" {
				fail("用户名或口令不正确")
			} else {
				fail("口令不正确")
			}
			return
		}
	}
	var totpCt uint64
	if totpOn() {
		ct, ok := verifyTOTP(r.FormValue("code"), ip)
		totpCt = ct
		if !ok {
			if needPw {
				fail("口令或动态验证码不正确") // 双因子模式下不透露是哪一项错
			} else {
				fail("动态验证码不正确")
			}
			return
		}
	}

	// DSH 会话：本设备已有有效会话时什么都不用做；没有则优先自动获取（需求②），
	// 自动获取未配置时退回老路——必须提供令牌并当场换票配对。
	token := strings.TrimSpace(r.FormValue("dstoken"))
	if token == "" {
		if !hasSession {
			if c, err := dshAutoSign(r); err == nil {
				if !dshAcceptsCookie(r, c) {
					secNote("自动获取失败", ip, "自签的会话 Cookie 不被 DSH 接受（GATE_DSH_SESSION_KEY 与 DSH 不匹配？）")
					fail("自动获取 DSH 会话失败（GATE_DSH_SESSION_KEY 配置不匹配）")
					return
				}
				http.SetCookie(w, c)
				secNote("自动获取 DSH 会话", ip, "门禁自签会话 Cookie（GATE_DSH_SESSION_KEY）")
			} else {
				time.Sleep(baseDelay)
				msg := "本设备还没有 DSH 会话，请在下方填写 DSH 令牌"
				if len(dshAutoKey) == 32 {
					// 自动获取模式下页面没有令牌框，别指向一个不存在的输入栏。
					msg = "自动获取 DSH 会话失败（GATE_DSH_SESSION_KEY 未配置或上游未就绪）"
				}
				renderLogin(w, http.StatusUnauthorized, msg, false, 0, next, false)
				return
			}
		}
	} else {
		pairCookie, err := dshPair(r, token)
		if err != nil {
			secNote("令牌换票失败", ip, "%v", err)
			fail("DSH 令牌不正确或已失效（DSH 重启后旧令牌即作废）")
			return
		}
		http.SetCookie(w, pairCookie)
		secNote("令牌换票成功", ip, "已换取 DSH 会话 Cookie")
	}
	if totpOn() {
		markTotpUsed(totpCt)
	}

	clearFail(ip)
	val, maxAge := issueCookie()
	setCookie(w, r, cookieName, val, maxAge)
	stampDSHSession(w, r) // 记下配对时间，后台页据此显示 DSH 会话剩余有效期
	secNote("登录成功", ip, "方式=%s", subtitleOf())
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	secNote("登出", clientIP(r), "已退出登录，门禁 Cookie 已清除")
	setCookie(w, r, cookieName, "", -1)
	http.Redirect(w, r, gatePrefix+"/login", http.StatusSeeOther)
}

// ---------- 后台：安全日志页 ----------

// adminHTML 直接内嵌在 main.go 里（而不是像 login.html 那样单独一个文件）：
// gate/Dockerfile 与 scripts/github-publish.sh 各自都有一份「要复制的文件清单」，
// 少写一处就会出现「本地有、镜像/仓库里没有」的漂移。少一个文件少一个坑。
const adminHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · 安全日志</title>
<style>
:root{
  --bg1:#0b1020; --bg2:#141b36; --card:rgba(255,255,255,.075); --cardb:rgba(255,255,255,.16);
  --fg:#eef2ff; --muted:#a5b0d4; --accent:#6d8bff; --accent2:#9b6dff;
  --ok:#5ad39a; --warn:#ffb547; --err:#ff8098;
  --shadow:0 24px 70px rgba(0,0,0,.5);
}
@media (prefers-color-scheme: light){
  :root{ --bg1:#eef1f8; --bg2:#dde5f6; --card:rgba(255,255,255,.72); --cardb:rgba(255,255,255,.95);
         --fg:#161d33; --muted:#5b6689; --accent:#3f5bd6; --accent2:#7a4fd6;
         --ok:#0f9d58; --warn:#b06a00; --err:#d3304f; --shadow:0 20px 55px rgba(30,45,90,.18); }
}
*{box-sizing:border-box}
body{
  margin:0;padding:26px 20px 40px;min-height:100vh;color:var(--fg);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,sans-serif;
  background:
    radial-gradient(900px 520px at 10% -6%, rgba(109,139,255,.28), transparent 60%),
    radial-gradient(760px 520px at 92% 104%, rgba(155,109,255,.24), transparent 60%),
    linear-gradient(160deg,var(--bg1),var(--bg2));
  background-attachment:fixed;
}
.wrap{max-width:1060px;margin:0 auto}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:12px;flex:1 1 260px}
.dot{width:11px;height:11px;border-radius:50%;flex:0 0 auto;
  background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 0 0 5px rgba(109,139,255,.16)}
h1{font-size:17px;margin:0;letter-spacing:.3px}
h1 small{display:block;color:var(--muted);font-weight:400;font-size:12px;margin-top:3px}
.actions{display:flex;gap:9px;flex-wrap:wrap}
.btn{display:inline-block;text-decoration:none;padding:9px 14px;border-radius:11px;font-size:13px;font-weight:600;
  color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));border:1px solid transparent;
  transition:filter .15s, transform .12s}
.btn:hover{filter:brightness(1.08)}
.btn:active{transform:translateY(1px)}
.btn.ghost{color:var(--fg);background:var(--card);border-color:var(--cardb);font-weight:500}
.btn.danger{color:var(--err)}
button.btn{font-family:inherit;font-size:13px;cursor:pointer}
button.btn:disabled{opacity:.55;cursor:default;filter:none}
.restartbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:15px}
.restartbar .muted{flex:1 1 280px;min-width:210px}
.actions form{margin:0;display:flex}
.restartline{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 16px}
.logtool{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 10px}
.chip{padding:4px 11px;border-radius:999px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;
  color:var(--muted);background:var(--card);border:1px solid var(--cardb)}
.chip[aria-pressed=true]{color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent}
table.filter-bad tr[data-tone=ok],table.filter-bad tr[data-tone=info]{display:none}
.card{background:var(--card);border:1px solid var(--cardb);border-radius:18px;padding:18px 20px;margin-bottom:16px;
  box-shadow:var(--shadow);
  -webkit-backdrop-filter:blur(16px) saturate(140%);backdrop-filter:blur(16px) saturate(140%)}
.card h2{font-size:12.5px;margin:0 0 12px;color:var(--muted);font-weight:600;letter-spacing:.4px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px 18px}
.stat b{display:block;color:var(--muted);font-size:11.5px;font-weight:500;margin-bottom:3px}
.stat span{font-size:13.5px;word-break:break-word}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;margin:2px 4px 2px 0;
  color:var(--warn);background:rgba(255,181,71,.14);border:1px solid rgba(255,181,71,.3)}
.tablewrap{overflow-x:auto;margin:0 -4px}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:620px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--cardb);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.4px;white-space:nowrap}
tbody tr:hover{background:rgba(125,145,255,.06)}
td.t{white-space:nowrap;color:var(--muted);font-variant-numeric:tabular-nums}
td.ip{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
td.n{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;white-space:nowrap;border:1px solid transparent}
.badge-ok{color:var(--ok);background:rgba(90,211,154,.14);border-color:rgba(90,211,154,.3)}
.badge-err{color:var(--err);background:rgba(255,128,152,.14);border-color:rgba(255,128,152,.3)}
.badge-warn{color:var(--warn);background:rgba(255,181,71,.14);border-color:rgba(255,181,71,.3)}
.badge-info{color:var(--muted);background:rgba(125,145,255,.12);border-color:var(--cardb)}
.empty{color:var(--muted);text-align:center;padding:22px 0}
.muted{color:var(--muted);font-size:12.5px}
.foot{text-align:center;font-size:11.5px;color:var(--muted);margin-top:6px}
.foot a{color:var(--muted)}
details{border-radius:12px}
summary{cursor:pointer;font-size:12.5px;color:var(--muted);font-weight:600;letter-spacing:.4px;
  list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸";font-size:12px;transition:transform .15s}
details[open] summary::before{transform:rotate(90deg)}
details[open] summary{margin-bottom:12px}
.steps{margin:0 0 14px;padding-left:20px;color:var(--muted);font-size:12.5px;line-height:1.75}
.steps code,.muted code{color:var(--fg);background:rgba(125,145,255,.14);padding:1px 6px;border-radius:6px;word-break:break-all}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px 16px;align-items:end}
.grid2 label{display:block;color:var(--muted);font-size:12px}
.grid2 label.wide{grid-column:1/-1}
.grid2 label.chk{color:var(--fg);font-size:13px;display:flex;align-items:center;gap:8px;margin-bottom:4px}
input[type=text],input[type=password],input:not([type]){
  width:100%;margin-top:5px;padding:9px 11px;border-radius:10px;font:inherit;font-size:13px;
  color:var(--fg);background:rgba(125,145,255,.10);border:1px solid var(--cardb)}
input:focus{outline:none;border-color:var(--accent);background:rgba(125,145,255,.18)}
.banner{margin-bottom:16px;color:var(--fg);background:rgba(90,211,154,.16);border-color:rgba(90,211,154,.4)}
.auto{display:flex;align-items:center;gap:6px;cursor:pointer}
.auto input{width:auto;margin:0}
@media (max-width:520px){
  body{padding:18px 13px 30px}
  .card{padding:15px 14px;border-radius:15px}
  .btn{padding:8px 11px;font-size:12.5px}
}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="brand">
    <span class="dot"></span>
    <h1>{{.Title}} · 安全日志<small>v{{.Version}} · 已运行 {{.Uptime}}</small></h1>
  </div>
  <nav class="actions">
    <form method="post" action="/__gate/restart"><button class="btn" type="submit"{{if .RestartBusy}} disabled{{end}} title="重启 DSH：会中断正在进行的对话约 30 秒">重启 DSH</button></form>
    <label class="muted auto"><input type="checkbox" id="gauto"> 自动刷新</label>
    <a class="btn" href="/" target="_blank" rel="noopener">进入 DSH ↗</a>
    <a class="btn ghost" href="/__gate/admin">立即刷新</a>
    <a class="btn ghost danger" href="/__gate/logout">退出登录</a>
  </nav>
</header>

<div class="restartline">
  <span class="badge badge-{{if .RestartBusy}}warn{{else}}ok{{end}}">{{if .RestartBusy}}重启进行中{{else}}可重启{{end}}</span>
  <span class="muted">最近一次发起：{{if .RestartAt}}{{.RestartAt}}{{else}}还没有{{end}} · 结果：{{if .RestartResult}}{{.RestartResult}}{{else}}—{{end}}</span>
  <span class="muted">装了插件、改了配置要重启才生效时用这个按钮；会中断正在进行的对话约 30 秒，进度就写在这一行，配合「自动刷新」盯着看。</span>
</div>

{{if .Msg}}<div class="card banner">{{.Msg}}</div>{{end}}

<div class="card">
  <h2>当前状态</h2>
  <div class="stats">
    <div class="stat"><b>登录方式</b><span>{{.Mode}}</span></div>
    <div class="stat"><b>本设备会话</b><span>剩余 {{.SessionLeft}}</span></div>
    <div class="stat"><b>监听 → 上游</b><span>{{.Listen}} → {{.Upstream}}</span></div>
    <div class="stat"><b>事件计数</b><span>累计 {{.Total}} 条（合并后显示 {{.Shown}} 行）</span></div>
    <div class="stat"><b>全局限流</b><span>当前响应延迟 {{.Delay}}</span></div>
    <div class="stat"><b>锁定中的 IP</b><span>{{if .Locks}}{{range .Locks}}<span class="pill">{{.IP}} · 剩余 {{.Until}} · 失败 {{.Fails}} 次</span>{{end}}{{else}}无{{end}}</span></div>
    <div class="stat"><b>DSH 状态</b><span>{{if .DshUp}}<span class="badge badge-ok">正常</span>{{else}}<span class="badge badge-err">连不上</span>{{end}} · 内存内上游错误 {{.UpErrCount}} 条 · DSH 重启 {{.RestartCount}} 次</span></div>
    <div class="stat"><b>应用市场</b><span>{{if .MarketVer}}{{.MarketVer}}{{else if .MarketFetching}}<span class="badge badge-info">获取中…</span>{{else}}—{{end}} · 可更新 {{.UpdateCount}} 个 · 快照 {{.SnapshotCount}} 份</span></div>
    <div class="stat"><b>DSH 版本</b><span>{{if .DSHVer}}<span class="badge badge-ok">{{.DSHVer}}</span>{{else if .DSHVerFetching}}<span class="badge badge-info">获取中…</span>{{else}}<span class="badge badge-info">未取到</span>{{end}} · 检测结果缓存 10 分钟</span></div>
    {{if .MarketBusy}}<div class="stat"><b>市场正在跑</b><span>{{.MarketPhase}} · {{.MarketLine}}</span></div>{{end}}
  </div>
</div>

<div class="card">
  <h2>登录方式（至少保留一种；关闭动态密码前必须先配好 GitHub 登录）</h2>
  <div class="stats">
    <div class="stat"><b>动态验证码</b><span>{{if not .TOTPConfigured}}<span class="badge badge-info">未配置密钥</span>{{else if .TOTPOn}}<span class="badge badge-ok">开启</span>{{else}}<span class="badge badge-info">已关闭</span>{{end}}</span></div>
    <div class="stat"><b>GitHub 登录</b><span>{{if .GitHubReady}}<span class="badge badge-ok">开启</span>{{else if .GitHubEnabled}}<span class="badge badge-warn">已勾开启但配置不全</span>{{else}}<span class="badge badge-info">未开启</span>{{end}}</span></div>
    <div class="stat"><b>访问口令</b><span>{{if .PwOn}}<span class="badge badge-ok">开启</span>{{else}}<span class="badge badge-info">未配置</span>{{end}}</span></div>
  </div>
  {{if .TOTPConfigured}}<form method="post" action="/__gate/methods" class="restartbar">
    <button class="btn ghost" type="submit" name="totp" value="{{if .TOTPOn}}off{{else}}on{{end}}">{{if .TOTPOn}}关闭动态验证码登录{{else}}开启动态验证码登录{{end}}</button>
    <span class="muted">改完立即生效，不用重启。密钥由服务器上的 <code>scripts/set-totp.sh</code> 生成，换密钥才会让现有验证码失效。</span>
  </form>{{else}}<p class="muted">还没配动态验证码。服务器上执行 <code>bash /opt/dshai/scripts/set-totp.sh</code> 生成密钥即可。</p>{{end}}
</div>

<div class="card">
  <details id="ghsec"{{if not .GitHubConfigured}} open{{end}}>
  <summary>GitHub 登录（手动配置）— {{if .GitHubConfigured}}已配置（{{if .GitHubEnabled}}开启中{{else}}未开启{{end}}），点这一行改{{else}}还没配好，点这一行展开设置{{end}}</summary>
  <ol class="steps">
    <li>打开 <a href="https://github.com/settings/developers" target="_blank" rel="noopener">GitHub → Settings → Developer settings → OAuth Apps → New OAuth App</a>。</li>
    <li>Application name 随便填，例如 <code>DSH 门禁</code>。</li>
    <li>Homepage URL 填 <code>{{.BaseURL}}</code>。</li>
    <li><b>Authorization callback URL 必须一字不差地填 <code>{{.CallbackURL}}</code></b>，差一个字符都会登录失败。</li>
    <li>点 Register application，复制 <b>Client ID</b>；再点 Generate a new client secret，复制密钥（只显示一次）。</li>
    <li>把两项粘到下面，允许名单填你自己的 GitHub 用户名（或数字 ID），勾上「开启 GitHub 登录」再保存。</li>
  </ol>
  <form method="post" action="/__gate/github" class="grid2">
    <label>Client ID<input name="clientId" value="{{.GitHubClientID}}" autocomplete="off" spellcheck="false" placeholder="Ov23li…"></label>
    <label>Client secret<input name="clientSecret" type="password" autocomplete="new-password" placeholder="{{if .GitHubSecretSet}}已保存（留空＝不修改）{{else}}粘贴 GitHub 给的密钥{{end}}"></label>
    <label class="wide">允许登录的 GitHub 账号（用户名或数字 ID，逗号 / 空格分隔）
      <input name="allow" value="{{.GitHubAllow}}" autocomplete="off" spellcheck="false" placeholder="your-name, 1234567"></label>
    <label class="chk"><input type="checkbox" name="enabled" value="1"{{if .GitHubEnabled}} checked{{end}}> 开启 GitHub 登录</label>
    <div><button class="btn" type="submit">保存 GitHub 配置</button></div>
  </form>
  <p class="muted">密钥只写进门禁自己的配置文件（<code>{{.StatePath}}</code>，权限 600），后台页永远只显示「已保存」，不回显原文。{{if not .StateWritable}}<b>警告：配置目录不可写，这里改的东西重启后会丢。</b>{{end}}</p>
  </details>
</div>

<div class="card">
  <h2>DSH 会话（门禁认定的有效期：{{.DSHDays}} 天）</h2>
  <div class="stats">
    <div class="stat"><b>本设备 DSH 会话</b><span>{{if .DSHOK}}<span class="badge badge-ok">有效</span>{{else}}<span class="badge badge-err">已失效或超出门禁有效期</span>{{end}}</span></div>
    <div class="stat"><b>配对记录剩余</b><span>{{.DSHLeft}}</span></div>
  </div>
  <form method="post" action="/__gate/repair" class="restartbar">
    <input name="dstoken" autocomplete="off" spellcheck="false" style="flex:1 1 300px;min-width:200px" placeholder="粘贴 DSH 令牌">
    <button class="btn" type="submit">配对并登录</button>
  </form>
  <p class="muted">DSH 重启后旧令牌作废、会话也可能失效；在这里粘一次最新令牌即可，不用重走登录流程。取令牌：<code>docker logs dshai-web 2>&1 | grep -o 'token=[A-Za-z0-9_-]*' | tail -1</code></p>
</div>

<div class="card">
  <h2>登录设备</h2>
  <form method="post" action="/__gate/logout-all" class="restartbar" onsubmit="return confirm('踢光所有设备？所有已登录的浏览器（包括本机）都要重新登录一次，本机会自动续上。')">
    <button class="btn ghost danger" type="submit">踢光所有设备</button>
    <span class="muted">怀疑有别的浏览器还登着、或口令/验证码泄露过，按这个按钮：全体旧登录立即作废、其它设备回到登录页，本机自动续上，DSH 配对不受影响。{{if .Epoch}}已踢过 {{.Epoch}} 轮。{{end}}</span>
  </form>
</div>

<div class="card">
  <details id="plugsec">
  <summary>插件管理（经应用市场执行；安装/更新是长任务，点完回本页看进度）— 点这一行展开/收起</summary>
  <div class="restartline">
    <span class="badge badge-{{.OpTone}}">{{if .OpRunning}}{{.Op}}进行中{{else if .OpAt}}上次：{{.Op}}{{else}}还没操作过{{end}}</span>
    <span class="muted">{{if .OpAt}}{{.OpAt}} · {{.OpResult}}{{end}}</span>
    {{if .MarketBusy}}<span class="badge badge-warn">市场忙</span><span class="muted">{{.MarketPhase}} · {{.MarketLine}}</span>{{end}}
    <form method="post" action="/__gate/market" style="display:inline">
      <input type="hidden" name="op" value="refresh">
      <button class="btn ghost" type="submit">{{if .MarketFetching}}正在获取…{{else}}手动检测刷新{{end}}</button>
    </form>
  </div>
  <form method="post" action="/__gate/market" class="restartbar">
    <input type="hidden" name="op" value="install">
    <input name="url" style="flex:1 1 340px;min-width:220px" placeholder="粘贴插件地址 https://…（必须是市场精选列表里的地址）" autocomplete="off" spellcheck="false">
    <button class="btn" type="submit">安装</button>
  </form>
  {{if .Plugins}}
  <div class="tablewrap"><table>
    <thead><tr>
      <th scope="col">插件</th><th scope="col">更新</th><th scope="col">状态</th><th scope="col" style="text-align:right">操作</th>
    </tr></thead>
    <tbody>
    {{range .Plugins}}<tr>
      <td><b>{{.Name}}</b><div class="muted" style="font-size:11.5px">{{.Spec}}</div></td>
      <td>{{if .Updatable}}<span class="badge badge-warn">{{.Latest}} 可更新</span>{{else}}{{if $.UpdatesOK}}<span class="badge badge-ok">已最新</span>{{else if $.MarketFetching}}<span class="badge badge-info">获取中…</span>{{else}}<span class="badge badge-info">未知</span>{{end}}{{end}}</td>
      <td>{{if .Disabled}}<span class="badge badge-info">已停用</span>{{else}}<span class="badge badge-ok">启用中</span>{{end}}</td>
      <td style="white-space:nowrap;text-align:right">
        <form method="post" action="/__gate/market" style="display:inline">
          <input type="hidden" name="op" value="toggle">
          <input type="hidden" name="name" value="{{.Name}}">
          <input type="hidden" name="enabled" value="{{if .Disabled}}1{{else}}0{{end}}">
          <button class="btn ghost" type="submit">{{if .Disabled}}启用{{else}}停用{{end}}</button>
        </form>
        {{if .Updatable}}<form method="post" action="/__gate/market" style="display:inline">
          <input type="hidden" name="op" value="update">
          <input type="hidden" name="name" value="{{.Name}}">
          <button class="btn" type="submit">更新</button>
        </form>{{end}}
        <form method="post" action="/__gate/market" style="display:inline" onsubmit="return confirm('确定卸载 {{.Name}}？页面上它提供的功能会消失。')">
          <input type="hidden" name="op" value="uninstall">
          <input type="hidden" name="name" value="{{.Name}}">
          <button class="btn ghost danger" type="submit">卸载</button>
        </form>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table></div>
  {{else if .MarketFetching}}<p class="empty">正在获取插件列表…（取到后本页会自动刷新显示）</p>
  {{else}}<p class="empty">{{if .PluginsErr}}{{.PluginsErr}}{{else}}没有读到插件列表{{end}}</p>{{end}}
  <p class="muted">装完/更完多数要重启 DSH 才生效（页顶「重启 DSH」）。被市场拒绝时，这一行会直接写出原因；每次操作也会记进安全日志。</p>
  </details>
</div>

<div class="card">
  <details id="logsec">
  <summary>最近事件（累计 {{.Total}} 条，合并后 {{.Shown}} 行{{if .Older}}，更早的 {{.Older}} 行没列出{{end}}；{{.Stats}}）— 点这一行展开/收起</summary>
  <div class="logtool">
    <button class="chip" type="button" data-f="all">全部</button>
    <button class="chip" type="button" data-f="bad">只看异常（失败 / 拦截）</button>
    <span class="muted" id="logfilterhint"></span>
  </div>
  <div class="tablewrap"><table id="logtable">
    <thead><tr>
      <th scope="col">时间</th><th scope="col">事件</th><th scope="col">来源 IP</th><th scope="col">说明</th><th scope="col" style="text-align:right">次数</th>
    </tr></thead>
    <tbody>
    {{range .Events}}<tr data-tone="{{.Tone}}">
      <td class="t">{{.Time}}</td>
      <td><span class="badge badge-{{.Tone}}">{{.Kind}}</span></td>
      <td class="ip">{{.IP}}</td>
      <td>{{.Text}}</td>
      <td class="n">{{.Count}}</td>
    </tr>
    {{else}}<tr><td colspan="5" class="empty">还没有记录。上面的动作都会出现在这里。</td></tr>
    {{end}}
    </tbody>
  </table></div>
  <p class="muted">最新在上；同一 IP 的同类事件 {{.Coalesce}} 秒内合并成一条并累加次数（中间夹了别的事件也照样并回最近那一条）。「只看异常」只是筛掉成功与中性行，统计数字不变。标准输出（<code>docker logs</code>）每 {{.OutWindow}} 秒最多打 {{.OutBurst}} 行新事件，超过的只在窗口结束时汇总一行——这张表始终是完整的。</p>
  </details>
</div>

<div class="card">
  <details id="histsec">
  <summary>历史日志（落盘 {{if .LogPath}}已开 · {{.LogSize}} · {{.LogRotate}}{{else}}未启用{{end}}）— 点这一行展开/收起</summary>
  <form method="get" action="/__gate/admin" class="logtool">
    <input name="q" value="{{.HistQuery}}" placeholder="关键词：事件 / IP / 说明，回车搜索" style="flex:1 1 260px;min-width:180px" autocomplete="off">
    <button class="btn ghost" type="submit">搜索</button>
    {{if .HistQuery}}<a class="btn ghost" href="/__gate/admin">清除</a>{{end}}
  </form>
  {{if .LogPath}}<p class="muted">文件 <code>{{.LogPath}}</code>；搜索从文件末尾往回读最近一段，最多列 {{.HistCap}} 行（最新在上）。</p>{{end}}
  <div class="tablewrap"><table>
    <thead><tr>
      <th scope="col">时间</th><th scope="col">事件</th><th scope="col">来源 IP</th><th scope="col">说明</th><th scope="col" style="text-align:right">次数</th>
    </tr></thead>
    <tbody>
    {{range .Hist}}<tr data-tone="{{.Tone}}">
      <td class="t">{{.Time}}</td>
      <td><span class="badge badge-{{.Tone}}">{{.Kind}}</span></td>
      <td class="ip">{{.IP}}</td>
      <td>{{.Text}}</td>
      <td class="n">{{.Count}}</td>
    </tr>
    {{else}}<tr><td colspan="5" class="empty">{{if .LogPath}}没有匹配的记录。{{else}}落盘未启用：给门禁设 <code>GATE_LOG</code> 指向可写文件即可长期留痕（默认在状态文件同目录 log.jsonl）。{{end}}</td></tr>
    {{end}}
    </tbody>
  </table></div>
  <p class="muted">上面「最近事件」只在内存里、重启就没；这张表来自落盘文件，重启后照样能翻。落盘每窗口限速写入，被限速的合并事件只累加计数、窗口结束补一条汇总——信息不丢，只是少写几行。文件写不进去时会在启动日志里告警，页面也能看到。</p>
  </details>
</div>

<div class="foot">内存里最近 {{.Max}} 条{{if .LogPath}}；历史日志落盘 <code>{{.LogPath}}</code>，重启不丢{{else}}，容器重启即清空{{end}} · 短地址 <a href="/gate">/gate</a></div>
</div>
<script>
(function(){
  var LOG='dshai_admin_log_open', AUTO='dshai_admin_auto', FILTER='dshai_admin_log_filter';
  function ls(k,v){ try{ if(v===undefined){return localStorage.getItem(k);} localStorage.setItem(k,v); }catch(e){ return null; } }
  var d=document.getElementById('logsec');
  if(ls(LOG)==='1'){ d.open=true; }
  d.addEventListener('toggle',function(){ ls(LOG, d.open?'1':'0'); });
  var hs=document.getElementById('histsec');
  if(ls('dshai_admin_hist_open')==='1'){ hs.open=true; }
  hs.addEventListener('toggle',function(){ ls('dshai_admin_hist_open', hs.open?'1':'0'); });
  // 插件管理默认折叠（1.9.0）；用户手动展开过就记住，刷新/自动重载不打断他。
  var ps=document.getElementById('plugsec');
  if(ls('dshai_admin_plug_open')==='1'){ ps.open=true; }
  ps.addEventListener('toggle',function(){ ls('dshai_admin_plug_open', ps.open?'1':'0'); });
  var tbl=document.getElementById('logtable'), chips=document.querySelectorAll('.logtool .chip'), hint=document.getElementById('logfilterhint');
  function applyFilter(f){
    if(f!=='bad'){ f='all'; }
    tbl.className = f==='bad' ? 'filter-bad' : '';
    Array.prototype.forEach.call(chips, function(c){ c.setAttribute('aria-pressed', String(c.getAttribute('data-f')===f)); });
    var n=0;
    if(tbl.tBodies[0]){
      Array.prototype.forEach.call(tbl.tBodies[0].rows, function(r){
        var t=r.getAttribute('data-tone');
        if(t!=='ok' && t!=='info'){ n++; }
      });
    }
    if(hint){ hint.textContent = f==='bad' ? ('已隐藏成功与中性行，留下 ' + n + ' 行异常') : ''; }
    ls(FILTER, f);
  }
  Array.prototype.forEach.call(chips, function(c){ c.addEventListener('click', function(){ applyFilter(c.getAttribute('data-f')); }); });
  applyFilter(ls(FILTER));
  var box=document.getElementById('gauto'), on=ls(AUTO)!=='0';
  box.checked=on;
  box.addEventListener('change',function(){ on=box.checked; ls(AUTO, on?'1':'0'); });
  var dirty=false;
  Array.prototype.forEach.call(document.querySelectorAll('form input'), function(el){
    if(el!==box){ el.addEventListener('input', function(){ dirty=true; }); }
  });
  // 市场/DSH 版本还在「获取中」时把自动刷新从 10 秒提到 3 秒：数据一到用户
  // 很快看到，取完（或取失败的 30 秒缓存期内）立刻回到 10 秒，不空转。
  var busy={{if or .MarketFetching .DSHVerFetching}}1{{else}}0{{end}};
  setInterval(function(){
    if(!on || dirty){ return; }
    if(document.querySelector('input:focus,textarea:focus')){ return; }
    location.reload();
  }, busy?3000:10000);
})();
</script>
</body>
</html>
`

var adminTpl = template.Must(template.New("admin").Parse(adminHTML))

type adminEvent struct {
	Time  string
	Kind  string
	Tone  string // ok / warn / err / info，决定徽章配色
	IP    string
	Text  string
	Count int
}

type adminLock struct {
	IP    string
	Until string
	Fails int
}

type adminView struct {
	Title       string
	Version     string
	Uptime      string
	Mode        string
	SessionDays int
	SessionLeft string
	Listen      string
	Upstream    string
	Total       int64
	Shown       int
	Older       int // 内存里更早、这次没渲染的事件条数
	Stats       string
	Coalesce    int // 同类事件合并窗口（秒），文案跟着常量走
	OutBurst    int // 标准输出每窗口最多几行，同上
	OutWindow   int // 标准输出的限速窗口（秒），同上
	Delay       string
	Max         int
	Locks       []adminLock
	Events      []adminEvent
	Msg         string

	// 登录方式
	TOTPConfigured bool
	TOTPOn         bool
	PwOn           bool

	// GitHub 登录
	GitHubEnabled    bool
	GitHubReady      bool
	GitHubConfigured bool // ClientID 与 secret 都存了（不看开关），用来决定配置卡默认展开还是折叠
	GitHubClientID   string
	GitHubAllow     string
	GitHubSecretSet bool
	BaseURL         string
	CallbackURL     string
	StatePath       string
	StateWritable   bool

	// DSH 会话
	DSHDays int
	DSHOK   bool
	DSHLeft string

	RestartBusy   bool
	RestartAt     string
	RestartResult string

	// 体检（1.8.0）：全是「读」，不在这页改任何东西
	DshUp         bool   // 上游现在通不通（探活一次）
	UpErrCount    int    // 内存里的「上游错误」事件条数
	RestartCount  int    // 内存里的「DSH 重启」次数
	MarketVer     string // 市场插件版本（拉不到写「拉取失败」）
	UpdateCount   int    // 有可更新的插件数
	UpdatesOK     bool   // 更新摘要拉到了吗（false 时不许说「已最新」）
	SnapshotCount int    // 快照数
	MarketBusy    bool   // 市场正在跑长任务（装/更）
	MarketPhase   string
	MarketLine    string
	MarketFetching bool  // 正在后台重拉市场（1.9.0：页面显示「获取中」，不阻塞）

	// DSH 版本检测（1.9.0：为更新功能铺路；缓存 10 分钟）
	DSHVer         string
	DSHVerFetching bool

	// 插件管理
	Plugins    []pluginRow
	PluginsErr string
	OpRunning  bool
	Op         string
	OpAt       string
	OpResult   string
	OpTone     string

	// 历史日志（1.8.0 落盘）
	LogPath   string // 空 = 未启用
	LogSize   string // 当前大小或状态
	LogRotate string // 轮转规则一句话
	Hist      []adminEvent
	HistShown int
	HistQuery string
	HistCap   int // 页面每次最多给几行

	// 踢光设备
	Epoch int64
}

// toneOf 把事件种类（必要时结合说明文字）映射成配色：失败类红、拦截类黄、
// 成功类绿、其余中性。
//
// 只看 Kind 不够：同一类事件里既有成功也有被拒（「GitHub 登录」既有
// 「已跳转 GitHub 授权」也有「不在允许名单，拒绝」；「后台操作」既有正常保存
// 也有「非同一站点，已拒绝」），一律涂成中性灰等于把一次拒绝藏起来。所以先按
// Kind 判，判不出来再看说明里的信号词。
func toneOf(kind, text string) string {
	switch kind {
	case "登录成功", "令牌换票成功", "登出", "DSH 就绪":
		return "ok"
	case "验证失败", "锁定", "动态码重放", "令牌换票失败", "上游错误", "探测 DSH 失败",
		"GitHub 换票失败", "GitHub 查询账号失败", "DSH 不可达":
		return "err"
	case "未鉴权拦截", "锁定期间尝试", "接口缺有效 DSH 会话",
		"踢光设备", "DSH 重启", "历史日志":
		return "warn"
	case "插件操作":
		// 同一类里既有「更新完成」也有「被市场拒绝」，先看文案里的信号词。
		if strings.Contains(text, "失败") || strings.Contains(text, "拒绝") || strings.Contains(text, "错误") {
			return "err"
		}
		return "ok"
	}
	if strings.Contains(text, "被拒") || strings.Contains(text, "拒绝") || strings.Contains(text, "失败") {
		return "err"
	}
	if strings.Contains(text, "拦截") || strings.Contains(text, "锁定") {
		return "warn"
	}
	return "info"
}

// logStats 拼出摘要行里的分布统计（只列非零项）——一眼能看出这份日志里
// 到底什么在刷屏：是有人在扫（拦截），还是真有人在试密码（失败）。
func logStats(bad, warn, ok, info int) string {
	var xs []string
	if bad > 0 {
		xs = append(xs, fmt.Sprintf("失败 %d", bad))
	}
	if warn > 0 {
		xs = append(xs, fmt.Sprintf("拦截 %d", warn))
	}
	if ok > 0 {
		xs = append(xs, fmt.Sprintf("成功 %d", ok))
	}
	if info > 0 {
		xs = append(xs, fmt.Sprintf("其他 %d", info))
	}
	if len(xs) == 0 {
		return "暂无事件"
	}
	return strings.Join(xs, " · ")
}

// buildRows 把内存里的事件转成页面行（最新在最前），最多 adminRowsMax 行，
// 同时按配色分类计数。
//
// ★统计走的是**全部**事件：只渲染 100 行、以及前端「只看异常」筛选都不该让
// 摘要里的数字变小——否则「拦截 3」会随着旧记录被挤出渲染范围而消失，看着像
// 攻击停了。这也正是 T10c 要断言页面渲染到底的原因。
func buildRows(evs []secEvent) (rows []adminEvent, bad, warn, ok, info int) {
	rows = make([]adminEvent, 0, min(len(evs), adminRowsMax))
	for i := len(evs) - 1; i >= 0; i-- { // 最新在最上面
		e := evs[i]
		tone := toneOf(e.Kind, e.Text)
		switch tone {
		case "err":
			bad++
		case "warn":
			warn++
		case "ok":
			ok++
		default:
			info++
		}
		if len(rows) >= adminRowsMax {
			continue // 超出渲染上限的行不再渲染，但已经计入统计
		}
		rows = append(rows, adminEvent{
			Time: e.Time.Format("01-02 15:04:05"), Kind: e.Kind, Tone: tone,
			IP: e.IP, Text: e.Text, Count: e.Count,
		})
	}
	return rows, bad, warn, ok, info
}

// sessionLeft 从本设备 Cookie 的过期时间算出剩余有效期
func sessionLeft(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "—"
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "—"
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "—"
	}
	d := time.Until(time.Unix(exp, 0))
	if d <= 0 {
		return "已过期"
	}
	return humanUptime(d)
}

// lockedSnapshot 返回仍在锁定期的 IP（供后台页展示）
func lockedSnapshot() []adminLock {
	limMu.Lock()
	defer limMu.Unlock()
	now := time.Now()
	var out []adminLock
	for ip, s := range limM {
		if s.until.After(now) {
			out = append(out, adminLock{IP: ip, Until: humanDur(time.Until(s.until)), Fails: s.fails})
		}
	}
	return out
}

// ---------- 后台页的「重启 DSH」 ----------

// 同一时刻只允许一个重启在跑；进度留在页面上，靠后台页 10 秒自动刷新呈现。
var restartState struct {
	mu      sync.Mutex
	running bool
	at      string
	result  string
}

func restartSnapshot() (busy bool, at, result string) {
	restartState.mu.Lock()
	defer restartState.mu.Unlock()
	return restartState.running, restartState.at, restartState.result
}

// restartDSH 以「本机直连」的身份请 DSH 重启自己。
//
// 市场的重启路由把「回环对端 + 无任何转发头 + Origin 的 authority 等于 Host」
// 当作唯一凭据 —— 实测连 Cookie / 令牌都不要（这也正是它能被本机任何进程调用的原因）。
// 所以这里刻意用回环 Host 与 Origin、且不设任何 X-Forwarded-*。
// 前提是 GATE_UPSTREAM 指向 127.0.0.1，否则对端不是回环，这道门会拒。
//
// 注意：这条路依赖 dshmarket 插件已加载（路由由它注册）；DSH 完全起不来时
// 这个按钮也救不了 —— 那种情况必须由宿主的 docker 来拉。
func restartDSH() (int, string) {
	u := *upstreamURL
	u.Path = "/dsh-market/restart"
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader("{}"))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+u.Host)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func dshListening() bool {
	c, err := net.DialTimeout("tcp", upstreamURL.Host, 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// waitDSHRestart 先等 DSH 真的停下，再等它起来，把真实结果写回页面。
//
// 容器里 DSH 收到停止信号是优雅退出（退出码 0），能不能被拉起来完全取决于
// compose 的 restart 策略：on-failure 不会重启退出码 0 的容器，必须 unless-stopped。
// 所以「等不到起来」这条分支要把这个原因直接说出来，而不是含糊地报失败。
func waitDSHRestart() string {
	start := time.Now()
	down := false
	for time.Since(start) < 30*time.Second {
		if !dshListening() {
			down = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !down {
		return "指令已被接受，但 30 秒内没看到 DSH 停止 —— 请到服务器确认"
	}
	for time.Since(start) < 300*time.Second {
		if dshListening() {
			return fmt.Sprintf("已重启完成，全程 %s", time.Since(start).Round(time.Second))
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "DSH 已停止，但 300 秒内没起来 —— 检查容器重启策略是否为 unless-stopped"
}

// sameOriginRequest 判定请求是否同源。
//
// 优先看 Sec-Fetch-Site（现代浏览器对同源请求必带 same-origin，跨站表单是 cross-site），
// 没有该头时退回比对 Origin 的 authority 与 Host。
//
// ⚠️ 「没有 Origin 就放行」是**安全**的：按 Fetch 规范，跨站 POST 一定会带 Origin，
// 所以「没有 Origin」不可能是一次跨站表单提交。反过来若要求必须有 Origin，
// 会把某些浏览器上同源表单导航不带 Origin 的情况一起误杀，那是可用性事故。
func sameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host == r.Host
}

// handleRestart 后台页的重启按钮（withGate 已保证只有已登录会话能到这里）。
// 会话 Cookie 是 SameSite=Lax，跨站表单本来就带不上；同源校验是纵深防御，
// 也让这条路由不比它所替代的市场路由更松。
func handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !sameOriginRequest(r) {
		secNote("重启 DSH", ip, "非同一站点，已拒绝（Sec-Fetch-Site=%q Origin=%q Host=%q）",
			r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin"), r.Host)
		http.Error(w, "只接受同源请求", http.StatusForbidden)
		return
	}
	restartState.mu.Lock()
	if restartState.running {
		restartState.mu.Unlock()
		secNote("重启 DSH", ip, "已有重启在进行中，忽略本次请求")
		http.Redirect(w, r, gatePrefix+"/admin", http.StatusSeeOther)
		return
	}
	restartState.running = true
	restartState.at = time.Now().Format("01-02 15:04:05")
	restartState.result = "已发出指令，等待 DSH 停止…"
	restartState.mu.Unlock()

	secNote("重启 DSH", ip, "已从后台页发起重启")
	go func() {
		code, detail := restartDSH()
		out := ""
		if code != http.StatusAccepted {
			out = fmt.Sprintf("上游拒绝（HTTP %d）：%s", code, detail)
		} else {
			out = waitDSHRestart()
		}
		restartState.mu.Lock()
		restartState.running = false
		restartState.result = out
		restartState.mu.Unlock()
		secNote("重启 DSH", ip, "结果：%s", out)
	}()
	http.Redirect(w, r, gatePrefix+"/admin", http.StatusSeeOther)
}

// handleLogoutAll 一键踢光所有登录设备（1.8.0）。
//
// 原理：门禁会话 Cookie 是无状态签名的，正常情况下服务端「不记得」发过谁 ——
// 这里给配置加一个会话代数（SessionEpoch），签名时把代数盖进去，校验时代数
// 不匹配一律按过期处理。代数 +1 后，所有旧 Cookie（含本机的）立即作废，
// 再给本机补发新一代 Cookie，于是「别的设备全部被踢、本机保持登录」。
// 代数落盘在 GATE_STATE 里，重启不回滚。踢不掉的只有服务器明确记名的
// d1 DSH 配对戳（stampDSHSession），那个由 DSH 自己管。
func handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if !adminPost(w, r) {
		return
	}
	ip := clientIP(r)
	c := configSnapshot()
	c.SessionEpoch++
	msg := fmt.Sprintf("已踢光：所有设备需要重新登录（会话代数 → %d），本机已自动续上新代。", c.SessionEpoch)
	if err := saveConfig(c); err != nil {
		// saveConfig 失败时内存里的代数已经生效，但重启会回滚 —— 必须如实告知，
		// 不能让用户以为重启后还踢得干净。
		msg = fmt.Sprintf("已踢光（仅本次运行生效：状态文件写失败 %v，重启门禁后代数会回退，届时需再踢一次）。", err)
	}
	secNote("踢光设备", ip, "会话代数 → %d，旧 Cookie 全部作废", c.SessionEpoch)
	val, maxAge := issueCookie()
	setCookie(w, r, cookieName, val, maxAge) // 本机换发新一代
	setAdminMsg("%s", msg)
	backToAdmin(w, r)
}

// ---------- 后台页的插件管理（1.8.0） ----------
//
// 边界说明：门禁不碰容器、不碰宿主文件（镜像里连 docker 都没有，数据卷只挂了
// /data）。插件的安装/启停/更新/卸载全部经 HTTP 转给 dshmarket 自己的路由，
// 门禁只做三件事：同源与登录校验、参数合法性把关、把结果写回页面。
//
// 与市场路由的关系：那 20 条写路由（marketMutationPaths）**自身不校验 DSH 会话**
// （2026-10-03 读源码确认，整个 routes.js 没有任何会话检查，唯一门是 sameOrigin），
// 所以 withGate 把它们一并纳入第二层（需有效 DSH 会话）。本函数是服务端发起的
// 调用，不经过 withGate 那个分支，不受影响；浏览器直连市场路由则会被第二层拦下。

// pluginRow 是插件表的一行。
type pluginRow struct {
	Name      string
	Spec      string // package.json 里的依赖写法（^1.2.3 / link:… / registry:…）
	Latest    string // 拉到更新信息时才有值
	Updatable bool
	Disabled  bool
}

// marketOpState 与 restartState 同构：市场写操作是分钟级长任务（跑 pnpm 装包），
// 同步等必然被前面的反代 60 秒掐断 —— 所以立即 303 回后台页，真正操作放
// goroutine 里跑，结果写回这里，页面 10 秒自动刷新呈现。
var marketOpState struct {
	mu      sync.Mutex
	running bool
	op      string
	at      string
	result  string
}

func marketOpSnapshot() (running bool, op, at, result string) {
	marketOpState.mu.Lock()
	defer marketOpState.mu.Unlock()
	return marketOpState.running, marketOpState.op, marketOpState.at, marketOpState.result
}

// validPluginName 只放行 npm 包名字符集：这条名字会拼进命令参数与页面 HTML，
// 宽一分就多一分注入/越权的空间。连两点（路径回溯）也明确拒绝。
func validPluginName(s string) bool {
	if s == "" || len(s) > 214 || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '@', r == '/', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// validInstallURL 把关安装地址：必须是 https、必须有主机名、不许带用户名口令
// （防 history 里漏出带凭据的 URL）。最终「在不在精选列表」由市场自己判。
func validInstallURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// marketPOST 以「回环直连」身份调市场的写路由：Host/Origin 取上游回环地址、
// 不设任何 X-Forwarded-*（同 restartDSH 的理由），并原样带上浏览器的 Cookie ——
// 市场当前不查会话，带上只是让请求与「用户亲手在市场页点按钮」更接近。
// 超时给 300 秒：安装是长任务，但反正没人同步等它（见 marketOpState）。
func marketPOST(path string, body any, cookie string) (int, string) {
	buf, err := json.Marshal(body)
	if err != nil {
		return 0, err.Error()
	}
	u := *upstreamURL
	u.Path = path
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(buf))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+u.Host)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// marketResultText 把市场返回码翻成给用户看的一句话。2xx 直接说「完成」
// （成功 body 是 {"ok":true,…} 这类 JSON，没有给人看的信息）；失败时把
// {"error":"…"} 里的正文解出来 —— 市场的中文错误提示（如「插件未安装」）
// 本身就是答案，包一层 JSON 或让人去翻服务器日志都是浪费。
func marketResultText(code int, detail string) string {
	if code >= 200 && code < 300 {
		return "完成"
	}
	msg := detail
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(detail), &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if code == 0 {
		return "失败：" + msg
	}
	return fmt.Sprintf("失败（HTTP %d）：%s", code, msg)
}

// handleMarket 后台页的插件操作入口（表单：op + name/url/enabled）。
func handleMarket(w http.ResponseWriter, r *http.Request) {
	if !adminPost(w, r) {
		return
	}
	ip := clientIP(r)
	op := r.FormValue("op")
	name := strings.TrimSpace(r.FormValue("name"))
	var body map[string]any
	switch op {
	case "refresh":
		// 手动检测刷新（1.9.0）：丢弃市场/版本缓存，当场同步重检一遍再回页，
		// 用户点一下就立刻看到新结果，不等后台轮询。
		marketInvalidate()
		dshVerInvalidate()
		marketRefreshNow()
		dshVersionRefreshNow(r.Host, dshCookieFor(r))
		secNote("插件操作", ip, "手动检测刷新")
		setAdminMsg("已重新检测：插件列表、更新情况和 DSH 版本都取了最新。")
		backToAdmin(w, r)
		return
	case "install":
		u := strings.TrimSpace(r.FormValue("url"))
		if !validInstallURL(u) {
			setAdminMsg("没执行：插件地址必须是 https:// 开头的完整网址。能装哪些由市场的精选列表决定，粘地址即可。")
			secNote("插件操作", ip, "被拒：非法安装地址")
			backToAdmin(w, r)
			return
		}
		body = map[string]any{"url": u}
		if v := strings.TrimSpace(r.FormValue("version")); v != "" {
			body["version"] = v
		}
		name = u // 安装没有包名，事件里记地址（市场 400 会自己说不在精选列表）
	case "toggle":
		if !validPluginName(name) {
			setAdminMsg("没执行：插件名不合法。")
			secNote("插件操作", ip, "被拒：非法插件名")
			backToAdmin(w, r)
			return
		}
		body = map[string]any{"name": name, "enabled": r.FormValue("enabled") == "1"}
	case "update", "uninstall":
		if !validPluginName(name) {
			setAdminMsg("没执行：插件名不合法。")
			secNote("插件操作", ip, "被拒：非法插件名")
			backToAdmin(w, r)
			return
		}
		body = map[string]any{"name": name}
	default:
		setAdminMsg("没执行：不认识的插件操作（%q）。", op)
		backToAdmin(w, r)
		return
	}
	// 展示与事件用中文动作名（面向零英文用户），路由名仍用 op。
	label := map[string]string{"install": "安装", "update": "更新", "uninstall": "卸载", "toggle": "停用"}[op]
	if op == "toggle" && r.FormValue("enabled") == "1" {
		label = "启用"
	}
	// 市场自己有两条硬规矩，先在门禁这层用中文拦下，别把英文 400 抛给用户：
	// 插件市场不能停用/卸载自身（市场源码原文：use the dsh CLI）。
	if (op == "toggle" || op == "uninstall") && (name == "dsh-market" || name == "dshmarket") {
		setAdminMsg("没执行：插件市场不能停用或卸载自己，要动它请在服务器上用 dsh 命令行。")
		secNote("插件操作", ip, "被拒：市场不允许操作自身")
		backToAdmin(w, r)
		return
	}

	marketOpState.mu.Lock()
	if marketOpState.running {
		marketOpState.mu.Unlock()
		setAdminMsg("已有插件操作在进行，等它完成再试（进度看插件管理那一行）。")
		backToAdmin(w, r)
		return
	}
	marketOpState.running = true
	marketOpState.op = label
	marketOpState.at = time.Now().Format("01-02 15:04:05")
	marketOpState.result = "进行中…"
	cookie := r.Header.Get("Cookie")
	marketOpState.mu.Unlock()

	secNote("插件操作", ip, "发起%s：%s", label, name)
	go func() {
		code, detail := marketPOST("/dsh-market/"+op, body, cookie)
		out := marketResultText(code, detail)
		marketOpState.mu.Lock()
		marketOpState.running = false
		marketOpState.result = out
		marketOpState.mu.Unlock()
		marketInvalidate() // 列表/可更新信息立即过期，下次打开后台页就是新的
		secNote("插件操作", ip, "%s %s → %s", label, name, out)
	}()
	backToAdmin(w, r)
}

// ---------- 只读市场信息（30 秒缓存） ----------

// dshGetJSON 给上游发一次只读 GET 并解 JSON。Host 取上游回环地址
// （http.NewRequest 默认就用 URL 里的 Host），与经反代转发时的身份一致。
func dshGetJSON(path string, timeout time.Duration, out any) error {
	if upstreamURL == nil {
		return fmt.Errorf("上游未配置")
	}
	u := *upstreamURL
	u.Path = path
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// marketReadInfo 是体检面板 + 插件表要用的那几样只读数据，一次拉齐。
type marketReadInfo struct {
	ok         bool
	at         time.Time
	fetching   bool // 正在后台重拉（页面显示「获取中」，不阻塞渲染）
	ver        string
	sumOK      bool // 更新摘要这次拉到了吗（false 时不能说「已最新」）
	updatable  int
	latest     map[string]string // 包名 → 最新版本
	snaps      int
	plugins    []pluginRow
	pluginsErr string
}

var marketRead struct {
	mu       sync.Mutex
	info     marketReadInfo
	fetching bool // 已有后台重拉在跑（单飞）
}

const marketReadTTL = 30 * time.Second

// marketInvalidate 让下一次取数立刻重拉（插件操作刚跑完时用）。
func marketInvalidate() {
	marketRead.mu.Lock()
	marketRead.info.at = time.Time{}
	marketRead.mu.Unlock()
}

// marketReadSnapshot 返回缓存的市场只读信息；过期时**不阻塞页面**：先回旧值
// （没有旧值就回空值 + fetching），再后台单飞重拉——后台页永远不该因为市场
// 慢而整页转圈。下一次渲染（页面 2 秒自动刷新或点手动检测）自然拿到新值。
func marketReadSnapshot() marketReadInfo {
	marketRead.mu.Lock()
	stale := !marketRead.info.ok || time.Since(marketRead.info.at) > marketReadTTL
	info := marketRead.info
	if stale {
		info.fetching = true
		if !marketRead.fetching {
			marketRead.fetching = true
			go func() {
				ni := refreshMarketRead()
				marketRead.mu.Lock()
				marketRead.info = ni
				marketRead.fetching = false
				marketRead.mu.Unlock()
			}()
		}
	}
	marketRead.mu.Unlock()
	return info
}

// marketRefreshNow 同步重拉一次（「手动检测刷新」按钮用）：用户点了按钮就在这
// 一次请求里等结果，回页立刻是新的；与后台单飞互斥，别人在拉就直接返回。
func marketRefreshNow() {
	marketRead.mu.Lock()
	if marketRead.fetching {
		marketRead.mu.Unlock()
		return
	}
	marketRead.fetching = true
	marketRead.mu.Unlock()
	ni := refreshMarketRead()
	marketRead.mu.Lock()
	marketRead.info = ni
	marketRead.fetching = false
	marketRead.mu.Unlock()
}

type mktStatus struct {
	Version string `json:"version"`
	Busy    bool   `json:"busy"`
	Phase   string `json:"phase"`
	Last    string `json:"lastLine"`
}

type mktSummary struct {
	Updatable int `json:"updatable"`
	Packages  []struct {
		Name          string `json:"name"`
		LatestVersion string `json:"latestVersion"`
	} `json:"packages"`
}

type mktInstalled struct {
	Installed map[string]string `json:"installed"`
	Disabled  []string          `json:"disabled"`
}

type mktSnaps struct {
	Snapshots []json.RawMessage `json:"snapshots"`
}

// refreshMarketRead 四路并发拉取（status / 更新摘要 / 已装列表 / 快照），
// 各自记各自的错：某一路挂了不至于让其它三路的数据显示不出来。
func refreshMarketRead() marketReadInfo {
	var (
		wg                                  sync.WaitGroup
		st                                  mktStatus
		sum                                 mktSummary
		inst                                mktInstalled
		snaps                               mktSnaps
		errVer, errSum, errInst, errSnaps   error
	)
	fetch := func(dst any, path string, errDst *error) {
		defer wg.Done()
		*errDst = dshGetJSON(path, 5*time.Second, dst)
	}
	wg.Add(4)
	go fetch(&st, "/dsh-market/status", &errVer)
	go fetch(&sum, "/dsh-market/api/v1/updates/summary", &errSum)
	go fetch(&inst, "/dsh-market/installed", &errInst)
	go fetch(&snaps, "/dsh-market/snapshots", &errSnaps)
	wg.Wait()

	info := marketReadInfo{ok: true, at: time.Now(), latest: map[string]string{}}
	if errVer != nil {
		info.ver = "拉取失败"
	} else {
		info.ver = st.Version
	}
	if errSum == nil {
		info.sumOK = true
		info.updatable = sum.Updatable
		for _, p := range sum.Packages {
			info.latest[p.Name] = p.LatestVersion
		}
	}
	if errInst == nil {
		disabled := map[string]bool{}
		for _, n := range inst.Disabled {
			disabled[n] = true
		}
		names := make([]string, 0, len(inst.Installed))
		for n := range inst.Installed {
			names = append(names, n)
		}
		sort.Strings(names)
		info.plugins = make([]pluginRow, 0, len(names))
		for _, n := range names {
			latest := info.latest[n]
			info.plugins = append(info.plugins, pluginRow{
				Name: n, Spec: inst.Installed[n], Latest: latest,
				// 摘要里只列「有更新」的包，所以见到 latest 就是可更新。
				Updatable: latest != "",
				Disabled:  disabled[n],
			})
		}
	} else {
		info.pluginsErr = "已装列表拉取失败：" + errInst.Error()
	}
	if errSnaps == nil {
		info.snaps = len(snaps.Snapshots)
	}
	return info
}

// marketStatusNow 取市场进度（busy/阶段/最后一行），5 秒缓存 ——
// 这行字每 10 秒随页面刷新，没必要每次都现场问。
const marketStatusTTL = 5 * time.Second

var marketStatusCache struct {
	mu  sync.Mutex
	at  time.Time
	st  mktStatus
	err string
}

func marketStatusNow() (mktStatus, string) {
	marketStatusCache.mu.Lock()
	if !marketStatusCache.at.IsZero() && time.Since(marketStatusCache.at) < marketStatusTTL {
		st, err := marketStatusCache.st, marketStatusCache.err
		marketStatusCache.mu.Unlock()
		return st, err
	}
	marketStatusCache.mu.Unlock()
	var st mktStatus
	errStr := ""
	if err := dshGetJSON("/dsh-market/status", 3*time.Second, &st); err != nil {
		errStr = err.Error()
	}
	marketStatusCache.mu.Lock()
	marketStatusCache.at, marketStatusCache.st, marketStatusCache.err = time.Now(), st, errStr
	marketStatusCache.mu.Unlock()
	return st, errStr
}

// ---------- DSH 版本检测（1.9.0：为将来的更新功能铺路） ----------
//
// DSH 没有任何版本 API，版本号只烤在前端构建里，只能两步抓：① 拿首页，
// 正则出设置页脚本地址（带 rev 指纹，少了 rev 那个地址直接 404）；② 抓
// 那个脚本，读 currentVersion 的 version 字段。结果缓存 10 分钟、后台单飞
// 刷新，页面只读缓存 —— 版本检测绝不能拖慢后台页。

const dshVerTTL = 10 * time.Minute

// 两个正则与 DSH 前端构建产物对齐（0.2.0-rc.2 实测通过）。
var (
	dshUIBundleRe = regexp.MustCompile(`plugins/(\?\?@deepseek-ai/dsh-client-ui-settings-general/client\.js&rev=[0-9a-f]+)`)
	dshUIVerRe    = regexp.MustCompile(`currentVersion", \{ version: "([^"]+)"`)
)

var dshVerRead struct {
	mu       sync.Mutex
	ver      string
	at       time.Time // 上次尝试时间（失败也更新，按 TTL 退避不打爆上游）
	fetching bool
}

// dshCookieFor 给版本检测用的 Cookie：优先门禁自签（不依赖浏览器状态，
// GATE_DSH_SESSION_KEY 配了就够），没配就借浏览器带来的整串 Cookie。
func dshCookieFor(r *http.Request) string {
	if c, err := dshAutoSign(r); err == nil {
		return c.Name + "=" + c.Value
	}
	return r.Header.Get("Cookie")
}

// dshDetectVersion 现场检测一次 DSH 版本（两步抓前端构建文件）。
// host/cookie 是算好的字符串：后台协程不碰 *http.Request。
func dshDetectVersion(host, cookie string) (string, error) {
	if upstreamURL == nil {
		return "", fmt.Errorf("上游未配置")
	}
	if cookie == "" {
		return "", fmt.Errorf("没有可用的 DSH 会话")
	}
	fetch := func(rawurl string) ([]byte, error) {
		req, err := http.NewRequest(http.MethodGet, rawurl, nil)
		if err != nil {
			return nil, err
		}
		req.Host = host // ★ 与 dshCall 同理：DSH 按 Host 计算 Cookie 归属
		req.Header.Set("Cookie", cookie)
		client := &http.Client{
			Timeout:       8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DSH 返回 %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	}
	home, err := fetch(upstreamURL.String() + "/")
	if err != nil {
		return "", err
	}
	m := dshUIBundleRe.FindSubmatch(home)
	if m == nil {
		return "", fmt.Errorf("首页里没找到设置页脚本地址")
	}
	// m[1] 以 "??@…" 开头：整串拼回 URL 里，第一个 ? 自然成为查询串分隔符，
	// 发出去的请求行与浏览器一字不差（少了 rev 就是 404）。
	js, err := fetch(upstreamURL.String() + "/plugins/" + string(m[1]))
	if err != nil {
		return "", err
	}
	v := dshUIVerRe.FindSubmatch(js)
	if v == nil {
		return "", fmt.Errorf("脚本里没找到版本号")
	}
	return string(v[1]), nil
}

// dshVersionSnapshot 返回缓存的 DSH 版本号；过期则后台单飞重检（不阻塞页面）。
// 返回 (版本, 是否正在检测)。
func dshVersionSnapshot(host, cookie string) (string, bool) {
	dshVerRead.mu.Lock()
	stale := dshVerRead.at.IsZero() || time.Since(dshVerRead.at) > dshVerTTL
	ver, fetching := dshVerRead.ver, dshVerRead.fetching
	if stale && !fetching {
		dshVerRead.fetching = true
		fetching = true
		go func() {
			v, err := dshDetectVersion(host, cookie)
			dshVerRead.mu.Lock()
			if err == nil && v != "" {
				dshVerRead.ver = v
			}
			dshVerRead.at = time.Now()
			dshVerRead.fetching = false
			dshVerRead.mu.Unlock()
		}()
	}
	dshVerRead.mu.Unlock()
	return ver, fetching
}

// dshVerInvalidate 让下一次取版本立刻重检（手动检测刷新用）。
func dshVerInvalidate() {
	dshVerRead.mu.Lock()
	dshVerRead.at = time.Time{}
	dshVerRead.mu.Unlock()
}

// dshVersionRefreshNow 同步重检一次（手动检测按钮用）：点了按钮就在这一次
// 请求里等结果，回页立刻是新的；与后台单飞互斥。
func dshVersionRefreshNow(host, cookie string) {
	dshVerRead.mu.Lock()
	if dshVerRead.fetching {
		dshVerRead.mu.Unlock()
		return
	}
	dshVerRead.fetching = true
	dshVerRead.mu.Unlock()
	v, err := dshDetectVersion(host, cookie)
	dshVerRead.mu.Lock()
	if err == nil && v != "" {
		dshVerRead.ver = v
	}
	dshVerRead.at = time.Now()
	dshVerRead.fetching = false
	dshVerRead.mu.Unlock()
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	evs, total := secSnapshot()
	rows, nBad, nWarn, nOK, nInfo := buildRows(evs)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	busy, at, result := restartSnapshot()
	cfg := configSnapshot()
	pw, totp, gh := modesOf(cfg)
	dshLeft := "没有记录（旧会话继续可用）"
	if d, ok := dshSessionLeft(r); ok {
		if d > 0 {
			dshLeft = humanUptime(d)
		} else {
			dshLeft = "已过期"
		}
	}
	// 体检数据：市场只读信息走 30 秒缓存、进度走 5 秒缓存，都是给完超时就认输
	// （写「拉取失败」照常出页）—— 体检卡绝不能把整张后台页拖死。
	mkt := marketReadSnapshot()
	// DSH 版本：缓存 10 分钟、过期后台单飞重检，页面只读缓存（1.9.0）。
	dshVer, dshVerFetching := dshVersionSnapshot(r.Host, dshCookieFor(r))
	st, stErr := marketStatusNow()
	opRunning, op, opAt, opResult := marketOpSnapshot()
	histQuery := r.URL.Query().Get("q")
	hist := histReadRows(histQuery)
	logPath, logSize := histSizeDesc()
	logRotate := ""
	if logPath != "" {
		if histRotateSize >= 1<<20 {
			logRotate = fmt.Sprintf("单文件满 %.0f MB 轮转、保留 %d 份", float64(histRotateSize)/(1<<20), histRotKeep)
		} else {
			logRotate = fmt.Sprintf("单文件满 %d KB 轮转、保留 %d 份", histRotateSize>>10, histRotKeep)
		}
	}
	// 内存里的计数只覆盖最近 secLogMax 条（更早的在落盘文件里，历史卡能搜到）
	upErrs, restarts := 0, 0
	for _, e := range evs {
		switch e.Kind {
		case "上游错误":
			upErrs++
		case "DSH 重启":
			restarts++
		}
	}
	marketLine := st.Last
	if marketLine == "" {
		marketLine = stErr
	}
	if marketLine == "" {
		marketLine = "—"
	}
	// 操作结果的配色：进行中=黄；失败/被拒/错误=红；完成=绿；还没做过=中性。
	// 复用 toneOf 的插件操作分支，只额外处理「进行中」。
	opTone := "info"
	if opRunning {
		opTone = "warn"
	} else if opResult != "" {
		opTone = toneOf("插件操作", opResult)
	}
	_ = adminTpl.Execute(w, adminView{
		Title: siteTitle, Version: gateVersion, Uptime: humanUptime(time.Since(startedAt)),
		Mode: subtitleOf(), SessionDays: sessionDs, SessionLeft: sessionLeft(r),
		Listen: listenAddr, Upstream: upstreamURL.String(),
		Total: total, Shown: len(rows), Older: len(evs) - len(rows),
		Stats: logStats(nBad, nWarn, nOK, nInfo), Coalesce: int(secCoalesce / time.Second),
		OutBurst: outBurst, OutWindow: int(outWindowLen / time.Second),
		Delay: globalDelay().String(), Max: secLogMax,
		Locks: lockedSnapshot(), Events: rows, Msg: adminMsg(),
		TOTPConfigured: needTotp, TOTPOn: totp, PwOn: pw,
		GitHubEnabled: cfg.GitHub.Enabled, GitHubReady: gh,
		GitHubClientID:   cfg.GitHub.ClientID,
		GitHubAllow:      strings.Join(cfg.GitHub.Allow, ", "),
		GitHubSecretSet:  cfg.GitHub.ClientSecret != "",
		GitHubConfigured: cfg.GitHub.ClientID != "" && cfg.GitHub.ClientSecret != "",
		BaseURL:          externalBase(r), CallbackURL: githubCallbackURL(r),
		StatePath: cfgPath, StateWritable: cfgWritable,
		DSHDays: dshSessionDs, DSHOK: dshSessionFresh(r), DSHLeft: dshLeft,
		RestartBusy: busy, RestartAt: at, RestartResult: result,
		DshUp:      dshListening(),
		UpErrCount: upErrs, RestartCount: restarts,
		MarketVer: mkt.ver, UpdateCount: mkt.updatable, UpdatesOK: mkt.sumOK, SnapshotCount: mkt.snaps,
		MarketBusy: st.Busy, MarketPhase: st.Phase, MarketLine: marketLine,
		MarketFetching: mkt.fetching,
		DSHVer:         dshVer, DSHVerFetching: dshVerFetching,
		Plugins:        mkt.plugins, PluginsErr: mkt.pluginsErr,
		OpRunning: opRunning, Op: op, OpAt: opAt, OpResult: opResult, OpTone: opTone,
		LogPath: logPath, LogSize: logSize, LogRotate: logRotate,
		Hist: hist, HistShown: len(hist), HistQuery: histQuery, HistCap: histRowsMax,
		Epoch: cfg.SessionEpoch,
	})
}

// ---------- 后台可改的配置（落盘） ----------

// githubConfig 是 GitHub 登录的全部配置。
// ★ 客户端密钥只存在门禁自己的配置文件里：compose 的 environment 会被
//   `docker inspect` 原样看到，后台页填进去的密钥不能走那条路。
type githubConfig struct {
	Enabled      bool     `json:"enabled"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Allow        []string `json:"allow"`
}

// gateConfig 是门禁落盘的全部内容。
// TOTPEnabled 用指针：要区分「从来没设置过」（按环境变量决定）与「后台明确关掉了」。
type gateConfig struct {
	TOTPEnabled *bool        `json:"totpEnabled,omitempty"`
	GitHub      githubConfig `json:"github"`
	// SessionEpoch 是「登录代数」：每踢一次光（/__gate/logout-all）+1，
	// 全体旧 Cookie（含未过期的）因代数对不上当场作废。0 = 还没踢过。
	SessionEpoch int64 `json:"sessionEpoch,omitempty"`
}

var (
	cfgMu       sync.Mutex
	cfgPath     string
	cfgWritable bool
	cfg         gateConfig
)

// loadConfig 读配置。文件不存在 = 全默认；读坏了 = 用默认值并大声告警。
// 两条降级路都不会放宽任何东西：GitHub 登录用不了、动态验证码回到「环境变量配了就开」。
func loadConfig(path string) {
	cfgPath = path
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("⚠️ 配置目录不可写（%v）。后台页改的设置重启后会丢；要保留请给门禁挂一个可写目录并把 GATE_STATE 指过去", err)
		return
	}
	cfgWritable = true
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️ 读不到配置文件 %s（%v），按默认值继续", path, err)
		}
		return
	}
	var c gateConfig
	if err := json.Unmarshal(b, &c); err != nil {
		log.Printf("⚠️ 配置文件 %s 解析失败（%v），按默认值继续", path, err)
		return
	}
	cfgMu.Lock()
	cfg = c
	cfgMu.Unlock()
}

// saveConfig 原子写盘（同目录临时文件 → rename），失败时把原因返回给后台页显示。
func saveConfig(c gateConfig) error {
	cfgMu.Lock()
	cfg = c
	path, ok := cfgPath, cfgWritable
	cfgMu.Unlock()
	if !ok {
		return fmt.Errorf("配置目录不可写（GATE_STATE=%q），改动只在内存里生效", path)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func configSnapshot() gateConfig {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return cfg
}

// modesOf 算出「按这份配置」实际可用的登录方式。
func modesOf(c gateConfig) (pw, totp, gh bool) {
	pw = needPw
	totp = needTotp && (c.TOTPEnabled == nil || *c.TOTPEnabled)
	g := c.GitHub
	gh = g.Enabled && g.ClientID != "" && g.ClientSecret != "" && len(g.Allow) > 0
	return
}

func loginModes() (pw, totp, gh bool) { return modesOf(configSnapshot()) }

// totpOn 动态验证码此刻是否对外提供（密钥配了 + 后台没关掉）。
func totpOn() bool { _, t, _ := loginModes(); return t }

// githubReady GitHub 登录是否配置齐全且已开启。缺任何一项都不算「可用」，
// 这样才能保证「关掉动态密码」时不会把唯一的进门方式一起关掉。
func githubReady() bool { _, _, g := loginModes(); return g }

// modesSummary 给启动日志与后台页用的一句话。
func modesSummary() string {
	pw, totp, gh := loginModes()
	var xs []string
	if pw {
		xs = append(xs, "访问口令")
	}
	if totp {
		xs = append(xs, "动态验证码")
	}
	if gh {
		xs = append(xs, "GitHub")
	}
	if len(xs) == 0 {
		return "无（配置异常）"
	}
	return strings.Join(xs, " + ")
}

func onOff(b bool) string {
	if b {
		return "开启"
	}
	return "关闭"
}

// splitAllow 把「逗号 / 空格 / 换行分隔」的允许名单切成切片并去重。
func splitAllow(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		f = strings.TrimSpace(f)
		if f == "" || seen[strings.ToLower(f)] {
			continue
		}
		seen[strings.ToLower(f)] = true
		out = append(out, f)
	}
	return out
}

// ---------- DSH 会话有效期 ----------

// stampDSHSession 记下「本设备此刻与 DSH 有会话」。记录只活 GATE_DSH_SESSION_DAYS 天。
func stampDSHSession(w http.ResponseWriter, r *http.Request) {
	v, maxAge := issueSigned("d1", dshSessionDs)
	setCookie(w, r, dshStampName, v, maxAge)
}

// dshSessionLeft 返回门禁记录的 DSH 会话剩余有效期；没有记录时 ok=false。
func dshSessionLeft(r *http.Request) (time.Duration, bool) {
	c, err := r.Cookie(dshStampName)
	if err != nil {
		return 0, false
	}
	exp, ok := signedExp(c.Value, "d1")
	if !ok {
		return 0, false
	}
	return time.Until(time.Unix(exp, 0)), true
}

// dshSessionFresh 是第二层校验：DSH 真的认这个会话，且没超出本地记录的有效期。
//
// ★ 没有本地记录时以 DSH 的真实会话为准：升级前登录的浏览器不该因为多了这个新
//   功能被踢出去（向后兼容）；有记录才按门禁的有效期算。
func dshSessionFresh(r *http.Request) bool {
	if !dshHasSession(r) {
		return false
	}
	d, ok := dshSessionLeft(r)
	if !ok {
		return true
	}
	return d > 0
}

// ---------- GitHub 登录 ----------

type githubIdentity struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

// githubAllowed 白名单比对：登录名不分大小写，数字 ID 精确匹配。
func githubAllowed(id githubIdentity, allow []string) bool {
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.EqualFold(a, id.Login) {
			return true
		}
		if a == strconv.FormatInt(id.ID, 10) {
			return true
		}
	}
	return false
}

func externalBase(r *http.Request) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func githubCallbackURL(r *http.Request) string {
	return externalBase(r) + gatePrefix + "/oauth/github/callback"
}

// oauthTicket 生成防重放票据：s1.<过期>.<随机>.<base64url(next)>.<签名>。
// 票据放在浏览器 Cookie 里（HttpOnly），服务端不存任何状态。
func oauthTicket(next string) (string, string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	st := hex.EncodeToString(raw[:])
	p := "s1." + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) + "." + st + "." +
		base64.RawURLEncoding.EncodeToString([]byte(next))
	return p + "." + sign(p), st, nil
}

// oauthTicketNext 验票并取回 next；want 是 GitHub 回跳时带上来的 state。
func oauthTicketNext(r *http.Request, want string) (string, bool) {
	c, err := r.Cookie(oauthStateName)
	if err != nil || want == "" {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 5 {
		return "", false
	}
	p := strings.Join(parts[:4], ".")
	if parts[0] != "s1" || !hmac.Equal([]byte(sign(p)), []byte(parts[4])) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return "", false
	}
	next, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", false
	}
	return sanitizeNext(string(next)), true
}

// handleGitHubStart 把浏览器送去 GitHub 授权页。
func handleGitHubStart(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	g := configSnapshot().GitHub
	if !githubReady() {
		secNote("GitHub 登录", ip, "未配置或未开启，拒绝发起")
		renderLogin(w, http.StatusNotFound, "GitHub 登录未开启", false, 0, r.URL.Query().Get("next"), dshHasSession(r))
		return
	}
	next := sanitizeNext(r.URL.Query().Get("next"))
	ticket, st, err := oauthTicket(next)
	if err != nil {
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	setCookie(w, r, oauthStateName, ticket, 600)
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("redirect_uri", githubCallbackURL(r))
	q.Set("scope", "read:user")
	q.Set("state", st)
	q.Set("allow_signup", "false")
	secNote("GitHub 登录", ip, "已跳转 GitHub 授权")
	http.Redirect(w, r, githubOAuthBase+"/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

// githubExchange 用一次性 code 换访问令牌（服务端对服务端，带客户端密钥）。
func githubExchange(r *http.Request, g githubConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientID)
	form.Set("client_secret", g.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", githubCallbackURL(r))
	req, err := http.NewRequest(http.MethodPost, githubOAuthBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Desc        string `json:"error_description"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("GitHub 换票响应无法解析（HTTP %d）", resp.StatusCode)
	}
	if out.AccessToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s：%s", out.Error, out.Desc)
		}
		return "", fmt.Errorf("GitHub 没给访问令牌（HTTP %d）", resp.StatusCode)
	}
	return out.AccessToken, nil
}

// githubWhoami 用访问令牌查「这是哪个 GitHub 账号」。
func githubWhoami(token string) (githubIdentity, error) {
	var id githubIdentity
	req, err := http.NewRequest(http.MethodGet, githubAPIBase+"/user", nil)
	if err != nil {
		return id, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "dshai-gate/"+gateVersion)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return id, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if resp.StatusCode != http.StatusOK {
		return id, fmt.Errorf("查询 GitHub 账号失败（HTTP %d）", resp.StatusCode)
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return id, fmt.Errorf("账号信息无法解析（HTTP %d）", resp.StatusCode)
	}
	if id.Login == "" && id.ID == 0 {
		return id, fmt.Errorf("GitHub 没返回账号信息")
	}
	return id, nil
}

// handleGitHubCallback 接收 GitHub 回跳：验票 → 换票 → 认账号 → 查白名单 → 发门禁会话。
// 任何一步失败都 fail-closed，并且把原因记进安全日志。
func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	g := configSnapshot().GitHub
	if !githubReady() {
		renderLogin(w, http.StatusNotFound, "GitHub 登录未开启", false, 0, "", dshHasSession(r))
		return
	}
	q := r.URL.Query()
	next, ok := oauthTicketNext(r, q.Get("state"))
	if !ok {
		secNote("GitHub 登录", ip, "票据校验失败（过期、被替换或不是本机发起）")
		renderLogin(w, http.StatusBadRequest, "登录票据已失效，请重新点一次 GitHub 登录", false, 0, "", dshHasSession(r))
		return
	}
	setCookie(w, r, oauthStateName, "", -1) // 票据一次性，用过即删
	if e := q.Get("error"); e != "" {
		secNote("GitHub 登录", ip, "GitHub 拒绝授权：%s（%s）", e, q.Get("error_description"))
		renderLogin(w, http.StatusUnauthorized, "GitHub 授权被拒绝", false, 0, next, dshHasSession(r))
		return
	}
	if q.Get("code") == "" {
		secNote("GitHub 登录", ip, "回跳缺少 code")
		renderLogin(w, http.StatusBadRequest, "GitHub 回跳参数不完整", false, 0, next, dshHasSession(r))
		return
	}
	token, err := githubExchange(r, g, q.Get("code"))
	if err != nil {
		secNote("GitHub 换票失败", ip, "%v", err)
		renderLogin(w, http.StatusBadGateway, "GitHub 换票失败，请稍后再试", false, 0, next, dshHasSession(r))
		return
	}
	id, err := githubWhoami(token)
	if err != nil {
		secNote("GitHub 查询账号失败", ip, "%v", err)
		renderLogin(w, http.StatusBadGateway, "查不到 GitHub 账号信息，请稍后再试", false, 0, next, dshHasSession(r))
		return
	}
	if !githubAllowed(id, g.Allow) {
		secNote("GitHub 登录", ip, "账号 %s(id=%d) 不在允许名单，拒绝", id.Login, id.ID)
		renderLogin(w, http.StatusForbidden, "这个 GitHub 账号不在允许名单里", false, 0, next, dshHasSession(r))
		return
	}
	val, maxAge := issueCookie()
	setCookie(w, r, cookieName, val, maxAge)
	if dshHasSession(r) {
		stampDSHSession(w, r)
	} else if c, err := dshAutoSign(r); err == nil && dshAcceptsCookie(r, c) {
		// 需求②：GitHub 登录成功后本机没有 DSH 会话时，门禁直接自签一枚
		http.SetCookie(w, c)
		stampDSHSession(w, r)
		secNote("自动获取 DSH 会话", ip, "门禁自签会话 Cookie（GitHub 登录后）")
	}
	secNote("登录成功", ip, "方式=GitHub(%s)", id.Login)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ---------- 后台页的写入操作（登录方式 / GitHub 配置 / DSH 重新配对） ----------

// adminMsgState 存「上一次操作的结果」，后台页顶部显示 60 秒。
var adminMsgState struct {
	mu   sync.Mutex
	text string
	at   time.Time
}

func setAdminMsg(format string, a ...any) {
	adminMsgState.mu.Lock()
	defer adminMsgState.mu.Unlock()
	adminMsgState.text = fmt.Sprintf(format, a...)
	adminMsgState.at = time.Now()
}

func adminMsg() string {
	adminMsgState.mu.Lock()
	defer adminMsgState.mu.Unlock()
	if time.Since(adminMsgState.at) > 60*time.Second {
		return ""
	}
	return adminMsgState.text
}

// adminPost 是所有后台写操作的共同前置：只收 POST、必须同源。
func adminPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return false
	}
	if !sameOriginRequest(r) {
		secNote("后台操作", clientIP(r), "非同一站点，已拒绝（%s）", r.URL.Path)
		http.Error(w, "只接受同源请求", http.StatusForbidden)
		return false
	}
	_ = r.ParseForm()
	return true
}

func backToAdmin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, gatePrefix+"/admin", http.StatusSeeOther)
}

// handleMethods 开关动态验证码登录。★ 校验后置：改完必须还剩至少一种登录方式，
// 否则这一步会把门从里面锁死（GitHub 没配好又关掉动态密码 = 谁也进不来）。
func handleMethods(w http.ResponseWriter, r *http.Request) {
	if !adminPost(w, r) {
		return
	}
	ip := clientIP(r)
	c := configSnapshot()
	on := r.FormValue("totp") == "on"
	c.TOTPEnabled = &on
	if pw, totp, gh := modesOf(c); !pw && !totp && !gh {
		setAdminMsg("没改：这会让所有登录方式都关掉，谁也进不来。请先配好 GitHub 登录。")
		secNote("登录方式变更", ip, "被拒：会导致没有任何登录方式")
		backToAdmin(w, r)
		return
	}
	err := saveConfig(c)
	if err != nil {
		setAdminMsg("动态验证码已%s（仅内存生效，没写进磁盘）：%v", onOff(on), err)
	} else {
		setAdminMsg("动态验证码已%s。下次打开登录页即生效，不用重启。", onOff(on))
	}
	secNote("登录方式变更", ip, "动态验证码=%s（当前可用：%s）", onOff(on), modesSummary())
	backToAdmin(w, r)
}

// handleGithubSave 保存 GitHub 登录配置（后台页手填，密钥不回显）。
func handleGithubSave(w http.ResponseWriter, r *http.Request) {
	if !adminPost(w, r) {
		return
	}
	ip := clientIP(r)
	c := configSnapshot()
	c.GitHub.ClientID = strings.TrimSpace(r.FormValue("clientId"))
	if s := strings.TrimSpace(r.FormValue("clientSecret")); s != "" {
		c.GitHub.ClientSecret = s // 留空 = 不改，避免后台页把密钥回显到浏览器
	}
	c.GitHub.Allow = splitAllow(r.FormValue("allow"))
	c.GitHub.Enabled = r.FormValue("enabled") == "1"
	if c.GitHub.Enabled && !(c.GitHub.ClientID != "" && c.GitHub.ClientSecret != "" && len(c.GitHub.Allow) > 0) {
		setAdminMsg("没保存：要开启 GitHub 登录，客户端 ID、客户端密钥、允许名单三项都得填。")
		secNote("GitHub 配置", ip, "被拒：开启但配置不完整")
		backToAdmin(w, r)
		return
	}
	if pw, totp, gh := modesOf(c); !pw && !totp && !gh {
		setAdminMsg("没保存：这会让所有登录方式都关掉，谁也进不来。")
		secNote("GitHub 配置", ip, "被拒：会导致没有任何登录方式")
		backToAdmin(w, r)
		return
	}
	err := saveConfig(c)
	if err != nil {
		setAdminMsg("GitHub 配置已保存（仅内存生效，没写进磁盘）：%v", err)
	} else {
		setAdminMsg("GitHub 配置已保存：登录=%s，允许名单 %d 个账号。", onOff(c.GitHub.Enabled), len(c.GitHub.Allow))
	}
	secNote("GitHub 配置", ip, "登录=%s，ClientID=%s，允许名单=%d 个",
		onOff(c.GitHub.Enabled), c.GitHub.ClientID, len(c.GitHub.Allow))
	backToAdmin(w, r)
}

// handleRepair 在后台页粘贴 DSH 令牌重新配对（DSH 重启后令牌作废、会话失效时用）。
func handleRepair(w http.ResponseWriter, r *http.Request) {
	if !adminPost(w, r) {
		return
	}
	ip := clientIP(r)
	token := strings.TrimSpace(r.FormValue("dstoken"))
	if token == "" {
		setAdminMsg("请先在输入框里粘贴 DSH 令牌。")
		backToAdmin(w, r)
		return
	}
	pairCookie, err := dshPair(r, token)
	if err != nil {
		secNote("令牌换票失败", ip, "%v", err)
		setAdminMsg("配对失败：%v。DSH 重启后旧令牌即作废，请在服务器上取最新的一条。", err)
		backToAdmin(w, r)
		return
	}
	http.SetCookie(w, pairCookie)
	stampDSHSession(w, r)
	secNote("令牌换票成功", ip, "已从后台页重新配对 DSH 会话")
	setAdminMsg("配对成功，本设备已经拿到新的 DSH 会话。")
	backToAdmin(w, r)
}

func withGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case gatePrefix + "/login":
			handleLogin(w, r)
			return
		case gatePrefix + "/logout":
			handleLogout(w, r)
			return
		case gatePrefix + "/oauth/github/start":
			handleGitHubStart(w, r)
			return
		case gatePrefix + "/oauth/github/callback":
			handleGitHubCallback(w, r)
			return
		case "/gate":
			// 短地址：好记、可收藏。未登录时会被后台页拦到登录页，
			// 登录成功后 next 会把人送回 /__gate/admin
			http.Redirect(w, r, gatePrefix+"/admin", http.StatusFound)
			return
		}
		if c, err := r.Cookie(cookieName); err == nil && cookieValid(c.Value) {
			// 后台页与门禁同权限，不额外开鉴权口子
			switch r.URL.Path {
			case gatePrefix + "/admin":
				handleAdmin(w, r)
				return
			case gatePrefix + "/restart":
				handleRestart(w, r)
				return
			case gatePrefix + "/methods":
				handleMethods(w, r)
				return
			case gatePrefix + "/github":
				handleGithubSave(w, r)
				return
			case gatePrefix + "/repair":
				handleRepair(w, r)
				return
			case gatePrefix + "/logout-all":
				// 一键踢光所有设备（1.8.0）：会话代数 +1，全部旧 Cookie 作废
				handleLogoutAll(w, r)
				return
			case gatePrefix + "/market":
				// 插件安装/启停/更新/卸载（1.8.0）：转给市场，异步执行
				handleMarket(w, r)
				return
			}
			// ★ 下面这些接口族自带 loopback 围栏，但**不校验 DSH 会话**：实测不带
			//   任何 DSH Cookie 一样返回 200。只放行回环身份就等于把「门禁 + DSH 令牌」
			//   压成一层 —— 远端执行接口能在用户配置的所有主机上执行命令，配置管理器
			//   能导出配置，搜索设置能读改写上游凭据。所以这里加第二层：
			//   DSH 真的认这个会话，且没有超出本地记录的有效期，才放行（fail-closed）。
			//
			// 1.8.0 再把 20 条市场写路由（marketMutationPaths，install/uninstall/
			//   toggle/…）一并纳入：2026-10-03 读 dshmarket 源码确认，这些写接口
			//   自身只有 sameOrigin 一道门、**没有任何会话检查**，而它们能改插件
			//   的安装与启停 —— 同样不能只靠门禁一层。读路由（installed/status 等）
			//   保持原样，不拦只读数据。
			if (sessionRequiredPath(r.URL.Path) || marketMutationPath(r.URL.Path)) && !dshSessionFresh(r) {
				secNote("接口缺有效 DSH 会话", clientIP(r), "%s %s", r.Method, r.URL.Path)
				http.Error(w, "需要有效的 DSH 会话", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		secNote("未鉴权拦截", clientIP(r), "%s %s", r.Method, r.URL.Path)
		if wantsHTML(r) {
			renderLogin(w, http.StatusUnauthorized, "", false, 0, r.URL.RequestURI(), dshHasSession(r))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	})
}

// dshSSHPrefix 是「远端执行」接口族：这些接口会在用户配置的远端主机上执行命令。
// 它自己带 loopback-only 围栏（见 loopbackOnlyPrefixes），但**不校验 DSH 会话**；
// 只放行回环身份就等于把「门禁 + DSH 令牌」压成一层，所以 withGate 另加第二层。
const dshSSHPrefix = "/api/dsh-ssh/"

// 另外几个同类前缀（2026-09-28 / 2026-10-03 实测）：
//
//	/api/dsh-config-manager/        配置管理器：导出/下载 profile 配置、崩溃救援、备份计划
//	/api/dsh-free-search-settings/  free-search 面板的配置桥：读写上游搜索服务的凭据
//	/api/market/                    应用市场客户端：列已装、装皮肤/预设/宠物
//
// 三者都是插件自带的「Host 必须是回环」围栏（源码里的 isLoopbackRequest /
// loopback requests only），DSH 的 --trusted-host 对它无效，于是经反代一律 403
// （free-search 的设置面板因此整个是坏的、市场面板的「已安装」列表也出不来）。
// **同时也都不带任何 DSH 会话就能访问**，所以它们不是「加进前缀就完事」，
// 必须一并进第二层。
const (
	configManagerPrefix      = "/api/dsh-config-manager/"
	freeSearchSettingsPrefix = "/api/dsh-free-search-settings/"
	marketPrefix             = "/api/market/"
)

// sessionRequiredPrefixes 列出「除门禁之外还必须带有效 DSH 会话」的接口前缀。
var sessionRequiredPrefixes = []string{
	dshSSHPrefix,
	configManagerPrefix,
	freeSearchSettingsPrefix,
	marketPrefix,
}

// sessionRequiredPath 报告路径是否属于「必须有 DSH 会话」的接口族。
func sessionRequiredPath(path string) bool {
	for _, prefix := range sessionRequiredPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// loopbackOnlyPrefixes 列出「仅回环同源」类插件接口的前缀。
// 这些插件把接口围栏为 loopback-only：Host 必须是 127.0.0.1/localhost 且
// Origin 与之相等，DSH 的 --trusted-host 对这类围栏不生效，于是经反代访问
// 时一律被拒（任务看板 403、技能中心 400、用量统计/modlens/modsearch 403）。
// 经门禁（已完成鉴权）转发时向上游补上回环身份即可放行。
// 将来遇到同类插件，把它的接口前缀加到这里。
var loopbackOnlyPrefixes = []string{
	"/api/task-board/",
	"/api/dsh-skill-explorer/",
	"/api/dsh-provider-usage/",
	dshSSHPrefix,
	configManagerPrefix,
	freeSearchSettingsPrefix,
	marketPrefix,
	"/modlens/",
	"/modsearch/",
}

func loopbackOnlyPath(path string) bool {
	for _, prefix := range loopbackOnlyPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// marketMutationPaths 列出「需要回环身份」的市场变更路由（**精确匹配**）。
//
// 背景：dshmarket 1.56.0（上游 commit 9be13bf，修 #678 DNS rebinding）给
// sameOrigin 加了 loopbackAuthority(host)：Host 必须是 127.0.0.1 / localhost /
// [::1]。1.55.0 只比对 Origin==Host，所以经门禁（Host 为域名）本来是放行的；
// 1.56.0 起，市场的全部写操作经反代一律 403 "untrusted origin"。
//
// ★ 为什么用精确匹配，而不是往 loopbackOnlyPrefixes 加 "/dsh-market/"：
//   实测 /dsh-market/backup 与 /dsh-market/logs **不带任何 DSH 会话**就能拿到
//   profile 配置与日志 —— 它们唯一的门就是 sameOrigin。用前缀一把梭等于把
//   「门禁 + DSH 令牌」压成一层（同 1.5.1 的教训）。这里只列「唯一能力就是
//   管理插件」的路由。
//
// 注意别把 /dsh-market/（市场插件本体）和 /api/market/（市场客户端
// @linxin666/dsh-client-ui-market）搞混：后者只有「列已装 + 装皮肤/预设/宠物」，
// 没有导出配置或读日志这类能力，所以走前缀 + 第二层（见 marketPrefix）。
//
// 刻意排除（仍由市场自己的围栏挡住，经门禁保持 403）：
//
//	/dsh-market/backup、/restore、/restore-snapshot、/delete-snapshot、
//	/snapshots、/rollback、/gist、/webdav、/logs、/self-uninstall
var marketMutationPaths = map[string]bool{
	// 插件安装 / 卸载 / 更新 / 启停
	"/dsh-market/install":   true,
	"/dsh-market/uninstall": true,
	"/dsh-market/update":    true,
	"/dsh-market/toggle":    true,
	"/dsh-market/cancel":    true,
	// 安装源与构建授权
	"/dsh-market/migrate-source": true,
	"/dsh-market/approve-builds": true,
	"/dsh-market/setup-pnpm":     true,
	// 市场自身偏好（纯 UI 状态，不含凭据）
	"/dsh-market/channel":                 true,
	"/dsh-market/region":                  true,
	"/dsh-market/favorite":                true,
	"/dsh-market/note":                    true,
	"/dsh-market/groups":                  true,
	"/dsh-market/presets":                 true,
	"/dsh-market/bundle-order":            true,
	"/dsh-market/use-skin":                true,
	"/dsh-market/github-proxy":            true,
	"/dsh-market/discovery-compatibility": true,
	// 更新 API v1（/api/v1/restart 见 processControlPaths）
	"/dsh-market/api/v1/updates":  true,
	"/dsh-market/api/v1/rollback": true,
}

func marketMutationPath(path string) bool { return marketMutationPaths[path] }

// processControlPaths 列出「拒绝一切转发痕迹」的市场路由（**精确匹配**）。
//
// 插件市场（dshmarket）的重启路由用 trustedRestartRequest 判定：对端是回环、
// 且**完全没有** Forwarded / X-Forwarded-For / X-Real-IP 任一痕迹、且 Origin 的
// authority 等于 Host —— 三者齐备才放行。它把「有转发头」直接等同于「来的是代理，
// 不是本人」，这是有意为之的安全设计。
//
// 而 Go 反代的 SetXForwarded() 对每个上游请求都必然补上 X-Forwarded-For，
// 于是市场里的「立即重启」按钮经门禁永远失败（实测 403
// "restart is limited to same-origin loopback requests"；去掉这一个头即放行，
// 因为 Host 与 Origin 本就相等、对端本就是回环）。
//
// ★ 只列重启这一条，**绝不能用前缀 "/dsh-market/" 一把梭**。
//   市场把「重启 / 导出配置 / 自卸载」放在同一道严门后面，而市场那些接口
//   **不要求 DSH 会话**——它们的唯一访问控制就是这道门。用前缀放行的实测后果是：
//   只带门禁会话就能下载 profile 配置（含凭据线索）、自卸载市场插件，
//   把「门禁 + DSH 令牌」的双层模型压成一层。
//   重启这两条路径的唯一能力就是「重启」，放行它们不扩大任何权限。
var processControlPaths = map[string]bool{
	"/dsh-market/restart":        true, // 市场横幅「立即重启」按钮走这条
	"/dsh-market/api/v1/restart": true, // v1 别名，内部 invokeLegacy 复用同一个 handler
}

func processControlPath(path string) bool {
	return processControlPaths[path]
}

// hasDotSegment 报告路径里是否含 "." 或 ".." 段。
//
// 为什么必须查它：门禁的前缀判定看的是**解码后**的路径，而上游收到的是**原始编码**
// 路径并会自行归一化（实测 DSH 把 /api/task-board/%2e%2e/%2e%2e/dsh-market/backup
// 归一化成 /dsh-market/backup）。两者不一致就等于给「回环身份白名单」开了后门：
// 一个解码后以某白名单前缀开头的路径，落地却可以是任意别的上游路径。
// 含点段的路径本来就不是合法插件接口，直接不给回环身份（请求照常转发，
// 由插件自己的围栏去拒），比事后补救简单。
func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// ---------- 反代 ----------

// ★ Directive：Rewrite / ModifyResponse / ErrorHandler 拿到的都是**出站请求**
// （Rewrite 的 pr.Out，另两处的 resp.Request / r 也都是它）。出站请求上
// pr.SetXForwarded() 已经把入站 RemoteAddr（也就是 nginx 的 127.0.0.1）追加到
// X-Forwarded-For 末尾，于是 clientIP() 取「最后一跳」必然拿到 127.0.0.1：
//
//	2026-09-27 实测 docker logs dshai-gate 的 41 条「上游错误」100% 记成
//	ip=127.0.0.1，而同机由 withGate 记录的「未鉴权拦截」（入站请求）拿到的是
//	真实 IP 202.107.251.210 —— 差别只在于用的哪个请求。
//
// 所以在 Rewrite 里把 pr.In 存进出站请求的 context，下游统一用 origRequest 取回。
type origReqKey struct{}

// origRequest 取回入站（浏览器原始）请求；取不到就退回传进来的请求。
func origRequest(r *http.Request) *http.Request {
	if r != nil {
		if v, ok := r.Context().Value(origReqKey{}).(*http.Request); ok && v != nil {
			return v
		}
	}
	return r
}

// attribBody 包装上游响应体，把「复制响应体时被截断」这个错误带上归因再记录。
//
// 为什么必须自己包装：这条错误由 stdlib reverseproxy.go:650 的 p.logf 直接输出，
//
//	httputil: ReverseProxy read error during body copy: unexpected EOF
//
// 只有错误文本，没有 IP、没有路径（2026-09-27 实测 25 小时 32 条，全部无归属，
// 且严格成对出现、每个时间点都紧贴 DSH 停机 —— 是 DSH 断开时截断两条常驻流的产物）。
// 把 ErrorLog 指向 io.Discard 免得同一条被记两遍；Go 1.23 里 logf 只剩三个调用点：
// reverseproxy.go:307（defaultErrorHandler，已被我们的 ErrorHandler 取代）、
// :527（仅测试环境）、:650（就是这一条）—— 所以丢掉的只有重复行。
type attribBody struct {
	rc   io.ReadCloser
	orig *http.Request
}

func (b *attribBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err != nil && err != io.EOF && err != context.Canceled {
		secNote("响应流中断", clientIP(b.orig), "%s %s: %v", b.orig.Method, b.orig.URL.Path, err)
	}
	return n, err
}

func (b *attribBody) Close() error { return b.rc.Close() }

// sessionExpiredResponse 把上游的裸 401 就地换成门禁登录页。
//
// 这是「门禁会话还有效、DSH 那层已经失效」的恢复路径：withGate 只凭门禁 Cookie
// 放行，DSH 回的 401 以前原样透传，浏览器看到的是 DSH 自己的
// `dsh web authentication required; reopen the URL printed by dsh web.`，
// 没有任何登录页可进（2026-09-27 在生产实测复现）。两边 Cookie 一起被清的情况
// 本来就会落到 withGate 的未鉴权分支，不经过这里。
func sessionExpiredResponse(resp *http.Response, orig *http.Request) {
	body := loginBytes(newLoginView("", false, 0, orig.URL.RequestURI(), false))
	secNote("DSH 会话失效", clientIP(orig), "%s %s", orig.Method, orig.URL.Path)

	_ = resp.Body.Close() // 401 体一律丢弃
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Status = fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))

	h := resp.Header
	// ★ 必须删：否则浏览器弹原生用户名/口令框，盖在登录页上
	h.Del("WWW-Authenticate")
	// ★ 必须删：DSH 若下发严格 CSP，登录页的内联 <style>/<script>
	//   与 data: URI favicon（gate/login.html 首行）会被直接挡掉 —— 页面无样式、复制按钮失效
	h.Del("Content-Security-Policy")
	h.Del("Content-Security-Policy-Report-Only")
	h.Del("Content-Encoding")
	h.Del("Content-Range")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	// 上游 401 上的 Set-Cookie 保留透传（DSH 顺手清自己的 Cookie 是它该做的事）
}

func newProxy(target *url.URL, inject bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		ErrorLog: log.New(io.Discard, "", 0), // 见 attribBody 注释
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// ★ 关键：SetURL 会把 Host 改成上游地址，必须改回原域名，
			//   否则 DSH 的 --trusted-host 校验失败，特权接口全部 403
			pr.Out.Host = pr.In.Host
			// ★ 仅回环类接口 + 市场变更路由（见 marketMutationPaths）+ 重启路由：
			//   向上游呈现回环身份（Host + Origin 同步），
			//   否则插件自身的 loopback-only 围栏会拒绝经反代来的合法请求。
			//   其余路径一律保持原 Host，避免影响 DSH 的 Cookie 归属与信任校验。
			//   含 "." / ".." 段的路径不给身份：它会与上游归一化后的落地路径不一致，
			//   等于给白名单开后门（见 hasDotSegment 注释）。
			// path 取一次：回环身份判定与转发头擦除共用。
			path := pr.In.URL.Path
			if (loopbackOnlyPath(path) || marketMutationPath(path) || processControlPath(path)) && !hasDotSegment(path) {
				pr.Out.Host = target.Host
				if pr.In.Header.Get("Origin") != "" {
					pr.Out.Header.Set("Origin", "http://"+target.Host)
				}
			}
			pr.SetXForwarded()
			// ★ 市场重启路由：擦掉转发痕迹。市场自己那道「无转发头 = 本机直连」
			//   的严门会把经门禁来的合法请求一律 403（重启按钮失效）。
			//   只对精确的重启路径生效，不动其它市场路由（见 processControlPaths 注释）。
			//   注意：trustedRestartRequest 除了要求「无转发头」还要求 Host 是回环，
			//   所以上面那一步也必须把这两条路径算进回环身份，否则经域名进来仍是 403。
			if processControlPath(path) {
				pr.Out.Header.Del("X-Forwarded-For")
				pr.Out.Header.Del("X-Real-IP")
				pr.Out.Header.Del("Forwarded")
			}
			// ★ 必须禁用上游压缩，否则响应体是 gzip，注入静默失效
			pr.Out.Header.Set("Accept-Encoding", "identity")
			// ★ 把入站请求存进出站请求的 context：ModifyResponse / ErrorHandler
			//   只能拿到出站请求，而 clientIP 必须用入站那个（见 origReqKey 注释）。
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), origReqKey{}, pr.In))
		},
		ModifyResponse: func(resp *http.Response) error {
			orig := origRequest(resp.Request)
			// ★ 会话失效检测：只拦「文档导航 + 上游 401 + 复核确认没有 DSH 会话」。
			//   复核（dshHasSession）让这成为精确触发器而不是启发式：某条插件路由
			//   对合法会话回 401 时探测得 200，于是不拦、保持原样。
			//   XHR / SSE / 静态资源被 wantsHTML 挡住，不会拿到 HTML 体。
			if resp.StatusCode == http.StatusUnauthorized && wantsHTML(orig) && !dshHasSession(orig) {
				sessionExpiredResponse(resp, orig)
				return nil
			}
			// ★ 101（WebSocket / h2c 升级）的响应体是**双向连接**：httputil 在
			//   handleUpgradeResponse 里会断言 io.ReadWriteCloser（reverseproxy.go:748）。
			//   包装它等于丢掉这个接口，升级请求被打成 502
			//   "internal error: 101 switching protocols response with non-writable body"
			//   ——2026-09-27 部署 1.6.0 后在生产的 GET /api/remote.mux 上实测到。
			if resp.Body != nil && resp.StatusCode != http.StatusSwitchingProtocols {
				resp.Body = &attribBody{rc: resp.Body, orig: orig}
			}
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if strings.HasPrefix(ct, "text/event-stream") {
				resp.Header.Set("Cache-Control", "no-cache, no-transform")
				resp.Header.Set("X-Accel-Buffering", "no")
				return nil
			}
			if !inject || !strings.Contains(ct, "text/html") || resp.Body == nil {
				return nil
			}
			if enc := strings.TrimSpace(resp.Header.Get("Content-Encoding")); enc != "" && enc != "identity" {
				log.Printf("上游仍返回压缩(%s)，跳过注入: %s", enc, pathOf(resp))
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			i := bytes.LastIndex(bytes.ToLower(body), []byte("</head>"))
			if i < 0 {
				resp.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}
			out := append(append(append([]byte{}, body[:i]...), []byte(injection)...), body[i:]...)
			resp.Body = io.NopCloser(bytes.NewReader(out))
			resp.ContentLength = int64(len(out))
			resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
			log.Printf("已注入 (%d→%d 字节): %s", len(body), len(out), pathOf(resp))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// ★ 必须用入站请求：r 是出站请求，其 XFF 末尾是 nginx 的 127.0.0.1，
			//   直接 clientIP(r) 会让所有上游错误都记在同一个 IP 上（见 origReqKey 注释）。
			orig := origRequest(r)
			secNote("上游错误", clientIP(orig), "%s %s: %v", orig.Method, orig.URL.Path, err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`<meta charset="utf-8"><h3>DSH 暂不可达</h3>` +
				`<p>容器可能正在启动或已停止。服务器上执行：<code>cd /opt/dshai && docker compose ps</code></p>`))
		},
	}
}

func pathOf(resp *http.Response) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.Path
	}
	return "?"
}

// ---------- 启动 ----------

func main() {
	listen := env("GATE_LISTEN", "127.0.0.1:2299")
	listenAddr = listen
	raw := env("GATE_UPSTREAM", "http://127.0.0.1:3082")
	inject := env("GATE_INJECT", "1") == "1"
	siteTitle = env("GATE_SITE_TITLE", "Harness")
	pwHash = strings.ToLower(strings.TrimSpace(os.Getenv("GATE_PASSWORD_HASH")))
	secret = strings.TrimSpace(os.Getenv("GATE_SESSION_SECRET"))
	sessionDs, _ = strconv.Atoi(env("GATE_SESSION_DAYS", "30"))
	needPw = len(pwHash) == 64
	if !needPw && pwHash != "" {
		log.Fatal("门禁配置错误：GATE_PASSWORD_HASH 格式不对（应为 64 位 hex）")
	}
	if rawSec := strings.ToUpper(strings.Join(strings.Fields(os.Getenv("GATE_TOTP_SECRET")), "")); rawSec != "" {
		b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(rawSec)
		if err != nil || len(b) < 10 {
			log.Fatalf("门禁配置错误：GATE_TOTP_SECRET 不是合法的 base32 密钥（%v）", err)
		}
		totpSecret = b
		needTotp = true
	}
	if len(secret) < 16 {
		log.Fatal("门禁未配置：GATE_SESSION_SECRET 缺失或过短。请运行 bash /opt/dshai/scripts/set-password.sh 或 set-totp.sh")
	}
	if sessionDs <= 0 {
		sessionDs = 30
	}
	dshSessionDs, _ = strconv.Atoi(env("GATE_DSH_SESSION_DAYS", "30"))
	if dshSessionDs <= 0 {
		dshSessionDs = 30
	}
	githubOAuthBase = strings.TrimSuffix(env("GATE_GITHUB_OAUTH_BASE", "https://github.com"), "/")
	githubAPIBase = strings.TrimSuffix(env("GATE_GITHUB_API_BASE", "https://api.github.com"), "/")

	// 需求②（1.9.0）：用户名维度 + DSH 会话自动获取。
	// GATE_USERNAME 必须与 GATE_PASSWORD_HASH 同配 —— 只写用户名没口令没有意义。
	gateUser = strings.TrimSpace(os.Getenv("GATE_USERNAME"))
	if gateUser != "" {
		if !needPw {
			log.Fatal("门禁配置错误：GATE_USERNAME 需要同时配置 GATE_PASSWORD_HASH（用户名必须配口令）")
		}
		gateUserHash = hashPassword("u:" + gateUser)
	}
	// GATE_DSH_SESSION_KEY：.credentials.yaml 里 client-connection/browser-session 的
	// 32 字节 base64url secret（可带 = padding）。配上后门禁自己签 dsh-auth-* Cookie，
	// 登录页不再显示 DSH 令牌输入框；配错只在实际换会话时暴露（探活 401），启动不拦。
	if k := strings.TrimSpace(os.Getenv("GATE_DSH_SESSION_KEY")); k != "" {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k, "="))
		if err != nil || len(b) != 32 {
			log.Fatal("门禁配置错误：GATE_DSH_SESSION_KEY 必须是 base64url 编码的 32 字节 secret（取自 .credentials.yaml 的 client-connection/browser-session）")
		}
		dshAutoKey = b
	}

	// 后台可改的配置（落盘）。放在 fail-closed 之前：GitHub 登录就是在后台开的，
	// 关掉动态密码后能不能启动，取决于这个文件读得读不出来。
	loadConfig(env("GATE_STATE", "/data/state.json"))

	// 历史日志落盘（1.8.0）。GATE_LOG：
	//   缺省 = 状态文件同目录 log.jsonl（跟着 GATE_STATE 走，即 /data 卷）
	//   显式 off / 0 / false = 关闭
	//   其它 = 指定路径（目录自动创建 0700、文件 0600）
	logPath := strings.TrimSpace(os.Getenv("GATE_LOG"))
	if strings.EqualFold(logPath, "off") || logPath == "0" || strings.EqualFold(logPath, "false") {
		logPath = ""
	} else if logPath == "" && cfgPath != "" {
		logPath = filepath.Join(filepath.Dir(cfgPath), "log.jsonl")
	}
	if b := strings.TrimSpace(os.Getenv("GATE_LOG_BYTES")); b != "" {
		if n, err := strconv.Atoi(b); err == nil && n >= 4096 {
			histRotateSize = int64(n)
		}
	}
	if logPath != "" {
		if err := histOpen(logPath); err != nil {
			secNote("历史日志", "-", "落盘打开失败（%v），本次运行只记内存", err)
		}
	}
	// 落盘/巡检状态给启动横幅用（放在 histOpen 之后才是真实状态）
	logDesc := "关"
	if p, _ := histSizeDesc(); p != "" {
		logDesc = p
	}

	// DSH 健康巡检（1.8.0）：GATE_HEALTH_INTERVAL 秒探一次上游，
	//   0 = 关。事件判据在 healthState.step：首通记「就绪」（不冒充重启）、
	//   连挂 3 次记一次「不可达」、由停转通记「重启（中断 X 秒）」。
	hi := 5
	if v := strings.TrimSpace(os.Getenv("GATE_HEALTH_INTERVAL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hi = n
		}
	}
	healthDesc := "关"
	if hi > 0 {
		healthInterval = time.Duration(hi) * time.Second
		healthDesc = healthInterval.String()
		go healthLoop()
	}

	if pw, totp, gh := loginModes(); !pw && !totp && !gh {
		log.Fatal("门禁未配置：既没有口令，也没有可用的动态验证码 / GitHub 登录 —— 拒绝启动（fail-closed）。请运行 scripts/set-totp.sh，或先在后台配好 GitHub 登录")
	}

	target, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("上游地址无效: %v", err)
	}
	upstreamURL = target

	secNote("启动", "-", "v%s 监听 %s → %s（%s，会话=%d 天，DSH 会话=%d 天，注入=%v，时区=%s，历史落盘=%s，巡检=%s）",
		gateVersion, listen, target, modesSummary(), sessionDs, dshSessionDs, inject, time.Local.String(), logDesc, healthDesc)
	srv := &http.Server{
		Addr:              listen,
		Handler:           withGate(newProxy(target, inject)),
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
