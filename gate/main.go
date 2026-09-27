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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed login.html
var loginHTML string

var loginTpl = template.Must(template.New("login").Parse(loginHTML))

const injection = `<script>try{window.__DSH_TRANSPORT__=Object.assign(window.__DSH_TRANSPORT__||{},{ownsHost:true})}catch(e){}</script><style>[data-slot="settings.action"]{display:none!important}</style>`

const (
	gatePrefix   = "/__gate"
	gateVersion  = "1.5.4"
	cookieName   = "dshai_gate"
	pwSalt       = "dshai-gate-v1"
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

	replayMu   sync.Mutex
	lastUsedCt uint64
)

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
	maxAge := sessionDs * 86400
	exp := time.Now().Add(time.Duration(sessionDs) * 24 * time.Hour).Unix()
	p := "v1." + strconv.FormatInt(exp, 10)
	return p + "." + sign(p), maxAge
}

func cookieValid(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(sign(parts[0]+"."+parts[1])), []byte(parts[2]))
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
// 噪声控制：同一 IP 的同类事件在 secCoalesce 内合并为一条并累加次数，
// 因此 stdout 也只在「新事件」时写一行——否则扫描器能把 docker 日志刷爆。
// ponytail: 未鉴权拦截同样进环形缓冲，海量分布式扫描仍可能挤掉旧记录（上限 secLogMax 条）。

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

func secNote(kind, ip, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	secMu.Lock()
	defer secMu.Unlock()
	secSeen++
	if n := len(secLog); n > 0 {
		if last := &secLog[n-1]; last.Kind == kind && last.IP == ip &&
			time.Since(last.Time) < secCoalesce {
			last.Count++
			last.Time = time.Now()
			last.Text = text
			return
		}
	}
	log.Printf("门禁：%s ip=%s %s", kind, ip, text)
	secLog = append(secLog, secEvent{Time: time.Now(), Kind: kind, IP: ip, Text: text, Count: 1})
	if len(secLog) > secLogMax {
		secLog = secLog[1:]
	}
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
	HasSession   bool
	TokenNeeded  bool
}

func subtitleOf() string {
	switch {
	case needPw && needTotp:
		return "需要口令 + 动态验证码"
	case needTotp:
		return "需要动态验证码"
	default:
		return "需要访问口令"
	}
}

func tipOf() string {
	if needPw && needTotp {
		return "双因子保护 · 仅限本人使用"
	}
	if needTotp {
		return "受动态验证码保护 · 仅限本人使用"
	}
	return "受口令保护 · 仅限本人使用"
}

func renderLogin(w http.ResponseWriter, status int, errMsg string, locked bool, remain time.Duration, next string, hasSession bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = loginTpl.Execute(w, loginView{
		Title: siteTitle, Subtitle: subtitleOf(), Tip: tipOf(),
		Next: sanitizeNext(next), Error: errMsg, Locked: locked,
		Remain: humanDur(remain), NeedPassword: needPw, NeedTOTP: needTotp,
		HasSession: hasSession, TokenNeeded: !hasSession,
	})
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

	if needPw {
		got := hashPassword(r.FormValue("password"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(pwHash)) != 1 {
			fail("口令不正确")
			return
		}
	}
	var totpCt uint64
	if needTotp {
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

	// DSH 令牌：本设备已有有效 DSH 会话时可留空；否则必须提供并当场换票配对
	token := strings.TrimSpace(r.FormValue("dstoken"))
	if token == "" {
		if !hasSession {
			time.Sleep(baseDelay)
			renderLogin(w, http.StatusUnauthorized,
				"本设备还没有 DSH 会话，请在下方填写 DSH 令牌", false, 0, next, false)
			return
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
	if needTotp {
		markTotpUsed(totpCt)
	}

	clearFail(ip)
	val, maxAge := issueCookie()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: val, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
	secNote("登录成功", ip, "方式=%s", subtitleOf())
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	secNote("登出", clientIP(r), "")
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
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
<meta http-equiv="refresh" content="10">
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
    <h1>{{.Title}} · 安全日志<small>v{{.Version}} · 已运行 {{.Uptime}} · 每 10 秒自动刷新</small></h1>
  </div>
  <nav class="actions">
    <a class="btn" href="/" target="_blank" rel="noopener">进入 DSH ↗</a>
    <a class="btn ghost" href="/__gate/admin">立即刷新</a>
    <a class="btn ghost danger" href="/__gate/logout">退出登录</a>
  </nav>
</header>

<div class="card">
  <h2>当前状态</h2>
  <div class="stats">
    <div class="stat"><b>登录方式</b><span>{{.Mode}}</span></div>
    <div class="stat"><b>本设备会话</b><span>剩余 {{.SessionLeft}}</span></div>
    <div class="stat"><b>监听 → 上游</b><span>{{.Listen}} → {{.Upstream}}</span></div>
    <div class="stat"><b>事件计数</b><span>{{.Total}} 条（显示最近 {{.Shown}} 条）</span></div>
    <div class="stat"><b>全局限流</b><span>当前响应延迟 {{.Delay}}</span></div>
    <div class="stat"><b>锁定中的 IP</b><span>{{if .Locks}}{{range .Locks}}<span class="pill">{{.IP}} · 剩余 {{.Until}} · 失败 {{.Fails}} 次</span>{{end}}{{else}}无{{end}}</span></div>
  </div>
</div>

<div class="card">
  <h2>DSH 控制</h2>
  <div class="stats">
    <div class="stat"><b>重启状态</b><span>{{if .RestartBusy}}<span class="badge badge-warn">进行中</span>{{else}}<span class="badge badge-ok">就绪</span>{{end}}</span></div>
    <div class="stat"><b>最近一次发起</b><span>{{if .RestartAt}}{{.RestartAt}}{{else}}还没有{{end}}</span></div>
    <div class="stat"><b>结果</b><span>{{if .RestartResult}}{{.RestartResult}}{{else}}—{{end}}</span></div>
  </div>
  <form method="post" action="/__gate/restart" class="restartbar">
    <button class="btn" type="submit"{{if .RestartBusy}} disabled{{end}}>重启 DSH</button>
    <span class="muted">装了插件、改了配置，需要重启才生效时用这里。会中断正在进行的对话约 30 秒；重启期间本页每 10 秒自动刷新，进度就在上面。</span>
  </form>
</div>

<div class="card">
  <h2>最近事件（最新在上；同一 IP 的同类事件 30 秒内合并计数）</h2>
  <div class="tablewrap"><table>
    <thead><tr>
      <th scope="col">时间</th><th scope="col">事件</th><th scope="col">来源 IP</th><th scope="col">说明</th><th scope="col" style="text-align:right">次数</th>
    </tr></thead>
    <tbody>
    {{range .Events}}<tr>
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
</div>

<div class="foot">只保留内存中最近 {{.Max}} 条，容器重启即清空 · 短地址 <a href="/gate">/gate</a></div>
</div>
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
	Delay       string
	Max         int
	Locks       []adminLock
	Events      []adminEvent

	RestartBusy   bool
	RestartAt     string
	RestartResult string
}

// toneOf 把事件种类映射成配色：失败类红、拦截类黄、成功类绿、其余中性
func toneOf(kind string) string {
	switch kind {
	case "登录成功", "令牌换票成功", "登出":
		return "ok"
	case "验证失败", "锁定", "动态码重放", "令牌换票失败", "上游错误":
		return "err"
	case "未鉴权拦截", "锁定期间尝试":
		return "warn"
	default:
		return "info"
	}
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

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	evs, total := secSnapshot()
	rows := make([]adminEvent, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- { // 最新在最上面
		e := evs[i]
		rows = append(rows, adminEvent{
			Time: e.Time.Format("01-02 15:04:05"), Kind: e.Kind, Tone: toneOf(e.Kind),
			IP: e.IP, Text: e.Text, Count: e.Count,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	busy, at, result := restartSnapshot()
	_ = adminTpl.Execute(w, adminView{
		Title: siteTitle, Version: gateVersion, Uptime: humanUptime(time.Since(startedAt)),
		Mode: subtitleOf(), SessionDays: sessionDs, SessionLeft: sessionLeft(r),
		Listen: listenAddr, Upstream: upstreamURL.String(),
		Total: total, Shown: len(rows), Delay: globalDelay().String(), Max: secLogMax,
		Locks: lockedSnapshot(), Events: rows,
		RestartBusy: busy, RestartAt: at, RestartResult: result,
	})
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
		case "/gate":
			// 短地址：好记、可收藏。未登录时会被后台页拦到登录页，
			// 登录成功后 next 会把人送回 /__gate/admin
			http.Redirect(w, r, gatePrefix+"/admin", http.StatusFound)
			return
		}
		if c, err := r.Cookie(cookieName); err == nil && cookieValid(c.Value) {
			// 后台页与门禁同权限，不额外开鉴权口子
			if r.URL.Path == gatePrefix+"/admin" {
				handleAdmin(w, r)
				return
			}
			if r.URL.Path == gatePrefix+"/restart" {
				handleRestart(w, r)
				return
			}
			// ★ 远端执行接口的第二层：它自带 loopback 围栏但不校验 DSH 会话，
			//   仅凭门禁 Cookie 就能在用户所有主机上执行命令。这里用浏览器带来的
			//   Cookie 探一次 DSH，没有有效会话即拒（fail-closed）。
			if dshSSHPath(r.URL.Path) && !dshHasSession(r) {
				secNote("远端执行接口缺 DSH 会话", clientIP(r), "%s %s", r.Method, r.URL.Path)
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

// dshSSHPath 报告路径是否属于远端执行接口族。
func dshSSHPath(path string) bool { return strings.HasPrefix(path, dshSSHPrefix) }

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

func newProxy(target *url.URL, inject bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
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
		},
		ModifyResponse: func(resp *http.Response) error {
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
			secNote("上游错误", clientIP(r), "%s %s: %v", r.Method, r.URL.Path, err)
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
	if !needPw && !needTotp {
		log.Fatal("门禁未配置：既没有 GATE_PASSWORD_HASH 也没有 GATE_TOTP_SECRET —— 拒绝启动（fail-closed）。请运行 scripts/set-totp.sh")
	}
	if sessionDs <= 0 {
		sessionDs = 30
	}

	target, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("上游地址无效: %v", err)
	}
	upstreamURL = target

	secNote("启动", "-", "v%s 监听 %s → %s（%s，会话=%d 天，注入=%v）",
		gateVersion, listen, target, subtitleOf(), sessionDs, inject)
	srv := &http.Server{
		Addr:              listen,
		Handler:           withGate(newProxy(target, inject)),
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
