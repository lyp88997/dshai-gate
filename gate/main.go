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

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
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
func verifyTOTP(input string) (uint64, bool) {
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
			log.Printf("门禁：动态码重放被拒（时间片 %d）", ct)
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
		log.Printf("门禁：探测 DSH 会话失败: %v", err)
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
		log.Printf("门禁：锁定期间尝试 ip=%s", ip)
		renderLogin(w, http.StatusTooManyRequests, "", true, rem, next, false)
		return
	}
	hasSession := dshHasSession(r)

	fail := func(msg string) {
		time.Sleep(globalDelay())
		noteGlobalFail()
		n, lockedNow, dur := noteFail(ip)
		if lockedNow {
			log.Printf("门禁：失败达上限，锁定 ip=%s 时长=%s", ip, dur)
			renderLogin(w, http.StatusTooManyRequests, "", true, dur, next, hasSession)
			return
		}
		log.Printf("门禁：验证失败 ip=%s 第 %d 次", ip, n)
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
		ct, ok := verifyTOTP(r.FormValue("code"))
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
			log.Printf("门禁：DSH 令牌换票失败 ip=%s: %v", ip, err)
			fail("DSH 令牌不正确或已失效（DSH 重启后旧令牌即作废）")
			return
		}
		http.SetCookie(w, pairCookie)
		log.Printf("门禁：DSH 令牌换票成功 ip=%s", ip)
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
	log.Printf("门禁：登录成功 ip=%s（方式=%s）", ip, subtitleOf())
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, gatePrefix+"/login", http.StatusSeeOther)
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
		}
		if c, err := r.Cookie(cookieName); err == nil && cookieValid(c.Value) {
			next.ServeHTTP(w, r)
			return
		}
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

// ---------- 反代 ----------

func newProxy(target *url.URL, inject bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// ★ 关键：SetURL 会把 Host 改成上游地址，必须改回原域名，
			//   否则 DSH 的 --trusted-host 校验失败，特权接口全部 403
			pr.Out.Host = pr.In.Host
			// ★ 仅回环类接口：向上游呈现回环身份（Host + Origin 同步），
			//   否则插件自身的 loopback-only 围栏会拒绝经反代来的合法请求。
			//   其余路径一律保持原 Host，避免影响 DSH 的 Cookie 归属与信任校验。
			if loopbackOnlyPath(pr.In.URL.Path) {
				pr.Out.Host = target.Host
				if pr.In.Header.Get("Origin") != "" {
					pr.Out.Header.Set("Origin", "http://"+target.Host)
				}
			}
			pr.SetXForwarded()
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
			log.Printf("上游错误 %s %s: %v", r.Method, r.URL.Path, err)
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

	log.Printf("dshai-gate 启动: http://%s -> %s（%s，会话=%d 天，注入=%v）",
		listen, target, subtitleOf(), sessionDs, inject)
	srv := &http.Server{
		Addr:              listen,
		Handler:           withGate(newProxy(target, inject)),
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
