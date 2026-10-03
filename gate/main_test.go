package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 安全日志的两层「合并 + 限速」是纯逻辑，这里直接测策略本身：不启容器、
// 不碰网络。跑法：cd gate && go test ./...

func resetSecLog() {
	secMu.Lock()
	secLog = nil
	secSeen = 0
	secMu.Unlock()
	outMu.Lock()
	outWindowAt = time.Time{}
	outWindowN, outSuppressed = 0, 0
	outMu.Unlock()
}

func mustAllow(t *testing.T, now time.Time) {
	t.Helper()
	allow, summary := outDecision(now)
	if !allow || summary != "" {
		t.Fatalf("期望放行且无汇总，实际 allow=%v summary=%q", allow, summary)
	}
}

// 第 2 层：一个窗口内只放 outBurst 行，溢出的攒到窗口翻篇时汇总一行。
func TestOutDecisionCapsPerWindow(t *testing.T) {
	resetSecLog()
	t0 := time.Now()
	for i := 0; i < outBurst; i++ {
		mustAllow(t, t0)
	}
	allow, summary := outDecision(t0)
	if allow || summary != "" {
		t.Fatalf("第 %d 行应被压掉且暂无汇总，实际 allow=%v summary=%q", outBurst+1, allow, summary)
	}
	outMu.Lock()
	sup := outSuppressed
	outMu.Unlock()
	if sup != 1 {
		t.Fatalf("被压掉的计数应为 1，实际 %d", sup)
	}
	// 窗口翻篇：这一行放行，并先补一行汇总说明上一窗压掉了多少。
	allow, summary = outDecision(t0.Add(outWindowLen))
	if !allow {
		t.Fatal("新窗口第一行应放行")
	}
	if !strings.Contains(summary, "1 条") {
		t.Fatalf("汇总应提到被压掉的 1 条，实际 %q", summary)
	}
	if !strings.Contains(summary, "标准输出") {
		t.Fatalf("汇总应说明没往标准输出打，实际 %q", summary)
	}
}

// 窗口内没有溢出时不该出现汇总行（N 条以内就是干净输出）。
func TestOutDecisionNoSummaryWhenUnderBurst(t *testing.T) {
	resetSecLog()
	t0 := time.Now()
	mustAllow(t, t0)
	mustAllow(t, t0)
	if _, summary := outDecision(t0.Add(outWindowLen)); summary != "" {
		t.Fatalf("没溢出却给了汇总 %q", summary)
	}
}

// 第 1 层：同一 IP 的同类事件在合并窗口内并成一条并累加次数。
func TestSecNoteCoalesces(t *testing.T) {
	resetSecLog()
	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())
	secNote("未鉴权拦截", "10.0.0.9", "GET /")
	secNote("未鉴权拦截", "10.0.0.9", "GET /a")
	secNote("未鉴权拦截", "10.0.0.9", "GET /b")
	evs, seen := secSnapshot()
	if len(evs) != 1 || evs[0].Count != 3 {
		t.Fatalf("应合并成 1 条、次数 3，实际 %d 条 %+v", len(evs), evs)
	}
	if seen != 3 {
		t.Fatalf("累计事件数应记全 3 次，实际 %d", seen)
	}
	if evs[0].Text != "GET /b" {
		t.Fatalf("说明应更新为最近一次，实际 %q", evs[0].Text)
	}
}

// 交错也要合并：A、B、A 里的第二个 A 必须并回那一条，而不是只比队尾。
// （只比队尾时扫描器错开一次请求就能让缓冲多占一行，把 300 条挤满。）
func TestSecNoteMergesAcrossInterleaving(t *testing.T) {
	resetSecLog()
	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())
	secNote("未鉴权拦截", "10.0.0.9", "一")
	secNote("验证失败", "10.0.0.9", "二")
	secNote("未鉴权拦截", "10.0.0.9", "三")
	evs, _ := secSnapshot()
	if len(evs) != 2 {
		t.Fatalf("应只有 2 条，实际 %d 条 %+v", len(evs), evs)
	}
	if evs[0].Count != 2 || evs[1].Count != 1 {
		t.Fatalf("交错时未能并回原条目：%+v", evs)
	}
}

// 不同 IP 不合并（否则分布式扫描会被伪装成「一次」而看不出规模）。
func TestSecNoteKeepsDifferentIPs(t *testing.T) {
	resetSecLog()
	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())
	secNote("未鉴权拦截", "10.0.0.1", "x")
	secNote("未鉴权拦截", "10.0.0.2", "x")
	evs, _ := secSnapshot()
	if len(evs) != 2 {
		t.Fatalf("不同 IP 应各占一条，实际 %d 条", len(evs))
	}
}

// 环形缓冲有上限，超出丢最旧的一条。
func TestSecLogTrims(t *testing.T) {
	resetSecLog()
	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())
	for i := 0; i < secLogMax+10; i++ {
		// 每个 IP 都不同 ⇒ 走「新事件」分支，保证条目数真的在涨
		secNote("未鉴权拦截", ipN(i), "x")
	}
	evs, _ := secSnapshot()
	if len(evs) != secLogMax {
		t.Fatalf("缓冲应封顶 %d，实际 %d", secLogMax, len(evs))
	}
}

func ipN(i int) string {
	return "10." + itoa(i/65536%256) + "." + itoa(i/256%256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// 配色：只看 Kind 会把「拒绝」类事件涂成中性色，所以要能看说明文字里的信号词。
func TestToneOf(t *testing.T) {
	cases := []struct {
		kind, text, want string
	}{
		{"登录成功", "方式=需要动态验证码", "ok"},
		{"验证失败", "第 1 次：口令不正确", "err"},
		{"未鉴权拦截", "GET /", "warn"},
		{"锁定期间尝试", "仍在锁定期内，剩余 3m", "warn"},
		// 同类事件里既有成功也有被拒，必须靠文字区分
		{"GitHub 登录", "已跳转 GitHub 授权", "info"},
		{"GitHub 登录", "账号 bob(id=2) 不在允许名单，拒绝", "err"},
		{"GitHub 配置", "登录=开启，ClientID=Ov23li…", "info"},
		{"GitHub 配置", "被拒：开启但配置不完整", "err"},
		{"后台操作", "已保存 GitHub 登录配置", "info"},
		{"后台操作", "非同一站点，已拒绝（Sec-Fetch-Site=\"cross-site\"）", "err"},
		{"重启 DSH", "已从后台页发起重启", "info"},
		{"探测 DSH 失败", "connection refused", "err"},
		{"启动", "监听 127.0.0.1:2299", "info"},
	}
	for _, c := range cases {
		if got := toneOf(c.kind, c.text); got != c.want {
			t.Errorf("toneOf(%q, %q) = %q，期望 %q", c.kind, c.text, got, c.want)
		}
	}
}

// 摘要只列非零项；一条都没有时给「暂无事件」而不是空串（否则标题里出现「；）」）。
func TestLogStats(t *testing.T) {
	if got := logStats(0, 0, 0, 0); got != "暂无事件" {
		t.Fatalf("空统计应为「暂无事件」，实际 %q", got)
	}
	if got := logStats(2, 0, 1, 0); got != "失败 2 · 成功 1" {
		t.Fatalf("应只列非零项，实际 %q", got)
	}
	if got := logStats(0, 5, 0, 3); got != "拦截 5 · 其他 3" {
		t.Fatalf("顺序应为失败/拦截/成功/其他，实际 %q", got)
	}
}

// 事件行只渲染最新 adminRowsMax 行，但统计要覆盖内存里的全部（否则「拦截 N」会漏）。
func TestAdminRowsCapKeepsStatsHonest(t *testing.T) {
	resetSecLog()
	log.SetOutput(io.Discard)
	defer log.SetOutput(log.Writer())
	for i := 0; i < adminRowsMax+7; i++ {
		secNote("未鉴权拦截", ipN(i), "x") // warn
	}
	evs, _ := secSnapshot()
	rows, bad, warn, ok, info := buildRows(evs)
	if len(rows) != adminRowsMax {
		t.Fatalf("渲染行数应封顶 %d，实际 %d", adminRowsMax, len(rows))
	}
	if warn != adminRowsMax+7 || bad+ok+info != 0 {
		t.Fatalf("统计应覆盖全部 %d 条，实际 失败%d 拦截%d 成功%d 其他%d", adminRowsMax+7, bad, warn, ok, info)
	}
	if rows[0].Tone != "warn" {
		t.Fatalf("最新一行应是最近的拦截，实际 %q", rows[0].Tone)
	}
}

// 白名单注册表：这几个接口族的围栏是插件自己的「只认回环」，而**插件自己不校验
// DSH 会话**（实测：回环身份 + 不带任何 Cookie 仍 200）。门禁呈现回环身份后，
// 它们必须由第二层补上「需要有效的 DSH 会话」，否则等于把「门禁 + DSH 令牌」
// 压成一层 —— 1.7.0 的配置管理器 / 自由搜索设置踩过，1.7.2 的应用市场客户端同坑。
func TestSessionlessVerbsNeedBothLayers(t *testing.T) {
	sessionless := []string{
		dshSSHPrefix,             // 远端执行
		configManagerPrefix,      // 配置管理器：导出 profile、崩溃救援
		freeSearchSettingsPrefix, // free-search 设置桥：读写搜索服务凭据
		marketPrefix,             // 应用市场客户端：列已装、装皮肤/预设/宠物
	}
	for _, prefix := range sessionless {
		if !loopbackOnlyPath(prefix) {
			t.Errorf("%s 没进 loopbackOnlyPrefixes：经门禁会被插件围栏 403", prefix)
		}
		if !sessionRequiredPath(prefix) {
			t.Errorf("%s 缺第二层：插件自己不校验 DSH 会话，只放行回环等于压成一层", prefix)
		}
	}
}

// 具体请求路径要能被前缀命中；同时别把「应用市场客户端 /api/market/」和
// 「插件市场本体 /dsh-market/（走精确表）」搞混。
func TestMarketClientPrefixRoutes(t *testing.T) {
	for _, p := range []string{
		"/api/market/installed",
		"/api/market/install-skin",
		"/api/market/install-preset",
		"/api/market/install-pet",
	} {
		if !loopbackOnlyPath(p) || !sessionRequiredPath(p) {
			t.Errorf("%s 应同时属于回环白名单与第二层", p)
		}
	}
	// 控制组：前缀带斜杠，不会误伤同形不同族的路由
	for _, p := range []string{"/dsh-market/installed", "/api/marketing/x", "/api/market"} {
		if loopbackOnlyPath(p) {
			t.Errorf("%s 不该被 /api/market/ 前缀命中", p)
		}
	}
}

// cssRuleOf 取出 selector 到下一条规则之前的声明块（含 selector 本身）。
// 只够用来看一条扁平规则，不处理嵌套。
func cssRuleOf(css, selector string) string {
	i := strings.Index(css, selector)
	if i < 0 {
		return ""
	}
	j := strings.Index(css[i:], "}")
	if j < 0 {
		return ""
	}
	return css[i : i+j+1]
}

// 登录页的 GitHub 按钮必须自带「成对」的前景与底色：线上那次白字就是因为
// 旧规则只给颜色不给底（浅色偏好下 white on white，对比度 1:1）。顺带锁住
// 探针 ④/⑩ 依赖的两个钩子（令牌输入框、复制按钮各一个）。
func TestLoginGithubButtonCarriesOwnColors(t *testing.T) {
	page := string(loginBytes(loginView{
		Title: "t", HasGitHub: true, NeedTOTP: true, TokenNeeded: true, Next: "/x",
	}))
	if n := strings.Count(page, `class="gh"`); n != 1 {
		t.Fatalf("GitHub 按钮应有且仅有 1 个，实际 %d", n)
	}
	rule := cssRuleOf(page, ".gh{")
	if rule == "" {
		t.Fatal("登录页缺少 .gh 样式规则")
	}
	if !strings.Contains(rule, "color:var(") || !strings.Contains(rule, "background:var(") {
		t.Fatalf("GitHub 按钮必须同时声明前景与底色（否则浅色偏好下会白字白底），实际：%q", rule)
	}
	for _, hook := range []string{`name="dstoken"`, "data-copy="} {
		if n := strings.Count(page, hook); n != 1 {
			t.Errorf("%s 应恰好 1 个，实际 %d", hook, n)
		}
	}
}

// ==================== 1.8.0 新功能 ====================

// resetHist 把落盘状态恢复成「未启用」，关掉上一个测试留下的句柄。
func resetHist(t *testing.T) {
	t.Helper()
	histMu.Lock()
	if histF != nil {
		_ = histF.Close()
	}
	histF = nil
	histPath = ""
	histSize = 0
	histWErr = ""
	histWarned = false
	histLast = map[string]time.Time{}
	histDelta = map[string]int{}
	histWindowAt = time.Time{}
	histWindowN, histSuppressed = 0, 0
	histRotateSize = histRotateBytes
	histMu.Unlock()
}

// 落盘限速窗口：一窗最多 histBurst 行，溢出先攒着，窗口翻篇补一条汇总。
func TestHistDecisionWindow(t *testing.T) {
	resetHist(t)
	t0 := time.Now()
	histMu.Lock()
	defer histMu.Unlock()
	for i := 0; i < histBurst; i++ {
		allow, summary := histDecision(t0)
		if !allow || summary != "" {
			t.Fatalf("第 %d 行应放行且无汇总，实际 allow=%v summary=%q", i+1, allow, summary)
		}
	}
	if allow, _ := histDecision(t0); allow {
		t.Fatal("超出窗口配额应拒绝")
	}
	allow, summary := histDecision(t0.Add(histWindowLen))
	if !allow {
		t.Fatal("新窗口第一行应放行")
	}
	if summary == "" {
		t.Fatal("上一窗被限速的行应在翻篇时补一条汇总")
	}
	if !strings.Contains(summary, "另有") {
		t.Fatalf("汇总文案应说明被限速条数，实际 %q", summary)
	}
}

// 落盘端到端：写 → 节流合并 → 读回 → 关键词过滤。
func TestHistAppendAndReadBack(t *testing.T) {
	resetHist(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if err := histOpen(path); err != nil {
		t.Fatalf("histOpen: %v", err)
	}
	t.Cleanup(func() { resetHist(t) })

	histAppend("插件操作", "1.2.3.4", "更新 foo → 完成", false)
	histAppend("插件操作", "1.2.3.4", "更新 foo → 完成", true) // 节流期内的合并：不写新行
	rows := histReadRows("")
	if len(rows) != 1 {
		t.Fatalf("合并行不该重复落盘，期望 1 行，实际 %d 行", len(rows))
	}
	if rows[0].Tone != "ok" {
		t.Errorf("完成类事件配色应为 ok，实际 %q", rows[0].Tone)
	}
	if got := histReadRows("FOO"); len(got) != 1 {
		t.Errorf("过滤应大小写不敏感地命中说明文字，实际 %d 行", len(got))
	}
	if got := histReadRows("9.9.9.9"); len(got) != 0 {
		t.Errorf("不匹配的关键词应 0 行，实际 %d 行", len(got))
	}
}

// 轮转：超阈值挪成 .1（继续涨继续挪），新文件接着写。
func TestHistRotation(t *testing.T) {
	resetHist(t)
	path := filepath.Join(t.TempDir(), "log.jsonl")
	histRotateSize = 300 // 一行 JSONL 约百字节，几行就该轮
	if err := histOpen(path); err != nil {
		t.Fatalf("histOpen: %v", err)
	}
	t.Cleanup(func() { resetHist(t) })
	for i := 0; i < 12; i++ {
		histAppend("历史日志", "1.1.1.1", "轮转测试行 "+strconv.Itoa(i), false)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("超过阈值应轮转出 .1：%v", err)
	}
	if rows := histReadRows("轮转测试行"); len(rows) == 0 {
		t.Fatal("轮转后新文件里的行应能读回")
	}
}

// 健康巡检状态机：首通记就绪（不冒充重启）、连挂 healthFails 次记一次
// 不可达、恢复记重启且带真实离线时长。
func TestHealthStepStates(t *testing.T) {
	var h healthState
	t0 := time.Now()
	if kind, _ := h.step(true, t0); kind != "DSH 就绪" {
		t.Fatalf("首次探通应记「DSH 就绪」，实际 %q", kind)
	}
	if kind, _ := h.step(true, t0.Add(5*time.Second)); kind != "" {
		t.Fatalf("一直通应安静，实际 %q", kind)
	}
	if kind, _ := h.step(false, t0.Add(10*time.Second)); kind != "" {
		t.Fatalf("单次抖动不该记事件，实际 %q", kind)
	}
	if kind, _ := h.step(false, t0.Add(11*time.Second)); kind != "" {
		t.Fatalf("第 2 次抖动仍不该记事件，实际 %q", kind)
	}
	t2 := t0.Add(20 * time.Second)
	if kind, _ := h.step(false, t2); kind != "DSH 不可达" {
		t.Fatalf("连续 %d 次不通应记「DSH 不可达」，实际 %q", healthFails, kind)
	}
	if kind, _ := h.step(false, t2.Add(5*time.Second)); kind != "" {
		t.Fatalf("不可达只记一次，实际 %q", kind)
	}
	kind, text := h.step(true, t2.Add(40*time.Second))
	if kind != "DSH 重启" {
		t.Fatalf("恢复应记「DSH 重启」，实际 %q", kind)
	}
	if !strings.Contains(text, "40s") {
		t.Fatalf("重启事件应带离线时长 40s，实际 %q", text)
	}
}

// 会话代数：旧三段在 epoch=0 时有效；代数 +1（踢光）后，旧 Cookie 即使
// 没到期也全部作废，新代 Cookie 才能进门；篡改过期时间验签必须失败。
func TestSessionEpochCookies(t *testing.T) {
	oldSecret, oldCfg := secret, cfg
	t.Cleanup(func() { secret, cfg = oldSecret, oldCfg })
	secret = "test-secret-0123456789"
	cfg = gateConfig{} // epoch 0

	exp := time.Now().Add(time.Hour).Unix()
	v0 := signSession("v1", exp, 0)
	if strings.Count(v0, ".") != 2 {
		t.Fatalf("epoch=0 应保持旧三段格式（向后兼容），实际 %q", v0)
	}
	if got, ok := sessionSignedExp(v0); !ok || got != exp {
		t.Fatalf("epoch=0 的三段 Cookie 应有效，实际 ok=%v exp=%d", ok, got)
	}

	v1 := signSession("v1", exp, 1)
	if strings.Count(v1, ".") != 3 {
		t.Fatalf("epoch>0 应是四段（多出代数段），实际 %q", v1)
	}
	if _, ok := sessionSignedExp(v1); ok {
		t.Fatal("代数不符的 Cookie 必须拒（还没踢就拿到「未来代」的票）")
	}

	// 踢光：代数 +1
	cfgMu.Lock()
	cfg.SessionEpoch = 1
	cfgMu.Unlock()
	if _, ok := sessionSignedExp(v1); !ok {
		t.Fatal("踢光后本机新代 Cookie 应有效")
	}
	if _, ok := sessionSignedExp(v0); ok {
		t.Fatal("踢光后旧三段 Cookie 必须作废（哪怕没到期）")
	}

	// 篡改过期时间不改签名 → 拒
	parts := strings.Split(v1, ".")
	forged := "v1." + strconv.FormatInt(exp+60, 10) + "." + parts[2] + "." + parts[3]
	if _, ok := sessionSignedExp(forged); ok {
		t.Fatal("篡改过期时间应验签失败")
	}
}

// 插件操作的入参把关：名字只许 npm 包名字符，地址必须 https。
func TestPluginInputValidation(t *testing.T) {
	for _, s := range []string{"dshmarket", "@scope/pkg", "pkg.name_v2", "a-b_c"} {
		if !validPluginName(s) {
			t.Errorf("%q 应是合法插件名", s)
		}
	}
	for _, s := range []string{"", "a b", "a;rm -rf /", "/abs", "..", "a/../b", "a\x00b", strings.Repeat("x", 215)} {
		if validPluginName(s) {
			t.Errorf("%q 必须判为非法插件名", s)
		}
	}
	for _, s := range []string{"https://github.com/x/y", "https://registry.npmjs.org/p"} {
		if !validInstallURL(s) {
			t.Errorf("%q 应是合法安装地址", s)
		}
	}
	for _, s := range []string{"", "http://x/y", "ftp://x/y", "https://user:pass@h/p", "javascript:alert(1)", "notaurl"} {
		if validInstallURL(s) {
			t.Errorf("%q 必须判为非法安装地址", s)
		}
	}
}

// 第二层补强（1.8.0）：20 条市场写路由自身零会话检查，必须和读路由分清 ——
// 写的进第二层，读的保持不拦（只读数据拦了只会把面板弄坏）。
func TestMarketWritesNeedSecondLayer(t *testing.T) {
	if len(marketMutationPaths) != 20 {
		t.Fatalf("市场写路由应恰为 20 条，实际 %d 条（改动要同步改注释与测试）", len(marketMutationPaths))
	}
	for p := range marketMutationPaths {
		if !(sessionRequiredPath(p) || marketMutationPath(p)) {
			t.Errorf("%s 的市场写路由没进第二层：市场自身零会话检查", p)
		}
	}
	for _, p := range []string{"/dsh-market/installed", "/dsh-market/status",
		"/dsh-market/api/v1/updates/summary", "/dsh-market/snapshots", "/dsh-market/registry"} {
		if sessionRequiredPath(p) || marketMutationPath(p) {
			t.Errorf("%s 是只读路由，不该被第二层拦、也不该被改写身份", p)
		}
	}
}

// 插件操作结果翻给用户看的话：成功说完成，失败要把市场的错误正文解出来。
func TestMarketResultText(t *testing.T) {
	if got := marketResultText(200, `{"ok":true}`); got != "完成" {
		t.Errorf("2xx 应说完成，实际 %q", got)
	}
	if got := marketResultText(0, "connection refused"); got != "失败：connection refused" {
		t.Errorf("连接错误应原样带出，实际 %q", got)
	}
	got := marketResultText(400, `{"error":"plugin is not installed"}`)
	if !strings.Contains(got, "HTTP 400") || !strings.Contains(got, "plugin is not installed") {
		t.Errorf("失败应同时带状态码与错误正文，实际 %q", got)
	}
}

// ==================== 1.9.0 新功能 ====================

// 需求②：配了 GATE_DSH_SESSION_KEY 后登录页撤掉令牌框；没配保持老样子。
// 令牌框（name="dstoken"）与取令牌命令（data-copy=）必须同进同出。
func TestLoginAutoPairHidesTokenField(t *testing.T) {
	auto := string(loginBytes(loginView{Title: "t", AutoPair: true}))
	old := string(loginBytes(loginView{Title: "t", AutoPair: false, TokenNeeded: true}))
	if strings.Contains(auto, `name="dstoken"`) {
		t.Error("自动获取模式下登录页不该再出现 DSH 令牌输入框")
	}
	if strings.Contains(auto, "data-copy=") {
		t.Error("自动获取模式下不该再展示取令牌命令")
	}
	if !strings.Contains(old, `name="dstoken"`) || !strings.Contains(old, "data-copy=") {
		t.Error("未配置自动获取时必须保留令牌输入框与取令牌命令（老行为）")
	}
}

// 需求②：GATE_USERNAME 配置后多一个用户名框，且与口令框同真同假之外独立存在。
func TestLoginUsernameField(t *testing.T) {
	with := string(loginBytes(loginView{Title: "t", NeedUsername: true, NeedPassword: true}))
	without := string(loginBytes(loginView{Title: "t", NeedUsername: false, NeedPassword: true}))
	if n := strings.Count(with, `id="username"`); n != 1 {
		t.Errorf("配了 GATE_USERNAME 应恰有 1 个用户名框，实际 %d", n)
	}
	if strings.Contains(without, `id="username"`) {
		t.Error("没配 GATE_USERNAME 不该出现用户名框")
	}
}

// 需求②：自签的 DSH 会话 Cookie 必须与 BrowserAuth 同构 ——
// 名字绑 authority 的 sha256，值是 v1.<body>.<sig>，HMAC 只覆盖 body。
func TestDshAutoSignShape(t *testing.T) {
	oldKey, oldUp, oldDays := dshAutoKey, upstreamURL, dshSessionDs
	t.Cleanup(func() { dshAutoKey, upstreamURL, dshSessionDs = oldKey, oldUp, oldDays })
	dshAutoKey = make([]byte, 32)
	for i := range dshAutoKey {
		dshAutoKey[i] = byte(i)
	}
	dshSessionDs = 30 // 只有 main() 里才解析 GATE_DSH_SESSION_DAYS，单测里自己给上
	u, err := url.Parse("http://127.0.0.1:3082")
	if err != nil {
		t.Fatal(err)
	}
	upstreamURL = u
	r, _ := http.NewRequest(http.MethodGet, "http://harness.mzlp.eu.org/", nil)
	r.Host = "Harness.mzlp.eu.org"
	c, err := dshAutoSign(r)
	if err != nil {
		t.Fatalf("dshAutoSign 失败：%v", err)
	}
	if !strings.HasPrefix(c.Name, "dsh-auth-") {
		t.Errorf("Cookie 名应以 dsh-auth- 开头，实际 %q", c.Name)
	}
	wantName := func(authority string) string {
		s := sha256.Sum256([]byte(authority))
		return "dsh-auth-" + base64.RawURLEncoding.EncodeToString(s[:])
	}
	if c.Name != wantName("harness.mzlp.eu.org") {
		t.Errorf("Cookie 名应绑小写权威主机，期望 %q，实际 %q", wantName("harness.mzlp.eu.org"), c.Name)
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		t.Fatalf("值应为 v1.<body>.<sig> 三段，实际 %q", c.Value)
	}
	mac := hmac.New(sha256.New, dshAutoKey)
	mac.Write([]byte(parts[1]))
	if want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); subtle.ConstantTimeCompare([]byte(want), []byte(parts[2])) != 1 {
		t.Error("HMAC 必须只覆盖 body 段且与密钥一致（DSH 侧要能验过）")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("body 不是 base64url：%v", err)
	}
	var p struct {
		Version   int    `json:"version"`
		Authority string `json:"authority"`
		IssuedAt  int64  `json:"issuedAt"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("payload 解析失败：%v", err)
	}
	if p.Version != 1 || p.Authority != "harness.mzlp.eu.org" {
		t.Errorf("payload version/authority 不对：%+v", p)
	}
	if p.ExpiresAt <= p.IssuedAt {
		t.Errorf("expiresAt 应晚于 issuedAt：%+v", p)
	}
}

// 需求④：两个正则必须与 DSH 0.2.0-rc.2 的真实前端构建产物对齐，
// 版本检测整条链路就靠它们；样本取自线上实测的页面与脚本片段。
func TestDshVersionRegexes(t *testing.T) {
	home := `<script src="/plugins/??@deepseek-ai/dsh-client-ui-settings-general/client.js&rev=53b18d3f3f48"></script>`
	m := dshUIBundleRe.FindStringSubmatch(home)
	if m == nil {
		t.Fatalf("首页样本没匹配到设置页脚本地址：%q", home)
	}
	if m[1] != "??@deepseek-ai/dsh-client-ui-settings-general/client.js&rev=53b18d3f3f48" {
		t.Errorf("捕获段应含 ??@ 前缀与 rev，实际 %q", m[1])
	}
	js := `children: t("general.currentVersion", { version: "0.2.0-rc.2" })`
	v := dshUIVerRe.FindStringSubmatch(js)
	if v == nil || v[1] != "0.2.0-rc.2" {
		t.Errorf("版本正则没从脚本样本里解出 0.2.0-rc.2，实际 %v", v)
	}
	// rev 缺失/格式不对就不该抓到（抓到 = 会去请求一个必然 404 的地址）。
	bad := `<script src="/plugins/??@deepseek-ai/dsh-client-ui-settings-general/client.js"></script>`
	if dshUIBundleRe.MatchString(bad) {
		t.Error("没有 rev 的脚本地址不该被匹配（直连必然 404）")
	}
}

// 需求①：市场数据过期时快照必须立刻回旧值 + fetching，绝不阻塞页面；
// 后台单飞重拉由 goroutine 负责，快照本身同步返回。
func TestMarketReadSnapshotDoesNotBlock(t *testing.T) {
	marketRead.mu.Lock()
	marketRead.info = marketReadInfo{ok: true, at: time.Now().Add(-time.Hour), ver: "旧值"}
	marketRead.fetching = false
	marketRead.mu.Unlock()
	t.Cleanup(func() {
		marketRead.mu.Lock()
		marketRead.info = marketReadInfo{}
		marketRead.fetching = false
		marketRead.mu.Unlock()
	})
	start := time.Now()
	info := marketReadSnapshot()
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("快照被市场拉取阻塞了 %v（必须立刻返回旧值）", elapsed)
	}
	if !info.fetching {
		t.Error("数据过期时快照必须带 fetching=true，页面据此显示「获取中」")
	}
	if info.ver != "旧值" {
		t.Errorf("过期时应先回旧值，实际 %q", info.ver)
	}
	// 等后台单飞结束，别把 goroutine 带进后续测试。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		marketRead.mu.Lock()
		running := marketRead.fetching
		marketRead.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("后台重拉迟迟不结束（单飞标志没清）")
}

// 需求①③④：后台页模板要长出这几样 —— 手动检测按钮、获取中徽章、
// 默认折叠的插件管理、DSH 版本行。
func TestAdminTemplateNewFeatures(t *testing.T) {
	var b bytes.Buffer
	err := adminTpl.Execute(&b, adminView{
		Title: "t", Version: "1.9.0",
		MarketFetching: true, UpdatesOK: false,
		DSHVerFetching: true,
	})
	if err != nil {
		t.Fatalf("模板渲染失败：%v", err)
	}
	page := b.String()
	for _, want := range []string{
		`value="refresh"`,       // 手动检测刷新按钮
		"获取中",                  // 获取中徽章（替代「未知」）
		`id="plugsec"`,          // 插件管理卡（默认折叠的 details）
		"DSH 版本",               // DSH 版本统计行
	} {
		if !strings.Contains(page, want) {
			t.Errorf("后台页缺少 %q", want)
		}
	}
	if strings.Contains(page, `id="plugsec" open`) {
		t.Error("插件管理必须默认折叠（details 不带 open）")
	}
	// 没在拉取时不该显示「获取中」，避免把已完成的状态说成进行时。
	marketRead.mu.Lock()
	marketRead.info = marketReadInfo{ok: true, at: time.Now(), ver: "1.66.8", sumOK: true}
	marketRead.fetching = false
	marketRead.mu.Unlock()
	dshVerRead.mu.Lock()
	dshVerRead.ver, dshVerRead.at, dshVerRead.fetching = "0.2.0-rc.2", time.Now(), false
	dshVerRead.mu.Unlock()
	t.Cleanup(func() {
		marketRead.mu.Lock()
		marketRead.info = marketReadInfo{}
		marketRead.mu.Unlock()
		dshVerRead.mu.Lock()
		dshVerRead.ver, dshVerRead.at = "", time.Time{}
		dshVerRead.mu.Unlock()
	})
	b.Reset()
	if err := adminTpl.Execute(&b, adminView{
		Title: "t", Version: "1.9.0",
		MarketVer: "1.66.8", UpdatesOK: true, DSHVer: "0.2.0-rc.2",
		Plugins: []pluginRow{{Name: "demo", Spec: "demo@1.0.0"}},
	}); err != nil {
		t.Fatalf("模板渲染失败：%v", err)
	}
	page = b.String()
	if strings.Contains(page, "获取中") {
		t.Error("数据已取到就不该再显示「获取中」")
	}
	if !strings.Contains(page, "已最新") {
		t.Error("UpdatesOK 时应显示「已最新」")
	}
	if !strings.Contains(page, "0.2.0-rc.2") {
		t.Error("DSH 版本应显示在后台页")
	}
}

// ==================== 1.10.0 新需求 ====================

// 需求②：后台改口令 —— 原口令不对必须拒、确认不一致必须拒；
// 改对了 currentPWHash() 立刻指向新口令（不用重启），状态文件落 pwHash。
func TestAdminChangePassword(t *testing.T) {
	oldPW, oldNeedPw, oldCfg, oldPath, oldW := pwHash, needPw, cfg, cfgPath, cfgWritable
	t.Cleanup(func() {
		pwHash, needPw, cfg, cfgPath, cfgWritable = oldPW, oldNeedPw, oldCfg, oldPath, oldW
		adminMsgState.mu.Lock()
		adminMsgState.text, adminMsgState.at = "", time.Time{}
		adminMsgState.mu.Unlock()
	})
	pwHash = hashPassword("old-pass-86")
	needPw = true
	cfg = gateConfig{}
	cfgPath = filepath.Join(t.TempDir(), "state.json")
	cfgWritable = true

	post := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/__gate/password", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handlePassword(w, r)
		return w
	}
	stillOld := func() bool {
		return subtle.ConstantTimeCompare([]byte(currentPWHash()), []byte(pwHash)) == 1
	}

	// 原口令错 → 拒，且不落盘
	w := post(url.Values{"old": {"wrong"}, "new": {"fresh-pass-01"}, "confirm": {"fresh-pass-01"}})
	if w.Code != http.StatusSeeOther || !stillOld() {
		t.Fatalf("原口令错必须拒：code=%d 还是旧口令=%v", w.Code, stillOld())
	}
	// 确认不一致 → 拒
	w = post(url.Values{"old": {"old-pass-86"}, "new": {"fresh-pass-01"}, "confirm": {"fresh-pass-02"}})
	if !stillOld() {
		t.Fatal("两次输入不一致必须拒")
	}
	// 新旧一样 → 拒（防手滑存个没意义的改动）
	w = post(url.Values{"old": {"old-pass-86"}, "new": {"old-pass-86"}, "confirm": {"old-pass-86"}})
	if !stillOld() {
		t.Fatal("新口令与原口令相同应拒")
	}
	// 正确 → 生效 + 落盘
	w = post(url.Values{"old": {"old-pass-86"}, "new": {"fresh-pass-01"}, "confirm": {"fresh-pass-01"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("正确改密应 303 回后台，实际 %d", w.Code)
	}
	if subtle.ConstantTimeCompare([]byte(currentPWHash()), []byte(hashPassword("fresh-pass-01"))) != 1 {
		t.Fatal("改完 currentPWHash() 应指向新口令")
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("状态文件没写出来：%v", err)
	}
	var onDisk gateConfig
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("状态文件解析失败：%v", err)
	}
	if onDisk.PWHash != hashPassword("fresh-pass-01") {
		t.Errorf("状态文件 pwHash 不对：%q", onDisk.PWHash)
	}
	if adminMsg() == "" {
		t.Error("改完应给后台页一句反馈")
	}
}

// 需求②：后台页在口令登录开着时给出改口令表单，没配口令就不给。
func TestAdminTemplatePasswordForm(t *testing.T) {
	var b bytes.Buffer
	if err := adminTpl.Execute(&b, adminView{Title: "t", Version: "1.10.0", PwOn: true}); err != nil {
		t.Fatalf("模板渲染失败：%v", err)
	}
	page := b.String()
	for _, want := range []string{`action="/__gate/password"`, `name="old"`, `name="new"`, `name="confirm"`} {
		if !strings.Contains(page, want) {
			t.Errorf("配了口令登录，后台页应有改口令表单（缺 %q）", want)
		}
	}
	b.Reset()
	if err := adminTpl.Execute(&b, adminView{Title: "t", Version: "1.10.0", PwOn: false}); err != nil {
		t.Fatalf("模板渲染失败：%v", err)
	}
	if strings.Contains(b.String(), `action="/__gate/password"`) {
		t.Error("没配口令登录不该出现改口令表单")
	}
}

// 需求③：自动刷新只刷数据不刷页面 —— JS 里所有被点名的数据区 id 必须真实
// 存在于渲染出的页面，否则 pick() 全 miss、每 10 秒退化成整页 reload。
func TestAdminPartialRefreshAnchors(t *testing.T) {
	var b bytes.Buffer
	if err := adminTpl.Execute(&b, adminView{
		Title: "t", Version: "1.10.0", PwOn: true,
		MarketFetching: true, DSHVerFetching: true,
		Events: []adminEvent{{Time: "01:02:03", Kind: "测试", Tone: "ok", Text: "x", Count: 1}},
	}); err != nil {
		t.Fatalf("模板渲染失败：%v", err)
	}
	page := b.String()
	for _, id := range []string{
		`id="uptime"`, `id="topline"`, `id="banner"`, `id="statgrid"`,
		`id="plugdata"`, `id="logsummary"`, `id="logrows"`, `id="histsummary"`, `id="histrows"`,
	} {
		if !strings.Contains(page, id) {
			t.Errorf("局部刷新数据区缺 %s", id)
		}
	}
	if !strings.Contains(page, `data-busy="1"`) {
		t.Error("获取中时 statgrid 的 data-busy 应为 1（驱动 3 秒节拍）")
	}
	if !strings.Contains(page, `fetch('/__gate/admin'`) {
		t.Error("自动刷新应改用 fetch 拉数据")
	}
	if !strings.Contains(page, `WATCH=[`) {
		t.Error("缺 WATCH 数据区清单")
	}
	// 只允许把整页 reload 当作兜底（结构变了），不能是周期性主路径。
	if strings.Contains(page, "location.reload();\n  }, busy") {
		t.Error("周期整页重载应已被 fetch+局部替换取代")
	}
}

// ---------- 需求④：口令 + 动态验证码拆两步登录 ----------

// 第一步页面：有用户名/口令、没有验证码栏、没有步骤票据字段。
func TestTwoStepFirstPage(t *testing.T) {
	v := newLoginView("", false, 0, "/", false)
	v.TwoStep = true
	v.NeedUsername, v.NeedPassword, v.NeedTOTP = true, true, true
	page := string(loginBytes(v))
	if !strings.Contains(page, `name="username"`) || !strings.Contains(page, `name="password"`) {
		t.Error("第 1 步必须有用户名与口令框")
	}
	if strings.Contains(page, `name="code"`) {
		t.Error("第 1 步不该出验证码栏（拆两步的意义）")
	}
	if strings.Contains(page, `name="st"`) {
		t.Error("第 1 步还没发票据，不该有 st 字段")
	}
	if !strings.Contains(page, "下一步") {
		t.Error("第 1 步提交按钮应显示「下一步」")
	}
}

// 第二步页面：只有验证码 + st 票据 + 令牌栏（按需），不再重问口令。
func TestTwoStepSecondPage(t *testing.T) {
	v := step2View("", false, 0, "/", "st2.99.sig", false)
	v.NeedUsername, v.NeedPassword, v.NeedTOTP = true, true, true
	page := string(loginBytes(v))
	if !strings.Contains(page, `name="code"`) {
		t.Error("第 2 步必须有验证码框")
	}
	if !strings.Contains(page, `name="st" value="st2.99.sig"`) {
		t.Error("第 2 步必须原样带回步骤票据")
	}
	if strings.Contains(page, `name="password"`) || strings.Contains(page, `name="username"`) {
		t.Error("第 2 步不该再问用户名/口令")
	}
	if !strings.Contains(page, "第 2 步 · 输入动态验证码") {
		t.Error("第 2 步副标题应点明当前步骤")
	}
}

// 步骤票据：签名格式对、5 分钟内有效、过期与伪造都拒。
func TestStep2Ticket(t *testing.T) {
	tok := step2Ticket()
	exp, ok := signedExp(tok, "st2")
	if !ok {
		t.Fatalf("自己签的票据验不过：%q", tok)
	}
	if exp <= time.Now().Unix() || exp > time.Now().Add(6*time.Minute).Unix() {
		t.Errorf("票据过期时间应在 5 分钟上下，实际 exp-now=%ds", exp-time.Now().Unix())
	}
	if _, ok := signedExp(tok, "v1"); ok {
		t.Error("st2 票据不能被当成门禁会话（ver 隔离失效）")
	}
	if _, ok := signedExp(tok+".x", "st2"); ok {
		t.Error("多一段的票据应被拒")
	}
	forged := "st2." + strconv.FormatInt(exp, 10) + ".forged"
	if _, ok := signedExp(forged, "st2"); ok {
		t.Error("伪造签名的票据应验不过")
	}
}

// 非两步模式（只口令、或口令+验证码同页）：页面必须保持老样子——验证码还在第 1 页。
func TestSingleStepStillShowsCode(t *testing.T) {
	v := newLoginView("", false, 0, "/", false)
	v.NeedPassword, v.NeedTOTP = true, true // TwoStep 未置位（mode 未拆）
	page := string(loginBytes(v))
	if !strings.Contains(page, `name="code"`) {
		t.Error("未启用两步模式时验证码必须留在同一页")
	}
	if strings.Contains(page, `name="st"`) {
		t.Error("未启用两步模式不该出现 st 票据字段")
	}
}

// 需求⑤（UI 检查优化）：两步登录的第 1 步副标题要和第 2 步的
//「第 2 步 · …」呼应，点明这是上半程；单步模式仍用 subtitleOf() 原副标题。
func TestTwoStepFirstPageSubtitle(t *testing.T) {
	oldNeedPw, oldNeedTotp, oldCfg := needPw, needTotp, cfg
	t.Cleanup(func() { needPw, needTotp, cfg = oldNeedPw, oldNeedTotp, oldCfg })

	needPw, needTotp, cfg = true, true, gateConfig{} // TOTPEnabled 未设 → 开
	v := newLoginView("", false, 0, "/", false)
	if !v.TwoStep {
		t.Fatal("口令+动态验证码应进入两步模式")
	}
	if v.Subtitle != "第 1 步 · 输入用户名与口令" {
		t.Errorf("第 1 步副标题应点明步骤，实际 %q", v.Subtitle)
	}
	if v2 := step2View("", false, 0, "/", "st2.1.x", false); v2.Subtitle != "第 2 步 · 输入动态验证码" {
		t.Errorf("第 2 步副标题被改坏了：%q", v2.Subtitle)
	}

	// 单步模式（关掉动态验证码）保持原副标题（测试里没配 GATE_USERNAME → subtitleOf() 给「需要访问口令」）
	needTotp = false
	if v3 := newLoginView("", false, 0, "/", false); v3.TwoStep || v3.Subtitle != subtitleOf() {
		t.Errorf("单步模式副标题不该变：TwoStep=%v Subtitle=%q", v3.TwoStep, v3.Subtitle)
	}
}
