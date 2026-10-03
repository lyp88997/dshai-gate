package main

import (
	"io"
	"log"
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
