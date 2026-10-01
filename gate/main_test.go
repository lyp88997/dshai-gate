package main

import (
	"io"
	"log"
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
