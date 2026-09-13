package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

// fakeLookup 构造一个可注入的 DNS 解析函数，让测试不依赖网络。
func fakeLookup(m map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		ss, ok := m[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		addrs := make([]netip.Addr, 0, len(ss))
		for _, s := range ss {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
		return addrs, nil
	}
}

func testLookup() func(context.Context, string) ([]netip.Addr, error) {
	return fakeLookup(map[string][]string{
		"example.com":              {"93.184.216.34"},
		"a.example.com":            {"93.184.216.34"},
		"evil.example.com":         {"127.0.0.1"},
		"api.github.com":           {"140.82.114.6"},
		"evil.test":                {"93.184.216.34"},
		"a.example.com.evil.test":  {"93.184.216.34"},
		"internal.test":            {"10.0.0.5"},
		"rebind.test":              {"93.184.216.34", "127.0.0.1"},
		"loop.test":                {"127.0.0.1"},
		"metadata.google.internal": {"169.254.169.254"},
	})
}

func newTestFilter(t *testing.T, cfg Config) *Filter {
	t.Helper()
	if cfg.LookupIP == nil {
		cfg.LookupIP = testLookup()
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return f
}

func TestNormalize(t *testing.T) {
	f := newTestFilter(t, Config{})
	tests := []struct {
		in       string
		wantHost string
		wantURL  string
	}{
		{"HTTP://EXAMPLE.COM./a", "example.com", "http://example.com/a"},
		{"example.com", "example.com", "http://example.com"},
		{"127.0.0.1:8080", "127.0.0.1", "http://127.0.0.1:8080"},
		{"http://0x7f.0.0.1/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://0x7f.1/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://0177.0.0.1/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://2130706433/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://[::ffff:7f00:1]/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://[::1]/", "::1", "http://[::1]/"},
		{"http://[::1]:8080/", "::1", "http://[::1]:8080/"},
		{"http://127.0.0.1./", "127.0.0.1", "http://127.0.0.1/"},
		{"http://１２７.０.０.１/", "127.0.0.1", "http://127.0.0.1/"},
		{"http://127.0.0.1\t/", "127.0.0.1", "http://127.0.0.1/"},
		{" http://example.com/x ", "example.com", "http://example.com/x"},
	}
	for _, tc := range tests {
		u, err := f.Normalize(tc.in)
		if err != nil {
			t.Fatalf("Normalize(%q) error = %v", tc.in, err)
		}
		if got := u.Hostname(); got != tc.wantHost {
			t.Errorf("Normalize(%q) host = %q, want %q", tc.in, got, tc.wantHost)
		}
		if got := u.String(); got != tc.wantURL {
			t.Errorf("Normalize(%q) url = %q, want %q", tc.in, got, tc.wantURL)
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	f := newTestFilter(t, Config{})
	tests := []struct {
		in   string
		want error
	}{
		{"", ErrEmptyInput},
		{"   ", ErrEmptyInput},
		{"file:///etc/passwd", ErrBadScheme},
		{"gopher://127.0.0.1:6379/_", ErrBadScheme},
		{"dict://127.0.0.1:11211/", ErrBadScheme},
		{"ftp://127.0.0.1/", ErrBadScheme},
		{"http://user:pass@127.0.0.1/", ErrUserInfo},
		{"http://a@b@127.0.0.1/", ErrUserInfo},
		{"http://1.2.3.4.5/", ErrInvalidHost},
		{"http://999.999.999.999/", ErrInvalidHost},
		{"http://例え.jp/", ErrNonASCIIHost},
		{"http://127.0.0.1:99999/", ErrInvalidHost},
	}
	for _, tc := range tests {
		_, err := f.Normalize(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("Normalize(%q) error = %v, want %v", tc.in, err, tc.want)
		}
	}
}

// parseLooseIPv4 的宽松写法与拒绝条件必须稳定：这里少拒一种写法，
// 上层就多一个 "0x7f.0.0.1" 式的绕过入口。
func TestParseLooseIPv4(t *testing.T) {
	accept := map[string]string{
		"127.0.0.1":       "127.0.0.1",
		"2130706433":      "127.0.0.1",
		"0x7f000001":      "127.0.0.1",
		"0x7f.0.0.1":      "127.0.0.1",
		"0177.0.0.1":      "127.0.0.1",
		"127.1":           "127.0.0.1",
		"127.0.1":         "127.0.0.1",
		"0":               "0.0.0.0",
		"255.255.255.255": "255.255.255.255",
	}
	for in, want := range accept {
		got, ok := parseLooseIPv4(in)
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("parseLooseIPv4(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}

	reject := []string{
		"", "127.", ".127", "1..2", "1.2.3.4.5",
		"1.2.3.256", "1.16777216", "1.2.65536", // 各段位宽越界
		"4294967296", // 超过 32 位
		"example.com", "1.2.3.4.5.6",
	}
	for _, in := range reject {
		if got, ok := parseLooseIPv4(in); ok {
			t.Errorf("parseLooseIPv4(%q) = %v, true; want rejected", in, got)
		}
	}
}

func TestCheckBlacklistBlocked(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist})
	blocked := []string{
		// 回环的各种写法
		"http://127.0.0.1/admin",
		"http://127.1/",
		"http://127.0.0.1./",
		"http://2130706433/",
		"http://0x7f000001/",
		"http://0x7f.0.0.1/",
		"http://0177.0.0.1/",
		"http://localhost/",
		"http://LOCALHOST./",
		"http://[::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[0:0:0:0:0:ffff:7f00:1]/",
		// 私网 / 保留段 / metadata
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1:8080/",
		"http://100.64.0.1/",
		"http://100.100.100.200/latest/meta-data/", // 阿里云 metadata
		"http://169.254.169.254/latest/meta-data/", // AWS/GCP/Azure metadata
		"http://0.0.0.0/",
		"http://255.255.255.255/",
		"http://[fd00::1]/",
		"http://[fe80::1]/",
		"http://[64:ff9b::7f00:1]/", // NAT64 内嵌 127.0.0.1
		"http://[2002:7f00:1::]/",   // 6to4 内嵌 127.0.0.1
		"http://metadata.google.internal/computeMetadata/v1/",
		// 域名解析到内网 / 混合解析（DNS Rebinding 前置场景）
		"http://internal.test/",
		"http://rebind.test/",
		// 解析失败一律拒绝
		"http://unknown-host.test/",
		// 高危端口
		"http://example.com:22/",
		"http://example.com:6379/",
		"http://example.com:11211/",
	}
	for _, in := range blocked {
		if _, err := f.Check(context.Background(), in); !errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%q) = %v, want blocked", in, err)
		}
	}
}

func TestCheckBlacklistAllowed(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist})
	allowed := []string{
		"http://example.com/",
		"https://example.com/path?q=1",
		"http://example.com:8080/",
		"http://8.8.8.8/",
		"http://93.184.216.34/",
		"http://[2606:4700:4700::1111]/",
	}
	for _, in := range allowed {
		if _, err := f.Check(context.Background(), in); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", in, err)
		}
	}
}

func TestCheckWhitelistHosts(t *testing.T) {
	f := newTestFilter(t, Config{
		Mode:         ModeWhitelist,
		AllowedHosts: []string{".example.com", "api.github.com", "93.184.216.34"},
		AllowedPorts: []int{80, 443},
	})

	allowed := []string{
		"http://example.com/",
		"http://a.example.com/",
		"https://api.github.com/repos",
		"http://93.184.216.34/",
	}
	for _, in := range allowed {
		if _, err := f.Check(context.Background(), in); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", in, err)
		}
	}

	blocked := []string{
		"http://evil.test/",               // 不在白名单
		"http://a.example.com.evil.test/", // 后缀伪装
		"http://8.8.8.8/",                 // IP 不在白名单
		"http://example.com:8080/",        // 端口不在白名单
		"http://evil.example.com/",        // 命中域名白名单但解析到 127.0.0.1
		"http://example.com.evil.test/",   // 不在白名单且解析失败
	}
	for _, in := range blocked {
		if _, err := f.Check(context.Background(), in); !errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%q) = %v, want blocked", in, err)
		}
	}
}

func TestCheckWhitelistCIDR(t *testing.T) {
	f := newTestFilter(t, Config{
		Mode:         ModeWhitelist,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")},
	})
	allowed := []string{"http://example.com/", "http://93.184.216.34/"}
	for _, in := range allowed {
		if _, err := f.Check(context.Background(), in); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", in, err)
		}
	}
	blocked := []string{"http://8.8.8.8/", "http://internal.test/", "http://other.test/"}
	for _, in := range blocked {
		if _, err := f.Check(context.Background(), in); !errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%q) = %v, want blocked", in, err)
		}
	}
}

// 白名单只配了地址段、又关闭了解析时，判断依据只剩下域名：
// 这时要给「域名不在白名单」，而不是「[] 不在地址段白名单里」。
func TestCheckWhitelistCIDRWithDisableResolve(t *testing.T) {
	f := newTestFilter(t, Config{
		Mode:           ModeWhitelist,
		AllowedCIDRs:   []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")},
		DisableResolve: true,
	})
	_, err := f.Check(context.Background(), "http://other.test/")
	var be *BlockedError
	if !errors.As(err, &be) || be.Reason != ReasonHostNotAllowed {
		t.Errorf("Check(other.test) = %v, want reason %q", err, ReasonHostNotAllowed)
	}
}

// 显式把内网网段放进 AllowedCIDRs 才能访问内网服务。
func TestCheckWhitelistExplicitInternalCIDR(t *testing.T) {
	f := newTestFilter(t, Config{
		Mode:         ModeWhitelist,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	if _, err := f.Check(context.Background(), "http://internal.test/"); err != nil {
		t.Errorf("Check(internal.test) = %v, want allowed", err)
	}
	if _, err := f.Check(context.Background(), "http://example.com/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(example.com) = %v, want blocked", err)
	}
}

func TestCheckEmptyWhitelistDeniesAll(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeWhitelist})
	if _, err := f.Check(context.Background(), "http://example.com/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(example.com) = %v, want blocked", err)
	}
}

func TestCheckDisableResolve(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist, DisableResolve: true})
	// 关闭解析后 IP 字面量仍受保护
	if _, err := f.Check(context.Background(), "http://127.0.0.1/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(127.0.0.1) = %v, want blocked", err)
	}
	// 域名不再解析，直接放行（黑名单模式下的已知取舍）
	res, err := f.Check(context.Background(), "http://internal.test/")
	if err != nil {
		t.Fatalf("Check(internal.test) = %v, want allowed", err)
	}
	if len(res.IPs) != 0 {
		t.Errorf("IPs = %v, want empty", res.IPs)
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	tests := []struct {
		in   string
		want netip.Addr
	}{
		{"64:ff9b::7f00:1", netip.MustParseAddr("127.0.0.1")},
		{"2002:7f00:0001::", netip.MustParseAddr("127.0.0.1")},
		{"2002:a9fe:a9fe::", netip.MustParseAddr("169.254.169.254")},
		{"::ffff:127.0.0.1", netip.MustParseAddr("127.0.0.1")}, // 由 Unmap 处理，不算内嵌
	}
	for _, tc := range tests {
		got, ok := embeddedIPv4(netip.MustParseAddr(tc.in))
		if tc.in == "::ffff:127.0.0.1" {
			if ok {
				t.Errorf("embeddedIPv4(%q) = %v, want not embedded", tc.in, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("embeddedIPv4(%q) = %v, %v; want %v", tc.in, got, ok, tc.want)
		}
	}
}

// Teredo 中的客户端 IPv4 是取反（XOR 0xFFFFFFFF）存储的。
func TestEmbeddedIPv4Teredo(t *testing.T) {
	got, ok := embeddedIPv4(netip.MustParseAddr("2001:0000:4136:e378:8000:63bf:3fff:fdd2"))
	if !ok {
		t.Fatal("expected teredo address to embed an IPv4")
	}
	if got != netip.MustParseAddr("192.0.2.45") {
		t.Errorf("embedded IPv4 = %v, want 192.0.2.45", got)
	}
}

func TestControlBlocksRebinding(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist})
	// 建连前兜底：即使目标 IP 是内网，也直接拒绝
	if err := f.Control("tcp", "127.0.0.1:80", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("Control(127.0.0.1:80) = %v, want blocked", err)
	}
	if err := f.Control("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("Control(169.254.169.254:80) = %v, want blocked", err)
	}
	if err := f.Control("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("Control(93.184.216.34:443) = %v, want allowed", err)
	}
}

func TestDialContextBlocksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	f := newTestFilter(t, Config{Mode: ModeBlacklist})
	ctx := context.Background()

	if _, err := f.DialContext(ctx, "tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Errorf("DialContext(%s) = %v, want blocked", ln.Addr(), err)
	}
	// 域名解析到回环同样拦截（因为解析后固定 IP 前会逐个校验）
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if _, err := f.DialContext(ctx, "tcp", net.JoinHostPort("loop.test", port)); !errors.Is(err, ErrBlocked) {
		t.Errorf("DialContext(loop.test) = %v, want blocked", err)
	}
}

// host 里的 %XX 只允许表示非 ASCII 字节，因此 "127.0.0.1%2e" 之类会被 url 解析直接判非法，
// 等价于 fail closed。
func TestPercentEncodedHost(t *testing.T) {
	f := newTestFilter(t, Config{})
	if _, err := f.Check(context.Background(), "http://127.0.0.1%2e/"); err == nil {
		t.Error("Check(percent-encoded host) = nil, want error")
	}
}

func TestCheckRedirect(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist})

	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := f.CheckRedirect(req, []*http.Request{req}); !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckRedirect(metadata) = %v, want blocked", err)
	}

	safe, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := f.CheckRedirect(safe, []*http.Request{safe}); err != nil {
		t.Errorf("CheckRedirect(example.com) = %v, want nil", err)
	}

	// via 是「已经发出过的请求」，因此边界在 len(via) == maxRedirects：
	// 此时还能再跟一跳（共 3 个请求），再多就拦下。
	atLimit := make([]*http.Request, maxRedirects)
	for i := range atLimit {
		atLimit[i] = safe
	}
	if err := f.CheckRedirect(safe, atLimit); err != nil {
		t.Errorf("CheckRedirect(via=%d) = %v, want nil（还能再跟随一跳）", maxRedirects, err)
	}

	loop := make([]*http.Request, maxRedirects+1)
	for i := range loop {
		loop[i] = safe
	}
	err = f.CheckRedirect(safe, loop)
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckRedirect(too many) = %v, want blocked", err)
	}
	var blockedErr *BlockedError
	if !errors.As(err, &blockedErr) || blockedErr.Reason != ReasonTooManyRedirects {
		t.Errorf("CheckRedirect(too many) = %v, want reason %q", err, ReasonTooManyRedirects)
	}
}

// Config() 返回的必须是副本：外部改动（尤其是地址段白名单）不能反过来影响
// Filter 的判定，否则一次「顺手改一下拿到的配置」就能让保留地址检查失效。
func TestConfigReturnsCopy(t *testing.T) {
	f := MustNew(Config{
		Mode:         ModeWhitelist,
		AllowedHosts: []string{".example.com"},
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")},
	})

	cfg := f.Config()
	cfg.AllowedHosts[0] = ".evil.test"
	cfg.AllowedCIDRs[0] = netip.MustParsePrefix("0.0.0.0/0")
	cfg.DeniedPorts[0] = 80

	if again := f.Config(); again.AllowedHosts[0] != ".example.com" ||
		again.AllowedCIDRs[0].String() != "93.184.216.0/24" {
		t.Errorf("Config() 的切片与内部共享: hosts=%v cidrs=%v", again.AllowedHosts, again.AllowedCIDRs)
	}
	// 如果 0.0.0.0/0 真的写进了内部配置，8.8.8.8 就会被放行
	if _, err := f.Check(context.Background(), "http://8.8.8.8/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(8.8.8.8) = %v, want blocked", err)
	}
}

// 未知 Mode 必须报错，不能静默按黑名单处理（那会把白名单配置悄悄变成几乎不拦截）。
func TestNewRejectsInvalidMode(t *testing.T) {
	if _, err := New(Config{Mode: Mode(7)}); err == nil {
		t.Error("New(Mode(7)) = nil, want error")
	}
}
