package ssrf

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// spyRoundTripper 记录底层 Transport 是否真的收到了请求。
type spyRoundTripper struct{ calls int }

func (s *spyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls++
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
}

// 回归：NewTransport 的兜底发生在建连阶段，那条路径看不到域名，
// 因此单独使用它时白名单模式下的 AllowedHosts 不会生效。
// NewRoundTripper / NewClient 必须把校验提到请求入口。
func TestWrapTransportEnforcesHostWhitelist(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeWhitelist, AllowedHosts: []string{".example.com"}})
	spy := &spyRoundTripper{}
	rt := f.WrapTransport(spy)

	denied, err := http.NewRequest(http.MethodGet, "http://evil.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(denied); !errors.Is(err, ErrBlocked) {
		t.Fatalf("RoundTrip(evil.test) = %v, want blocked", err)
	}
	if spy.calls != 0 {
		t.Fatalf("被拦截的请求不应到达底层 Transport（calls=%d）", spy.calls)
	}

	allowed, err := http.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(allowed); err != nil {
		t.Fatalf("RoundTrip(a.example.com) = %v, want nil", err)
	}
	if spy.calls != 1 {
		t.Fatalf("放行的请求应该到达底层 Transport 一次（calls=%d）", spy.calls)
	}
}

// 同一份配置下，域名白名单在请求级校验里生效，而 Control 只能看到 IP、
// 无法感知域名——这条差异是设计上的取舍，用测试固定下来，避免文档与行为脱节。
func TestDialPathCannotEnforceHostWhitelist(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeWhitelist, AllowedHosts: []string{".example.com"}})

	if err := f.Control("tcp", "93.184.216.34:80", nil); err != nil {
		t.Fatalf("Control(公网 IP) = %v, want nil（白名单模式下未配置 AllowedCIDRs 时不做 IP 白名单）", err)
	}
	if _, err := f.Check(context.Background(), "http://evil.test/"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Check(evil.test) = %v, want blocked", err)
	}
}

func TestNewClientIsWired(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist})
	c := f.NewClient()
	if c.Transport == nil {
		t.Fatal("NewClient 必须设置 Transport")
	}
	if c.CheckRedirect == nil {
		t.Fatal("NewClient 必须设置 CheckRedirect")
	}
}

// 通过 NewClient 发出的请求同样要过校验：这是最容易漏配、也是危害最大的用法。
func TestNewClientBlocksNonWhitelistedHost(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeWhitelist, AllowedHosts: []string{".example.com"}})
	if _, err := f.NewClient().Get("http://evil.test/"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("client.Get(evil.test) = %v, want blocked", err)
	}
}
