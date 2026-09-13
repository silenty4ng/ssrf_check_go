package ssrf

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeHostPattern(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"  Example.COM.  ", "example.com"},
		{".example.com", ".example.com"},
		{".example.com.", ".example.com"},
		{"*.example.com.", "*.example.com"},
		{"ｅｘａｍｐｌｅ.com", "example.com"}, // 全角字母
		{"example。com", "example.com"}, // 全角句号
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1.", "127.0.0.1"},
		{"0177.0.0.1", "127.0.0.1"}, // 宽松 IP 写法与输入侧对齐
		{"0x7f.0.0.1", "127.0.0.1"},
		{"::ffff:10.0.0.5", "10.0.0.5"},
	}
	for _, tc := range tests {
		got, err := normalizeHostPattern(tc.in, false)
		if err != nil {
			t.Errorf("normalizeHostPattern(%q) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeHostPattern(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeHostPatternRejects(t *testing.T) {
	tests := []struct {
		in      string
		wantErr error
	}{
		{"", ErrInvalidHost},
		{"   ", ErrInvalidHost},
		{".", ErrInvalidHost},
		{"*.", ErrInvalidHost},
		{"**.example.com", ErrInvalidHost},   // 多打一个星号，永远匹配不上
		{"10.0.0.0/8", ErrInvalidHost},       // CIDR 应该配置到 *_cidrs
		{"example.com:8080", ErrInvalidHost}, // 端口不是主机名的一部分
		{"example..com", ErrInvalidHost},
		{"a b.example.com", ErrInvalidHost},
		{"1.2.3.4.5", ErrInvalidHost}, // 纯数字结尾，只可能是没识别出来的 IP
		{".10.0.0.5", ErrInvalidHost}, // 通配不能与 IP 字面量混用
		{"*.127.0.0.1", ErrInvalidHost},
		{"аpple.com", ErrNonASCIIHost}, // 西里尔字母 а 的同形异义写法
	}
	for _, tc := range tests {
		if _, err := normalizeHostPattern(tc.in, false); !errors.Is(err, tc.wantErr) {
			t.Errorf("normalizeHostPattern(%q) = %v, want %v", tc.in, err, tc.wantErr)
		}
	}
}

// allow_non_ascii_host 打开时，IDN 写法才允许留在名单里。
func TestNormalizeHostPatternAllowsIDNWhenEnabled(t *testing.T) {
	got, err := normalizeHostPattern("例え.jp", true)
	if err != nil {
		t.Fatalf("normalizeHostPattern(IDN, allowNonASCII=true) error = %v", err)
	}
	if got != "例え.jp" {
		t.Errorf("got %q, want %q", got, "例え.jp")
	}
}

// 回归：名单里的末尾点号曾经会变成一条永不命中的规则，且没有任何报错。
// 黑名单方向是「防护无声失效」，白名单方向是「请求被无声拒绝」，两者都属于静默失败。
func TestHostPatternWithTrailingDotStillWorks(t *testing.T) {
	ctx := context.Background()

	denied := newTestFilter(t, Config{Mode: ModeBlacklist, DeniedHosts: []string{"evil.internal."}})
	if _, err := denied.Check(ctx, "http://evil.internal/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(evil.internal) = %v, want blocked", err)
	}

	allowed := newTestFilter(t, Config{Mode: ModeWhitelist, AllowedHosts: []string{".example.com."}})
	if _, err := allowed.Check(ctx, "http://a.example.com/"); err != nil {
		t.Errorf("Check(a.example.com) = %v, want nil", err)
	}
}

// 回归：全角字符的同形异义写法在名单里同样必须命中。
func TestHostPatternWithFullWidthStillWorks(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeBlacklist, DeniedHosts: []string{"ｅｘａｍｐｌｅ.com"}})
	if _, err := f.Check(context.Background(), "http://example.com/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("Check(example.com) = %v, want blocked", err)
	}
}

// 规范化的结果要能被 Config() 看到，方便审计「实际生效的是哪条写法」。
func TestConfigExposesNormalizedHostPatterns(t *testing.T) {
	f := newTestFilter(t, Config{Mode: ModeWhitelist, AllowedHosts: []string{"  .Example.COM.  ", "127.0.0.1."}})
	got := f.Config().AllowedHosts
	want := []string{".example.com", "127.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("AllowedHosts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllowedHosts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// 非法写法必须让 New 报错，并指明是哪个字段，而不是等到运行时才发现配置没生效。
func TestNewRejectsInvalidHostPatterns(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		substr string
	}{
		{"allowed", Config{AllowedHosts: []string{"**.example.com"}}, "AllowedHosts"},
		{"denied", Config{DeniedHosts: []string{"10.0.0.0/8"}}, "DeniedHosts"},
		{"index", Config{AllowedHosts: []string{".example.com", "bad host"}}, "[1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil {
				t.Fatal("New() = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("New() error = %q, want it to mention %q", err, tc.substr)
			}
		})
	}
}

// 默认配置、以及把 Config() 的结果回灌给 New，都必须依然通过校验。
func TestNewAcceptsBuiltinAndEffectiveConfig(t *testing.T) {
	f := newTestFilter(t, Config{
		Mode:         ModeWhitelist,
		AllowedHosts: []string{".example.com"},
		DeniedHosts:  []string{"evil.internal"},
	})
	if _, err := New(f.Config()); err != nil {
		t.Errorf("New(Config()) error = %v", err)
	}
}

func TestNewRejectsNegativeDialTimeout(t *testing.T) {
	_, err := New(Config{DialTimeout: -5 * time.Second})
	if err == nil {
		t.Fatal("New(negative DialTimeout) = nil, want error")
	}
	// 0 表示「用默认值」，必须继续接受
	if _, err := New(Config{DialTimeout: 0}); err != nil {
		t.Errorf("New(DialTimeout=0) error = %v", err)
	}
}
