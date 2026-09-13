package ssrf

import (
	"math/rand"
	"strings"
	"testing"
)

func TestHostMatcherSemantics(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		host     string
		want     string // 期望命中的原始写法；空串表示不命中
	}{
		{"精确匹配", []string{"api.github.com"}, "api.github.com", "api.github.com"},
		{"精确不匹配子域", []string{"api.github.com"}, "x.api.github.com", ""},
		{"精确不匹配父域", []string{"api.github.com"}, "github.com", ""},

		{"apex 匹配自身", []string{".example.com"}, "example.com", ".example.com"},
		{"apex 匹配子域", []string{".example.com"}, "a.example.com", ".example.com"},
		{"apex 匹配多级子域", []string{".example.com"}, "a.b.c.example.com", ".example.com"},
		{"apex 不匹配后缀同名", []string{".example.com"}, "notexample.com", ""},
		{"apex 不匹配伪装后缀", []string{".example.com"}, "example.com.evil.test", ""},

		{"通配匹配子域", []string{"*.example.com"}, "a.example.com", "*.example.com"},
		{"通配匹配多级子域", []string{"*.example.com"}, "a.b.example.com", "*.example.com"},
		{"通配不匹配 apex", []string{"*.example.com"}, "example.com", ""},
		{"通配不匹配伪装后缀", []string{"*.example.com"}, "example.com.evil.test", ""},

		{"顶层标签精确匹配", []string{"com"}, "com", "com"},
		{"顶层标签不影响子域", []string{"com"}, "example.com", ""},

		{"大小写与空白被归一", []string{"  .ExAmPle.CoM  "}, "a.example.com", "  .ExAmPle.CoM  "},
		{"空名单", nil, "example.com", ""},
		{"不可能命中的写法", []string{"", ".", "*.", "*", "*.*.example.com"}, "example.com", ""},

		// 同一域名配置了多种写法时，返回的写法必须确实能匹配上该主机名
		{"exact+apex 命中 apex", []string{"example.com", ".example.com"}, "example.com", "example.com"},
		{"exact+apex 命中子域", []string{"example.com", ".example.com"}, "a.example.com", ".example.com"},
		{"apex+sub 命中 apex", []string{".example.com", "*.example.com"}, "example.com", ".example.com"},
		{"apex+sub 命中子域", []string{".example.com", "*.example.com"}, "a.example.com", ".example.com"},
		{"exact+sub 命中 apex", []string{"example.com", "*.example.com"}, "example.com", "example.com"},
		{"exact+sub 命中子域", []string{"example.com", "*.example.com"}, "a.example.com", "*.example.com"},

		// 多层规则同时覆盖时，自上而下先撞上离 TLD 最近的那条
		{"多层规则命中最近 TLD 的一条", []string{".a.example.com", ".example.com"}, "x.a.example.com", ".example.com"},
		{"多层规则命中最近 TLD 的一条（顺序无关）", []string{".example.com", ".a.example.com"}, "x.a.example.com", ".example.com"},
		{"多层通配也一样", []string{"*.a.example.com", "*.example.com"}, "x.a.example.com", "*.example.com"},
		{"中间层规则胜过更深的规则", []string{".a.b.example.com", ".b.example.com", ".example.com"}, "x.a.b.example.com", ".example.com"},
		{"只有深规则时照常命中深规则", []string{".a.example.com", ".other.test"}, "x.a.example.com", ".a.example.com"},
		{"同键上 exact 优先于 apex 与通配", []string{"*.example.com", ".example.com", "example.com"}, "example.com", "example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := newHostMatcher(tc.patterns).match(tc.host)
			if tc.want == "" {
				if ok {
					t.Fatalf("match(%q) = %q, true, want no match", tc.host, got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("match(%q) = %q, %v, want %q, true", tc.host, got, ok, tc.want)
			}
		})
	}
}

// refMatchHost 是主机名匹配的参考实现，即改造前用过的线性顺序扫描。
// 它只服务于测试，且有两个不可替代的作用：
//   - 作为 TestHostMatcherMatchesReference 的对照物：索引实现是手写的标签遍历，
//     「多层规则谁优先命中」这类语义很容易写错，需要一个独立的朴素实现对拍；
//   - 作为基准里的基线：见 BenchmarkMatchHost 的 ref/* 与 BenchmarkMatchWildcard。
func refMatchHost(patterns []string, host string) (string, bool) {
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(host, "."+p[2:]) {
				return raw, true
			}
		case strings.HasPrefix(p, "."):
			if host == p[1:] || strings.HasSuffix(host, p) {
				return raw, true
			}
		default:
			if host == p {
				return raw, true
			}
		}
	}
	return "", false
}

// TestHostMatcherMatchesReference 用随机生成的名单和主机名做差分测试：
// 索引化匹配的判定结果必须与线性参考实现完全一致，且命中时返回的写法必须是
// 「名单里真实存在、且自己就能匹配该主机名」的那一条。
//
// 注意这里只比较「是否命中」：参考实现返回的是名单里第一条命中的写法，
// 而索引实现自上而下返回的是离 TLD 最近的那条，两者本就可以不同，
// 所以对返回值另外做「在名单里 + 自己能匹配上该主机名」的校验。
func TestHostMatcherMatchesReference(t *testing.T) {
	labels := []string{"a", "b", "example", "com", "test", "cn", "sub-domain", "999"}
	rnd := rand.New(rand.NewSource(20260913))
	pick := func() string { return labels[rnd.Intn(len(labels))] }

	randomPattern := func() string {
		var b strings.Builder
		switch rnd.Intn(4) {
		case 0:
			b.WriteString(".")
		case 1:
			b.WriteString("*.")
		}
		for i, n := 0, 1+rnd.Intn(3); i < n; i++ {
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(pick())
		}
		s := b.String()
		if rnd.Intn(8) == 0 {
			s = " " + s + " "
		}
		if rnd.Intn(8) == 0 {
			s = strings.ToUpper(s)
		}
		return s
	}
	randomHost := func() string {
		parts := make([]string, 1+rnd.Intn(4))
		for i := range parts {
			parts[i] = pick()
		}
		return strings.Join(parts, ".")
	}

	for i := 0; i < 2000; i++ {
		patterns := make([]string, 1+rnd.Intn(6))
		for j := range patterns {
			patterns[j] = randomPattern()
		}
		m := newHostMatcher(patterns)

		for k := 0; k < 20; k++ {
			host := randomHost()
			wantPattern, wantHit := refMatchHost(patterns, host)
			gotPattern, gotHit := m.match(host)
			if gotHit != wantHit {
				t.Fatalf("patterns=%q host=%q: match = %q, %v, 参考实现 = %q, %v",
					patterns, host, gotPattern, gotHit, wantPattern, wantHit)
			}
			if !gotHit {
				continue
			}
			var inList bool
			for _, p := range patterns {
				if p == gotPattern {
					inList = true
					break
				}
			}
			if !inList {
				t.Fatalf("patterns=%q host=%q: 返回的写法 %q 不在名单里", patterns, host, gotPattern)
			}
			if _, ok := refMatchHost([]string{gotPattern}, host); !ok {
				t.Fatalf("patterns=%q host=%q: 返回的写法 %q 其实匹配不上该主机名", patterns, host, gotPattern)
			}
		}
	}
}
