package ssrf

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
)

const (
	// benchHitHost 命中 hostPatterns 的最后一条，对应线性扫描的最坏情况。
	benchHitHost = "www.deep.target.test"
	// benchMissHost 命中不了任何一条，对应线性扫描的完整遍历。
	benchMissHost = "api.other.test"
)

// hostPatterns 构造 n 条域名规则，最后一条能匹配 benchHitHost。
func hostPatterns(n int) []string {
	list := make([]string, 0, n)
	for i := 0; i < n-1; i++ {
		list = append(list, ".example-"+strconv.Itoa(i)+".test")
	}
	return append(list, ".target.test")
}

// BenchmarkMatchHost 把索引实现与线性参考实现放在同一张表里对比：
// hit 是命中最坏情况（最后一条），miss 要遍历完整名单，
// index/* 与 ref/* 的差距就是索引化带来的收益。
func BenchmarkMatchHost(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		list := hostPatterns(n)
		m := newHostMatcher(list)
		scale := strconv.Itoa(n)

		b.Run("index/hit/"+scale, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := m.match(benchHitHost); !ok {
					b.Fatal("want hit")
				}
			}
		})
		b.Run("index/miss/"+scale, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := m.match(benchMissHost); ok {
					b.Fatal("want miss")
				}
			}
		})
		b.Run("ref/hit/"+scale, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := refMatchHost(list, benchHitHost); !ok {
					b.Fatal("want hit")
				}
			}
		})
		b.Run("ref/miss/"+scale, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := refMatchHost(list, benchMissHost); ok {
					b.Fatal("want miss")
				}
			}
		})
	}
}

// BenchmarkMatchHostOwnEntry 覆盖另一种真实形状：查询本身就是名单里的条目。
// 真实黑名单里三层以上的主机名条目很多（StevenBlack 名单 79,962 条里占 66.8%），
// 自上而下遇到这种形状要从顶级标签一路走满三层才命中，是它相对最不利的情况。
// 这里父域 "ownentry.test" 刻意不在名单里，否则走到第二层就会被命中而提前返回。
func BenchmarkMatchHostOwnEntry(b *testing.B) {
	const host = "deep.ownentry.test"
	m := newHostMatcher(append(hostPatterns(10000), "."+host))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := m.match(host); !ok {
			b.Fatal("want hit")
		}
	}
}

// BenchmarkMatchWildcard 对比 "*.example.com" 写法的开销：线性实现在每次匹配时
// 都要拼接一次 "."+pattern（编译器把它放在栈上，所以没有堆分配，但仍要拷贝）。
func BenchmarkMatchWildcard(b *testing.B) {
	const n = 1000
	list := make([]string, n)
	for i := range list {
		list[i] = "*.example-" + strconv.Itoa(i) + ".test"
	}
	m := newHostMatcher(list)
	host := "www.example-999.test" // 命中最坏情况：最后一条

	b.Run("ref", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := refMatchHost(list, host); !ok {
				b.Fatal("want hit")
			}
		}
	})
	b.Run("index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := m.match(host); !ok {
				b.Fatal("want hit")
			}
		}
	})
}

// BenchmarkCheckHostOnly 只走域名白名单（关闭 DNS），此时链路里几乎没有别的开销，
// 域名匹配的占比会被放大到最不利的情况。
func BenchmarkCheckHostOnly(b *testing.B) {
	f := MustNew(Config{
		Mode:           ModeWhitelist,
		AllowedHosts:   hostPatterns(1000),
		DisableResolve: true,
		LookupIP:       benchLookup,
	})
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := f.Check(ctx, "http://"+benchHitHost+"/"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCheckFull 走完整路径：标准化 + 黑白名单 + 解析 + 逐 IP 校验。
// 这里用固定结果代替真实 DNS，以排除网络抖动；真实 DNS 通常还要 1~30ms。
func BenchmarkCheckFull(b *testing.B) {
	f := MustNew(Config{
		Mode:         ModeWhitelist,
		AllowedHosts: hostPatterns(1000),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		LookupIP:     benchLookup,
	})
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := f.Check(ctx, "https://"+benchHitHost+"/path?q=1"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchLookup(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}
