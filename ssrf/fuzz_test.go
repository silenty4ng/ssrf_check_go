package ssrf

import (
	"context"
	"testing"
)

// FuzzCheck 用随机输入冲击「解析 -> 规范化 -> 判定」这条最容易被绕过的路径。
//
// 两个不变量：
//  1. 任何输入都不能 panic（解析器是纯手写的，最容易在边界上崩）；
//  2. 一旦某个输入被接受，它自己产出的标准化结果也必须被接受，且再次标准化保持不变
//     （幂等）。否则「先 Check 再使用 Normalized」的调用方会拿到与校验结果不一致的地址。
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		"http://example.com/",
		"example.com",
		"example.com/a?b=c#d",
		"127.0.0.1:8080",
		"http://2130706433/",
		"http://0177.0.0.1/",
		"http://0x7f.1/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::1]:8080/",
		"http://127.0.0.1./",
		"http://１２７.０.０.１/",
		"http://user:pass@example.com/",
		"HTTP://EXAMPLE.COM./x",
		"http://example.com/%2e%2e/",
		"//example.com/",
		"http://",
	} {
		f.Add(s)
	}

	// 关掉 DNS：让 fuzz 完全离线，把火力集中在解析与匹配上。
	filter, err := New(Config{Mode: ModeBlacklist, DisableResolve: true})
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, raw string) {
		res, err := filter.Check(ctx, raw)
		if err != nil {
			return // 拒绝是合法结论，只要不 panic
		}
		again, err := filter.Check(ctx, res.Normalized)
		if err != nil {
			t.Fatalf("Check(%q) 接受，但 Check(标准化结果 %q) 被拒: %v", raw, res.Normalized, err)
		}
		if again.Normalized != res.Normalized {
			t.Fatalf("标准化不幂等: %q -> %q -> %q", raw, res.Normalized, again.Normalized)
		}
		if again.Host != res.Host || again.Port != res.Port {
			t.Fatalf("host/port 不稳定: %q 得到 (%q,%d)，再次得到 (%q,%d)",
				raw, res.Host, res.Port, again.Host, again.Port)
		}
	})
}

// FuzzParseConfig 用随机字节冲击配置解析：必须不 panic，
// 且解析成功的配置要能通过 Config.String() 稳定往返（否则 -print-config 的输出不可信）。
func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		"mode: whitelist\nallowed_hosts:\n  - .example.com\n",
		"mode: blacklist\nallowed_ports:\n  - 80\n",
		`{"mode":"whitelist","allowed_cidrs":["10.0.0.0/8"],"denied_ports":[8888]}`,
		"allowed_hosts: []\ndial_timeout: 5s\n",
		"{}",
		"[]",
		"mode: ",
		"unknown_field: 1",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range []Format{FormatAuto, FormatYAML, FormatJSON} {
			cfg, err := ParseConfig(data, format)
			if err != nil {
				continue
			}
			text := cfg.String()
			back, err := ParseConfig([]byte(text), FormatAuto)
			if err != nil {
				t.Fatalf("format=%s: 解析成功但 Config.String() 无法再次解析: %v\n原文: %q\n输出:\n%s",
					format, err, data, text)
			}
			if !sameConfig(back, cfg) {
				t.Fatalf("format=%s: 往返不一致\n原文: %q\n输出:\n%s\n得到: %+v\nwant: %+v",
					format, data, text, back, cfg)
			}
		}
	})
}
