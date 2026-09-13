package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssrfguard/ssrf"
)

const testConfig = `mode: whitelist
allowed_hosts:
  - .example.com
allowed_cidrs:
  - 10.0.0.0/8
allowed_ports:
  - 80
  - 443
denied_hosts:
  - evil.internal
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssrf.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写测试配置失败: %v", err)
	}
	return path
}

// 只有「命令行里显式出现过的」flag 才能覆盖配置文件，默认值不行——
// 否则 -config 加载的配置会被 flag 的零值悄悄清空。
func TestBuildConfigOnlyOverridesExplicitFlags(t *testing.T) {
	path := writeConfig(t, testConfig)

	t.Run("只用配置文件", func(t *testing.T) {
		cfg, source, err := buildConfig(options{configPath: path}, map[string]bool{})
		if err != nil {
			t.Fatalf("buildConfig() error = %v", err)
		}
		if source != path {
			t.Errorf("source = %q, want %q", source, path)
		}
		if cfg.Mode != ssrf.ModeWhitelist {
			t.Errorf("Mode = %v, want whitelist", cfg.Mode)
		}
		if !reflect.DeepEqual(cfg.AllowedHosts, []string{".example.com"}) {
			t.Errorf("AllowedHosts = %v", cfg.AllowedHosts)
		}
		if !reflect.DeepEqual(cfg.AllowedPorts, []int{80, 443}) {
			t.Errorf("AllowedPorts = %v", cfg.AllowedPorts)
		}
	})

	t.Run("默认值不覆盖", func(t *testing.T) {
		// opts 里带着零值（mode 默认串、空的名单），但 set 为空表示用户没传过
		cfg, _, err := buildConfig(options{configPath: path, mode: "blacklist"}, map[string]bool{})
		if err != nil {
			t.Fatalf("buildConfig() error = %v", err)
		}
		if cfg.Mode != ssrf.ModeWhitelist {
			t.Errorf("Mode = %v, want 配置文件里的 whitelist", cfg.Mode)
		}
		if !reflect.DeepEqual(cfg.AllowedHosts, []string{".example.com"}) {
			t.Errorf("AllowedHosts 被默认值覆盖了: %v", cfg.AllowedHosts)
		}
	})

	t.Run("只覆盖传了的字段", func(t *testing.T) {
		cfg, _, err := buildConfig(
			options{configPath: path, mode: "blacklist", denyHosts: "a.test,b.test"},
			map[string]bool{"mode": true, "deny-hosts": true},
		)
		if err != nil {
			t.Fatalf("buildConfig() error = %v", err)
		}
		if cfg.Mode != ssrf.ModeBlacklist {
			t.Errorf("Mode = %v, want blacklist", cfg.Mode)
		}
		if !reflect.DeepEqual(cfg.DeniedHosts, []string{"a.test", "b.test"}) {
			t.Errorf("DeniedHosts = %v", cfg.DeniedHosts)
		}
		// 没传的字段必须保留配置文件里的值
		if !reflect.DeepEqual(cfg.AllowedPorts, []int{80, 443}) {
			t.Errorf("AllowedPorts 被覆盖了: %v", cfg.AllowedPorts)
		}
		if !reflect.DeepEqual(cfg.AllowedCIDRs, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
			t.Errorf("AllowedCIDRs = %v", cfg.AllowedCIDRs)
		}
	})

	t.Run("无配置文件", func(t *testing.T) {
		cfg, source, err := buildConfig(options{mode: "whitelist"}, map[string]bool{"mode": true})
		if err != nil {
			t.Fatalf("buildConfig() error = %v", err)
		}
		if source != "命令行参数/默认值" {
			t.Errorf("source = %q", source)
		}
		if cfg.Mode != ssrf.ModeWhitelist {
			t.Errorf("Mode = %v, want whitelist", cfg.Mode)
		}
	})
}

func TestBuildConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		opts options
		set  map[string]bool
	}{
		{"mode", options{mode: "nope"}, map[string]bool{"mode": true}},
		{"allow-cidrs", options{allowCIDRs: "10.0.0.0/8,abc"}, map[string]bool{"allow-cidrs": true}},
		{"deny-cidrs", options{denyCIDRs: "abc"}, map[string]bool{"deny-cidrs": true}},
		{"allow-ports", options{allowPorts: "0"}, map[string]bool{"allow-ports": true}},
		{"deny-ports", options{denyPorts: "70000"}, map[string]bool{"deny-ports": true}},
		{"config", options{configPath: filepath.Join("no", "such", "file.yaml")}, map[string]bool{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := buildConfig(tc.opts, tc.set); err == nil {
				t.Error("buildConfig() = nil, want error")
			}
		})
	}
}

// 非法的主机名单写法必须在 CLI 上直接报错，而不是运行时静默失效。
func TestRunRejectsInvalidHostPattern(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-allow-hosts", "**.example.com", "http://a.example.com/"}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "AllowedHosts") {
		t.Errorf("stderr = %q, want it to mention AllowedHosts", errOut.String())
	}
}

func TestRunChecksTargetsFromStdin(t *testing.T) {
	path := writeConfig(t, testConfig)
	var out, errOut bytes.Buffer
	stdin := strings.NewReader("http://10.0.0.5/\nhttp://169.254.169.254/\n\n")

	if code := run([]string{"-config", path}, stdin, &out, &errOut); code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, errOut.String())
	}
	got := out.String()
	// 显式信任的网段放行，云 metadata 地址仍被拒绝
	if !strings.Contains(got, "ALLOW   http://10.0.0.5/") {
		t.Errorf("输出缺少放行 10.0.0.5 的行:\n%s", got)
	}
	if !strings.Contains(got, "REJECT  http://169.254.169.254/") {
		t.Errorf("输出缺少拒绝 metadata 的行:\n%s", got)
	}
	// 空行被跳过，不应产生 REJECT 行
	if strings.Contains(got, "REJECT  \n") {
		t.Errorf("空行不应被当成待校验地址:\n%s", got)
	}
}

func TestRunWithoutInput(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "标准输入") {
		t.Errorf("stderr = %q, want 用法提示", errOut.String())
	}
}

// -print-config 是排查「到底哪份配置生效了」的主要手段，输出必须包含内建黑名单。
func TestRunPrintConfig(t *testing.T) {
	path := writeConfig(t, testConfig)
	var out, errOut bytes.Buffer
	if code := run([]string{"-print-config", "-config", path}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("run() = %d, want 0, stderr=%q", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{"# 配置来源: " + path, "mode: whitelist", "metadata.azure.com", ".example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("print-config 输出缺少 %q:\n%s", want, got)
		}
	}
}

func TestRunDumpConfig(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run([]string{"-dump-config", "yaml"}, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("run() = %d, want 0", code)
		}
		if out.String() != ssrf.ExampleConfig(ssrf.FormatYAML) {
			t.Error("-dump-config yaml 的输出与 ssrf.ExampleConfig 不一致")
		}
	})

	t.Run("file", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "out.json")
		var out, errOut bytes.Buffer
		if code := run([]string{"-dump-config", "json", "-o", target}, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("run() = %d, want 0", code)
		}
		body, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("读回输出文件失败: %v", err)
		}
		if string(body) != ssrf.ExampleConfig(ssrf.FormatJSON) {
			t.Error("落盘的 JSON 与 ssrf.ExampleConfig(FormatJSON) 不一致")
		}
		// 落盘时不应该同时把内容打到 stdout
		if out.Len() != 0 {
			t.Errorf("stdout = %q, want empty", out.String())
		}
	})
}

// 这个组合极易被误读成「多允许一点」，CLI 上有义务提醒它实际意味着什么。
func TestRunWarnsOnBlacklistWithAllowedCIDRs(t *testing.T) {
	var out, errOut bytes.Buffer
	// 用字面量地址，避免测试依赖真实 DNS
	args := []string{"-allow-cidrs", "127.0.0.1/32", "-deny-cidrs", "10.0.0.0/8", "http://8.8.8.8/"}
	if code := run(args, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !strings.Contains(errOut.String(), "信任标记") {
		t.Errorf("stderr = %q, want 含「信任标记」的提醒", errOut.String())
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" .example.com , ,api.github.com ")
	want := []string{".example.com", "api.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitList() = %v, want %v", got, want)
	}
	if got := splitList(""); got != nil {
		t.Errorf("splitList(\"\") = %v, want nil", got)
	}
}

func TestParseIntsAndPrefixes(t *testing.T) {
	ports, err := parseInts("80, 443", "-allow-ports")
	if err != nil || !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Errorf("parseInts() = %v, %v", ports, err)
	}
	for _, bad := range []string{"0", "65536", "abc", "-1", ""} {
		if _, err := parseInts(bad, "-allow-ports"); err == nil && bad != "" {
			t.Errorf("parseInts(%q) = nil error, want error", bad)
		}
	}

	// 裸 IP 按 /32 处理，与前缀写法等价
	ps, err := parsePrefixes("10.0.0.0/8,127.0.0.1", "-allow-cidrs")
	if err != nil {
		t.Fatalf("parsePrefixes() error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}
	if !reflect.DeepEqual(ps, want) {
		t.Errorf("parsePrefixes() = %v, want %v", ps, want)
	}
	if _, err := parsePrefixes("abc", "-allow-cidrs"); err == nil {
		t.Error("parsePrefixes(\"abc\") = nil error, want error")
	}
}
