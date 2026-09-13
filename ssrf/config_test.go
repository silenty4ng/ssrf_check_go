package ssrf

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const sampleYAML = `
mode: whitelist
allowed_schemes: [http, https]
default_scheme: http
allowed_hosts:
  - .example.com
  - api.github.com
allowed_cidrs:
  - 10.0.0.0/8
allowed_ports: [80, 443]
denied_hosts:
  - bad.test
denied_cidrs:
  - 192.0.2.0/24
denied_ports: [8888]
allow_non_ascii_host: false
allow_user_info: false
disable_resolve: false
dial_timeout: 5s
`

const sampleJSON = `{
  "mode": "whitelist",
  "allowed_schemes": ["http", "https"],
  "default_scheme": "http",
  "allowed_hosts": [".example.com", "api.github.com"],
  "allowed_cidrs": ["10.0.0.0/8"],
  "allowed_ports": [80, 443],
  "denied_hosts": ["bad.test"],
  "denied_cidrs": ["192.0.2.0/24"],
  "denied_ports": [8888],
  "allow_non_ascii_host": false,
  "allow_user_info": false,
  "disable_resolve": false,
  "dial_timeout": "5s"
}`

func TestParseConfigYAML(t *testing.T) {
	cfg, err := ParseConfig([]byte(sampleYAML), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	want := Config{
		Mode:           ModeWhitelist,
		AllowedSchemes: []string{"http", "https"},
		DefaultScheme:  "http",
		AllowedHosts:   []string{".example.com", "api.github.com"},
		AllowedCIDRs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AllowedPorts:   []int{80, 443},
		DeniedHosts:    []string{"bad.test"},
		DeniedCIDRs:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		DeniedPorts:    []int{8888},
		DialTimeout:    5 * time.Second,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("ParseConfig(yaml) =\n%+v\nwant\n%+v", cfg, want)
	}
}

// YAML 与 JSON 描述同一份配置时必须得到完全相同的 Config。
func TestParseConfigJSONMatchesYAML(t *testing.T) {
	fromYAML, err := ParseConfig([]byte(sampleYAML), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig(yaml) error = %v", err)
	}
	fromJSON, err := ParseConfig([]byte(sampleJSON), FormatJSON)
	if err != nil {
		t.Fatalf("ParseConfig(json) error = %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Errorf("yaml/json 解析结果不一致:\nyaml=%+v\njson=%+v", fromYAML, fromJSON)
	}
}

func TestParseConfigAutoFormat(t *testing.T) {
	// FormatAuto：以 { 开头按 JSON 解析
	if _, err := ParseConfig([]byte(sampleJSON), FormatAuto); err != nil {
		t.Errorf("ParseConfig(auto json) error = %v", err)
	}
	// 其他内容按 YAML 解析
	if _, err := ParseConfig([]byte(sampleYAML), FormatAuto); err != nil {
		t.Errorf("ParseConfig(auto yaml) error = %v", err)
	}
	// YAML 流式映射以 { 开头但不是合法 JSON，应回退到 YAML
	if _, err := ParseConfig([]byte("{mode: whitelist}"), FormatAuto); err != nil {
		t.Errorf("ParseConfig(auto flow yaml) error = %v", err)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"conf.yaml", "conf.yml", "conf.json", "conf.conf"} {
		body := sampleYAML
		if strings.HasSuffix(name, ".json") {
			body = sampleJSON
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig(%s) error = %v", name, err)
		}
		if cfg.Mode != ModeWhitelist || len(cfg.AllowedHosts) != 2 {
			t.Errorf("LoadConfig(%s) = %+v, want whitelist with 2 hosts", name, cfg)
		}
	}

	f, err := LoadFilter(filepath.Join(dir, "conf.yaml"))
	if err != nil {
		t.Fatalf("LoadFilter() error = %v", err)
	}
	// 配置里的 .example.com 生效，其余拒绝
	f.cfg.LookupIP = fakeLookup(map[string][]string{
		"a.example.com": {"93.184.216.34"},
		"evil.test":     {"93.184.216.34"},
	})
	if _, err := f.Check(context.Background(), "http://a.example.com/"); err != nil {
		t.Errorf("Check(a.example.com) = %v, want allowed", err)
	}
	if _, err := f.Check(context.Background(), "http://evil.test/"); err == nil {
		t.Error("Check(evil.test) = nil, want blocked")
	}
	// 内建黑名单与配置中的黑名单都会生效
	if p, ok := f.deniedHosts.match("localhost"); !ok {
		t.Errorf("denied hosts %v 里应包含内建项 localhost (%s)", f.Config().DeniedHosts, p)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("LoadConfig(missing) = %v, want read error", err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "config is empty"},
		{"blank", "   \n\t\n", "config is empty"},
		{"unknown field", "unknown_key: 1\n", "unknown_key"},
		{"bad mode", "mode: strict\n", "field mode"},
		{"bad cidr", "allowed_cidrs:\n  - 10.0.0.0/8\n  - not-a-cidr\n", "allowed_cidrs[1]"},
		// YAML 会把标量 10 当成字符串 "10"，因此这里由 ParseDuration 报错（含字段名）
		{"bad duration type", "dial_timeout: 10\n", "dial_timeout"},
		{"negative duration", "dial_timeout: -1s\n", "must be positive"},
		{"bad scheme type", "allowed_schemes: 80\n", "cannot unmarshal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.data), FormatAuto)
			if err == nil {
				t.Fatalf("ParseConfig(%q) = nil, want error containing %q", tc.data, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseConfig(%q) error = %v, want containing %q", tc.data, err, tc.want)
			}
		})
	}

	// 端口越界交给 New 校验，LoadFilter 必须把错误暴露出来而不是静默放行
	dir := t.TempDir()
	path := filepath.Join(dir, "port.yaml")
	if err := os.WriteFile(path, []byte("allowed_ports: [99999]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFilter(path); err == nil {
		t.Error("LoadFilter(bad port) = nil, want error")
	}
}

// 示例配置必须永远可用：既能被严格解析，也必须是安全的 whitelist 配置。
func TestExampleConfig(t *testing.T) {
	yamlCfg, err := ParseConfig([]byte(ExampleConfig(FormatYAML)), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig(ExampleConfig(yaml)) error = %v", err)
	}
	jsonCfg, err := ParseConfig([]byte(ExampleConfig(FormatJSON)), FormatJSON)
	if err != nil {
		t.Fatalf("ParseConfig(ExampleConfig(json)) error = %v", err)
	}
	if !reflect.DeepEqual(yamlCfg, jsonCfg) {
		t.Errorf("示例配置的 yaml/json 版本不一致:\nyaml=%+v\njson=%+v", yamlCfg, jsonCfg)
	}
	if yamlCfg.Mode != ModeWhitelist {
		t.Errorf("示例配置 mode = %v, want whitelist", yamlCfg.Mode)
	}
	f, err := New(yamlCfg)
	if err != nil {
		t.Fatalf("New(example) error = %v", err)
	}
	if _, err := f.Check(context.Background(), "http://169.254.169.254/"); err == nil {
		t.Error("示例配置不应放行 169.254.169.254")
	}
}

// 仓库里的示例文件必须与 ExampleConfig 保持一致，避免文档漂移。
func TestExamplesDirMatchesExampleConfig(t *testing.T) {
	cases := []struct {
		path   string
		format Format
	}{
		{filepath.Join("..", "examples", "ssrf.yaml"), FormatYAML},
		{filepath.Join("..", "examples", "ssrf.json"), FormatJSON},
	}
	for _, tc := range cases {
		body, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("读不到示例文件 %s: %v", tc.path, err)
		}
		if string(body) != ExampleConfig(tc.format) {
			t.Errorf("%s 与 ExampleConfig(%s) 不一致，请用 ssrfcheck -dump-config %s 重新生成",
				tc.path, tc.format, tc.format)
		}
	}
}

func TestConfigStringRoundTrip(t *testing.T) {
	original, err := ParseConfig([]byte(sampleYAML), FormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	f := MustNew(original)

	for name, cfg := range map[string]Config{
		"parsed":    original,
		"effective": f.Config(),
		"zero":      {},
	} {
		text := cfg.String()
		back, err := ParseConfig([]byte(text), FormatAuto)
		if err != nil {
			t.Fatalf("%s: ParseConfig(String()) error = %v\ntext:\n%s", name, err, text)
		}
		if !sameConfig(back, cfg) {
			t.Errorf("%s: 往返不一致\n原文:\n%s\n得到: %+v\nwant: %+v", name, text, back, cfg)
		}
	}
}

// sameConfig 比较两份配置，忽略无法序列化的字段（LookupIP）。
func sameConfig(a, b Config) bool {
	a.LookupIP, b.LookupIP = nil, nil
	return reflect.DeepEqual(a, b)
}

func TestConfigCIDRNormalization(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
allowed_cidrs:
  - ::ffff:10.0.0.0/104
  - 93.184.216.34
  - 2001:db8::/32
`), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),       // 4-in-6 网段被还原成 IPv4
		netip.MustParsePrefix("93.184.216.34/32"), // 裸 IP 按 /32 处理
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(f.Config().AllowedCIDRs, want) {
		t.Errorf("AllowedCIDRs = %v, want %v", f.Config().AllowedCIDRs, want)
	}
}
