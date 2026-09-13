package ssrf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Format 表示配置文件的格式。
type Format string

const (
	// FormatAuto 按文件扩展名（.yaml/.yml/.json）或内容自动识别。
	FormatAuto Format = ""
	// FormatYAML YAML 格式。YAML 是 JSON 的超集，因此也能解析 JSON。
	FormatYAML Format = "yaml"
	// FormatJSON JSON 格式。
	FormatJSON Format = "json"
)

// fileConfig 是配置文件的数据结构。所有字段都是可选的，缺省即采用 Config 的安全默认值，
// 字段名统一使用 snake_case（JSON 与 YAML 共用）。
type fileConfig struct {
	Mode           string   `json:"mode" yaml:"mode"`
	AllowedSchemes []string `json:"allowed_schemes" yaml:"allowed_schemes"`
	DefaultScheme  string   `json:"default_scheme" yaml:"default_scheme"`

	AllowedHosts []string `json:"allowed_hosts" yaml:"allowed_hosts"`
	AllowedCIDRs []string `json:"allowed_cidrs" yaml:"allowed_cidrs"`
	AllowedPorts []int    `json:"allowed_ports" yaml:"allowed_ports"`

	DeniedHosts []string `json:"denied_hosts" yaml:"denied_hosts"`
	DeniedCIDRs []string `json:"denied_cidrs" yaml:"denied_cidrs"`
	DeniedPorts []int    `json:"denied_ports" yaml:"denied_ports"`

	AllowNonASCIIHost bool `json:"allow_non_ascii_host" yaml:"allow_non_ascii_host"`
	AllowUserInfo     bool `json:"allow_user_info" yaml:"allow_user_info"`
	DisableResolve    bool `json:"disable_resolve" yaml:"disable_resolve"`

	DialTimeout string `json:"dial_timeout" yaml:"dial_timeout"`
}

// ParseConfig 解析配置文件内容，format 为 FormatAuto 时按内容自动识别。
//
// 解析是严格模式：出现未知字段（通常是拼写错误）会直接报错，避免配置静默失效
// 而使用者误以为防护已经生效。
func ParseConfig(data []byte, format Format) (Config, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // 去掉 UTF-8 BOM
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, errors.New("parse config: config is empty")
	}

	auto := format == FormatAuto
	if auto {
		format = detectFormatByContent(data)
	}

	formats := []Format{format}
	if auto && format == FormatJSON {
		// 内容像 JSON 但其实是 YAML 流式写法时，回退再用 YAML 试一次
		formats = append(formats, FormatYAML)
	}

	var lastErr error
	for _, f := range formats {
		var fc fileConfig
		if err := decodeConfig(data, f, &fc); err != nil {
			lastErr = err
			continue
		}
		return fc.toConfig()
	}
	return Config{}, fmt.Errorf("parse config: %w", lastErr)
}

// LoadConfig 读取并解析配置文件。
// 格式按扩展名推断（.yaml/.yml → YAML，.json → JSON），其他扩展名按内容自动识别。
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("ssrf: read config %q: %w", path, err)
	}
	cfg, err := ParseConfig(data, formatByExtension(path))
	if err != nil {
		return Config{}, fmt.Errorf("ssrf: config %q: %w", path, err)
	}
	return cfg, nil
}

// LoadFilter 读取配置文件并构建过滤器，等价于 New(LoadConfig(path))。
func LoadFilter(path string) (*Filter, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	f, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("ssrf: config %q: %w", path, err)
	}
	return f, nil
}

// ExampleConfig 返回可直接落盘的示例配置。
// format 为 FormatJSON 时输出 JSON，否则输出带注释的 YAML。
func ExampleConfig(format Format) string {
	if format == FormatJSON {
		data, err := json.MarshalIndent(exampleFileConfig(), "", "  ")
		if err != nil {
			return ""
		}
		return string(data) + "\n"
	}
	return exampleYAML
}

// String 以 YAML 形式返回配置摘要，便于写日志排查「到底哪份配置生效了」。
// 注意：它不会输出内建黑名单，若要看生效后的完整配置请用 (*Filter).Config()。
func (c Config) String() string {
	data, err := yaml.Marshal(toFileConfig(c))
	if err != nil {
		return fmt.Sprintf("mode=%s allowedHosts=%v allowedCIDRs=%v deniedHosts=%v deniedCIDRs=%v",
			c.Mode, c.AllowedHosts, c.AllowedCIDRs, c.DeniedHosts, c.DeniedCIDRs)
	}
	return string(data)
}

func decodeConfig(data []byte, format Format, fc *fileConfig) error {
	switch format {
	case FormatJSON:
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(fc); err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("config is empty")
			}
			return fmt.Errorf("parse json config: %w", err)
		}
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(fc); err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("config is empty")
			}
			return fmt.Errorf("parse yaml config: %w (可用 ssrf.ExampleConfig 查看全部可用字段)", err)
		}
	}
	return nil
}

// toConfig 把文件结构转成 Config，并在这里完成字段级校验。
func (fc fileConfig) toConfig() (Config, error) {
	cfg := Config{
		AllowedSchemes:    cleanStrings(fc.AllowedSchemes),
		DefaultScheme:     strings.TrimSpace(fc.DefaultScheme),
		AllowedHosts:      cleanStrings(fc.AllowedHosts),
		AllowedPorts:      cleanInts(fc.AllowedPorts),
		DeniedHosts:       cleanStrings(fc.DeniedHosts),
		DeniedPorts:       cleanInts(fc.DeniedPorts),
		AllowNonASCIIHost: fc.AllowNonASCIIHost,
		AllowUserInfo:     fc.AllowUserInfo,
		DisableResolve:    fc.DisableResolve,
	}

	switch strings.ToLower(strings.TrimSpace(fc.Mode)) {
	case "", "blacklist":
		cfg.Mode = ModeBlacklist
	case "whitelist":
		cfg.Mode = ModeWhitelist
	default:
		return Config{}, fmt.Errorf("field mode: unknown value %q (want \"blacklist\" or \"whitelist\")", fc.Mode)
	}

	var err error
	if cfg.AllowedCIDRs, err = parsePrefixList(fc.AllowedCIDRs, "allowed_cidrs"); err != nil {
		return Config{}, err
	}
	if cfg.DeniedCIDRs, err = parsePrefixList(fc.DeniedCIDRs, "denied_cidrs"); err != nil {
		return Config{}, err
	}

	if s := strings.TrimSpace(fc.DialTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return Config{}, fmt.Errorf("field dial_timeout: %w", err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("field dial_timeout: must be positive, got %q", s)
		}
		cfg.DialTimeout = d
	}
	return cfg, nil
}

// toFileConfig 是 toConfig 的逆操作，用于打印配置。
func toFileConfig(c Config) fileConfig {
	fc := fileConfig{
		Mode:              c.Mode.String(),
		AllowedSchemes:    append([]string(nil), c.AllowedSchemes...),
		DefaultScheme:     c.DefaultScheme,
		AllowedHosts:      append([]string(nil), c.AllowedHosts...),
		AllowedPorts:      append([]int(nil), c.AllowedPorts...),
		DeniedHosts:       append([]string(nil), c.DeniedHosts...),
		DeniedPorts:       append([]int(nil), c.DeniedPorts...),
		AllowNonASCIIHost: c.AllowNonASCIIHost,
		AllowUserInfo:     c.AllowUserInfo,
		DisableResolve:    c.DisableResolve,
	}
	for _, p := range c.AllowedCIDRs {
		fc.AllowedCIDRs = append(fc.AllowedCIDRs, p.String())
	}
	for _, p := range c.DeniedCIDRs {
		fc.DeniedCIDRs = append(fc.DeniedCIDRs, p.String())
	}
	if c.DialTimeout > 0 {
		fc.DialTimeout = c.DialTimeout.String()
	}
	return fc
}

// parsePrefixList 解析地址段列表：接受 CIDR，也接受省略掩码的裸 IP（按 /32 或 /128 处理）。
func parsePrefixList(in []string, field string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = normalizeAddr(a)
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("field %s[%d]: %q is not a valid CIDR or IP (e.g. 10.0.0.0/8)", field, i, s)
	}
	return out, nil
}

func cleanStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cleanInts 让空列表统一为 nil，保证「配置 -> Config -> 配置」的往返结果稳定。
func cleanInts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	return in
}

func formatByExtension(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return FormatYAML
	case ".json":
		return FormatJSON
	default:
		return FormatAuto
	}
}

func detectFormatByContent(data []byte) Format {
	t := bytes.TrimLeft(data, " \t\r\n")
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		return FormatJSON
	}
	return FormatYAML
}

func exampleFileConfig() fileConfig {
	return fileConfig{
		Mode:              "whitelist",
		AllowedSchemes:    []string{"http", "https"},
		DefaultScheme:     "http",
		AllowedHosts:      []string{".example.com", "api.github.com"},
		AllowedCIDRs:      []string{"10.0.0.0/8"},
		AllowedPorts:      []int{80, 443},
		DeniedHosts:       []string{"metadata.google.internal"},
		DeniedCIDRs:       []string{"192.0.2.0/24"},
		DeniedPorts:       []int{8888},
		AllowNonASCIIHost: false,
		AllowUserInfo:     false,
		DisableResolve:    false,
		DialTimeout:       "10s",
	}
}

const exampleYAML = `# ssrf 过滤器配置文件
# JSON 版本可用 ssrf.ExampleConfig(ssrf.FormatJSON) 或 ssrfcheck -dump-config json 生成。
#
# mode:
#   blacklist  只拒绝命中的目标（内建保留地址段 + denied_* 列表）
#   whitelist  只放行显式允许的目标，其余一律拒绝（推荐）
mode: whitelist

# 允许的 URL scheme，默认 [http, https]
allowed_schemes:
  - http
  - https

# 输入不带 scheme 时补全的 scheme，默认 http
default_scheme: http

# ---------------- 白名单 ----------------
# 主机白名单，支持三种写法：
#   api.github.com   精确匹配
#   .example.com     匹配 example.com 及其所有子域
#   *.example.com    只匹配子域
allowed_hosts:
  - .example.com
  - api.github.com

# 地址段白名单，可省略掩码（按 /32 或 /128 处理）。
# 它同时是「信任标记」：只有写在这里的网段才会跳过内建保留地址段检查，
# 所以需要访问内网服务时必须在此显式放行，而不是靠域名白名单漂白。
# 注意：blacklist 模式下没有「必须命中白名单」这道闸门，这里的每个网段都只起
# 「豁免内建保留地址段」的作用——写 127.0.0.1/32 的效果是放行回环地址。
allowed_cidrs:
  - 10.0.0.0/8

# 端口白名单，留空表示不限制；仅 whitelist 模式生效
allowed_ports:
  - 80
  - 443

# ---------------- 黑名单 ----------------
# 主机黑名单。写法同 allowed_hosts：条目会先做同样的规范化（小写、折叠全角、
# 剥掉末尾点号），写错的写法（如 "**.example.com"）会让程序在启动时报错，
# 而不是留到运行时静默失效。
# 内建 metadata 主机名始终生效，无法关闭；下面这条只是示例。
denied_hosts:
  - metadata.google.internal

# 追加拒绝的地址段，叠加在内建保留地址段之上。
# 下面这条只是示例：TEST-NET 网段内建已经默认拒绝，这里写出来只为演示写法。
denied_cidrs:
  - 192.0.2.0/24

# 追加拒绝的端口，叠加在内建高危端口（22/6379/9200/11211 ...）之上
denied_ports:
  - 8888

# ---------------- 其他 ----------------
# 允许非 ASCII 主机名（IDN），默认 false，避免同形异义绕过
allow_non_ascii_host: false
# 允许 URL 中出现 user:pass@，默认 false
allow_user_info: false
# 关闭 DNS 解析，默认 false；关闭后黑名单模式的 IP 层防护会失效，请谨慎使用。
# 它只影响 Check 的校验路径，DialContext 为了建连仍会解析域名。
disable_resolve: false
# 建连超时，默认 10s
dial_timeout: 10s
`
