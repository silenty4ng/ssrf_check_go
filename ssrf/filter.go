// Package ssrf 提供一套防御 SSRF（服务端请求伪造）的地址过滤组件：
//
//  1. 标准化 Normalize：把用户输入的畸形写法（十进制/八进制/十六进制 IP、简写 IP、
//     IPv4-mapped IPv6、全角字符、末尾点号、控制字符等）统一成规范形式；
//  2. 过滤 Check：按黑名单或白名单校验 scheme / host / port / DNS 解析后的全部 IP；
//  3. 运行时兜底 Control / DialContext：在真正建连时再次校验并固定已解析的 IP，
//     防止 DNS Rebinding（校验时解析到公网 IP，建连时解析到内网 IP）。
//
// 最小用法：
//
//	f, err := ssrf.New(ssrf.Config{
//		Mode:         ssrf.ModeWhitelist,
//		AllowedHosts: []string{".example.com"},
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if _, err := f.Check(ctx, userInput); err != nil {
//		// 拒绝请求
//	}
//	client := &http.Client{Transport: f.NewTransport()}
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrBlocked 是过滤阶段所有拦截错误的统一判定入口，配合 errors.Is 使用。
//
// 标准化阶段的错误是另一类（ErrEmptyInput / ErrInvalidURL / ErrBadScheme / ErrUserInfo /
// ErrInvalidHost / ErrNonASCIIHost）：它们同样意味着「这次请求必须拒绝」，
// 但不满足 errors.Is(err, ErrBlocked)，便于调用方区分「输入非法」与「策略拦截」。
var ErrBlocked = errors.New("ssrf: request blocked")

// 拦截原因，可通过 BlockedError.Reason 读取。
const (
	ReasonDeniedHost       = "host_denied"
	ReasonHostNotAllowed   = "host_not_allowed"
	ReasonResolveFailed    = "resolve_failed"
	ReasonReservedIP       = "reserved_ip"
	ReasonDeniedIP         = "ip_denied"
	ReasonNotAllowedIP     = "ip_not_allowed"
	ReasonDeniedPort       = "port_denied"
	ReasonPortNotAllowed   = "port_not_allowed"
	ReasonTooManyRedirects = "too_many_redirects"
)

// BlockedError 表示一次请求被 SSRF 过滤器拦截。
type BlockedError struct {
	Reason string // 拦截原因，见 Reason* 常量
	Detail string // 人类可读的细节
}

func (e *BlockedError) Error() string {
	return "ssrf blocked (" + e.Reason + "): " + e.Detail
}

// Is 让 errors.Is(err, ErrBlocked) 成立。
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

func block(reason, format string, args ...any) *BlockedError {
	return &BlockedError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Mode 决定过滤策略。
type Mode int

const (
	// ModeBlacklist 黑名单模式：只拒绝命中的目标（默认）。
	ModeBlacklist Mode = iota
	// ModeWhitelist 白名单模式（推荐）：只放行显式允许的目标，其余全部拒绝。
	ModeWhitelist
)

func (m Mode) String() string {
	if m == ModeWhitelist {
		return "whitelist"
	}
	return "blacklist"
}

// Config 是过滤器配置，所有布尔字段的零值都是安全默认值。
type Config struct {
	// Mode 过滤模式，默认 ModeBlacklist。
	Mode Mode

	// AllowedSchemes 允许的 URL scheme，默认 http/https。
	AllowedSchemes []string
	// DefaultScheme 输入未带 scheme 时补全的 scheme，默认 "http"。
	DefaultScheme string

	// ---- 白名单 ----

	// AllowedHosts 允许的主机名，支持三种写法：
	//   "example.com"   精确匹配
	//   ".example.com"  匹配 example.com 及其所有子域
	//   "*.example.com" 只匹配子域
	//
	// 名单在 New 时被预编译成索引，单次匹配只与域名的标签数有关，与名单规模无关，
	// 因此可以放心配置上万条。
	AllowedHosts []string
	// AllowedCIDRs 允许访问的地址段。它同时也是"信任标记"：只有落在白名单地址段内的
	// IP 才允许跳过内建保留地址段（回环/私网/链路本地等）检查。
	// 即：想访问内网服务，必须在这里显式放行对应网段，而不是靠域名白名单漂白。
	AllowedCIDRs []netip.Prefix
	// AllowedPorts 允许的端口，为空表示不限制（仅白名单模式生效）。
	AllowedPorts []int

	// ---- 黑名单 ----

	// DeniedHosts 拒绝的主机名，写法同 AllowedHosts（同样会预编译成索引）。
	// 同一主机名被多条规则覆盖时（如同时配了 ".example.com" 与 ".a.example.com"），
	// 拦截信息里回显的是离 TLD 最近、覆盖范围最大的那条（这里是 ".example.com"）；
	// 拒绝与否的判定不受遍历顺序影响。
	DeniedHosts []string
	// DeniedCIDRs 额外拒绝的地址段（叠加在内建保留地址段之上）。
	DeniedCIDRs []netip.Prefix
	// DeniedPorts 拒绝的端口，默认叠加 defaultDeniedPorts 中的高危端口。
	DeniedPorts []int

	// AllowNonASCIIHost 允许非 ASCII 主机名（IDN），默认 false 直接拒绝，
	// 避免 IDN 同形异义绕过。如需支持国际域名，请先做 punycode 归一后再传入。
	AllowNonASCIIHost bool
	// AllowUserInfo 允许 URL 中出现 user:pass@，默认 false。
	AllowUserInfo bool

	// DisableResolve 关闭 DNS 解析（默认 false，即开启）。
	// 关闭后黑名单模式将失去 IP 层防护，仅建议在纯域名白名单场景下使用。
	DisableResolve bool
	// LookupIP 自定义解析函数，便于测试或接入内部 DNS，默认 net.DefaultResolver。
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)

	// DialTimeout DialContext 使用的超时，默认 10s。
	DialTimeout time.Duration
}

// Filter 构造后只读，可并发使用。
type Filter struct {
	cfg     Config
	builtin []netip.Prefix // 内建保留地址段

	// 主机名黑白名单的索引：构建时预编译一次，避免每个请求都遍历整个名单
	allowedHosts hostMatcher
	deniedHosts  hostMatcher
}

// New 构建过滤器。配置非法（如 Mode 未知、CIDR / 端口越界）时返回错误，绝不静默放行。
func New(cfg Config) (*Filter, error) {
	// 未知 Mode 不能静默按黑名单处理：那会把「本该只放行白名单」的
	// 笔误配置悄悄变成几乎不拦截，属于典型的 fail open。
	if cfg.Mode != ModeBlacklist && cfg.Mode != ModeWhitelist {
		return nil, fmt.Errorf("ssrf: invalid mode %d", cfg.Mode)
	}

	if len(cfg.AllowedSchemes) == 0 {
		cfg.AllowedSchemes = []string{"http", "https"}
	}
	schemes := make([]string, 0, len(cfg.AllowedSchemes))
	for _, s := range cfg.AllowedSchemes {
		schemes = append(schemes, strings.ToLower(strings.TrimSpace(s)))
	}
	cfg.AllowedSchemes = schemes

	if cfg.DefaultScheme == "" {
		cfg.DefaultScheme = "http"
	}
	cfg.DefaultScheme = strings.ToLower(cfg.DefaultScheme)

	allowedCIDRs, err := normalizePrefixes(cfg.AllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid AllowedCIDRs: %w", err)
	}
	cfg.AllowedCIDRs = allowedCIDRs

	deniedCIDRs, err := normalizePrefixes(cfg.DeniedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid DeniedCIDRs: %w", err)
	}
	cfg.DeniedCIDRs = deniedCIDRs

	for _, p := range append(append([]int{}, cfg.AllowedPorts...), cfg.DeniedPorts...) {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("ssrf: invalid port %d", p)
		}
	}

	// 内建规则始终叠加，无法被关闭（如需放行请使用 AllowedCIDRs 显式信任）
	hosts := make([]string, 0, len(cfg.DeniedHosts)+len(defaultDeniedHosts))
	hosts = append(hosts, cfg.DeniedHosts...)
	hosts = append(hosts, defaultDeniedHosts...)
	cfg.DeniedHosts = hosts

	ports := make([]int, 0, len(cfg.DeniedPorts)+len(defaultDeniedPorts))
	ports = append(ports, cfg.DeniedPorts...)
	ports = append(ports, defaultDeniedPorts...)
	cfg.DeniedPorts = ports

	if cfg.LookupIP == nil {
		cfg.LookupIP = defaultLookupIP
	}

	f := &Filter{cfg: cfg, builtin: blockedPrefixes}
	f.allowedHosts = newHostMatcher(cfg.AllowedHosts)
	f.deniedHosts = newHostMatcher(cfg.DeniedHosts)
	return f, nil
}

// MustNew 与 New 相同，配置非法时 panic，适合 init / 测试中使用。
func MustNew(cfg Config) *Filter {
	f, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return f
}

// Config 返回构建时实际生效的配置（已合并内建黑名单与默认值），便于日志排查与审计。
// 返回的是副本：调用方修改它（包括其中的切片）不会影响 Filter。
func (f *Filter) Config() Config {
	c := f.cfg
	c.AllowedSchemes = append([]string(nil), f.cfg.AllowedSchemes...)
	c.AllowedHosts = append([]string(nil), f.cfg.AllowedHosts...)
	c.AllowedCIDRs = append([]netip.Prefix(nil), f.cfg.AllowedCIDRs...)
	c.AllowedPorts = append([]int(nil), f.cfg.AllowedPorts...)
	c.DeniedHosts = append([]string(nil), f.cfg.DeniedHosts...)
	c.DeniedCIDRs = append([]netip.Prefix(nil), f.cfg.DeniedCIDRs...)
	c.DeniedPorts = append([]int(nil), f.cfg.DeniedPorts...)
	return c
}

// Result 是校验通过后的目标信息。
type Result struct {
	Original   string       // 用户原始输入
	Normalized string       // 标准化后的 URL
	URL        *url.URL     // 标准化后的 URL 对象
	Host       string       // 规范化后的主机名或 IP
	Port       int          // 端口（未指定时已补全 scheme 默认端口）
	IsIP       bool         // Host 是否为 IP 字面量
	IPs        []netip.Addr // DNS 解析结果；未解析或以 IP 字面量访问时为 nil/单个地址
}

// Check 执行完整校验：标准化 -> 黑/白名单过滤 -> DNS 解析 -> 逐 IP 校验。
// 解析失败或解析结果为空时直接拒绝（fail closed）。
func (f *Filter) Check(ctx context.Context, raw string) (*Result, error) {
	u, info, err := f.normalize(raw)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Original:   raw,
		Normalized: u.String(),
		URL:        u,
		Host:       info.host,
		Port:       portOf(u),
		IsIP:       info.isIP,
	}

	if err := f.checkHostName(info.host); err != nil {
		return nil, err
	}
	if err := f.checkPort(res.Port); err != nil {
		return nil, err
	}

	// 解析目标 IP；IP 字面量无需解析
	var ips []netip.Addr
	if info.isIP {
		ips = []netip.Addr{normalizeAddr(info.addr)}
	} else if !f.cfg.DisableResolve {
		ips, err = f.cfg.LookupIP(ctx, info.host)
		if err != nil {
			return nil, block(ReasonResolveFailed, "cannot resolve %q: %v", info.host, err)
		}
		if len(ips) == 0 {
			return nil, block(ReasonResolveFailed, "%q resolved to no address", info.host)
		}
		for i := range ips {
			ips[i] = normalizeAddr(ips[i])
		}
	}
	res.IPs = ips

	// 白名单模式：域名白名单与地址段白名单满足其一即可
	_, allowedByHost := f.allowedHosts.match(info.host)
	allowedByCIDR := len(ips) > 0 && allInPrefixes(f.cfg.AllowedCIDRs, ips)

	if f.cfg.Mode == ModeWhitelist {
		if len(f.cfg.AllowedHosts) == 0 && len(f.cfg.AllowedCIDRs) == 0 {
			return nil, block(ReasonHostNotAllowed, "whitelist is empty, every target is denied")
		}
		if !allowedByHost && !allowedByCIDR {
			// 走到这里 allowedByHost 必为 false。解析被关闭或没有解析结果时，
			// 唯一能给出的结论就是域名不在白名单里，避免报出「[] 不在地址段白名单内」。
			if len(ips) == 0 || len(f.cfg.AllowedHosts) > 0 {
				return nil, block(ReasonHostNotAllowed, "%q is not in allowed hosts", info.host)
			}
			return nil, block(ReasonNotAllowedIP, "%v is not in allowed cidrs", ips)
		}
	}

	// 逐 IP 校验。只有显式出现在 AllowedCIDRs 中的地址才豁免内建保留地址段检查，
	// 这样即使白名单域名被解析到内网 / metadata 地址也会被拦下。
	for _, ip := range ips {
		explicitlyAllowed := matchesPrefix(f.cfg.AllowedCIDRs, ip)
		if err := f.checkIP(ip, explicitlyAllowed); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// checkHostName 校验主机名黑名单。
func (f *Filter) checkHostName(host string) error {
	if p, ok := f.deniedHosts.match(host); ok {
		return block(ReasonDeniedHost, "%q matches denied pattern %q", host, p)
	}
	return nil
}

// checkPort 校验端口黑名单 / 白名单。
func (f *Filter) checkPort(port int) error {
	if port == 0 {
		return nil
	}
	if containsInt(f.cfg.DeniedPorts, port) {
		return block(ReasonDeniedPort, "port %d is denied", port)
	}
	if f.cfg.Mode == ModeWhitelist && len(f.cfg.AllowedPorts) > 0 &&
		!containsInt(f.cfg.AllowedPorts, port) {
		return block(ReasonPortNotAllowed, "port %d is not allowed", port)
	}
	return nil
}

// checkIP 对单个地址做黑名单校验，并递归检查 IPv6 中内嵌的 IPv4。
// trusted 表示该地址已被 AllowedCIDRs 显式放行，可跳过内建保留地址段检查。
func (f *Filter) checkIP(a netip.Addr, trusted bool) error {
	a = normalizeAddr(a)
	if !trusted {
		if p, ok := matchPrefix(f.builtin, a); ok {
			return block(ReasonReservedIP, "%s is in reserved range %s", a, p)
		}
	}
	if p, ok := matchPrefix(f.cfg.DeniedCIDRs, a); ok {
		return block(ReasonDeniedIP, "%s is in denied range %s", a, p)
	}
	if v4, ok := embeddedIPv4(a); ok {
		return f.checkIP(v4, trusted)
	}
	return nil
}

// allInPrefixes 判断所有地址是否都落在给定地址段内（列表为空时返回 false）。
func allInPrefixes(list []netip.Prefix, addrs []netip.Addr) bool {
	if len(list) == 0 || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !matchesPrefix(list, a) {
			return false
		}
	}
	return true
}

func matchesPrefix(list []netip.Prefix, a netip.Addr) bool {
	_, ok := matchPrefix(list, a)
	return ok
}

// normalizePrefixes 校验并规范化地址段（Masked 保证 Contains 语义正确）。
// IPv4-mapped IPv6 形式的网段（如 ::ffff:10.0.0.0/104）会被还原成 IPv4 网段，
// 否则它永远匹配不到已经 Unmap 过的地址。
func normalizePrefixes(in []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			return nil, fmt.Errorf("invalid prefix %q", p)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("invalid prefix %q", p)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func defaultLookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
