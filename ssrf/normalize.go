package ssrf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var (
	// ErrEmptyInput 输入为空或只包含空白字符。
	ErrEmptyInput = errors.New("ssrf: input is empty")
	// ErrInvalidURL URL 无法解析。
	ErrInvalidURL = errors.New("ssrf: invalid url")
	// ErrBadScheme scheme 不在允许列表中。
	ErrBadScheme = errors.New("ssrf: scheme not allowed")
	// ErrUserInfo URL 带有 userinfo（user:pass@host），是常见的绕过与欺骗手法。
	ErrUserInfo = errors.New("ssrf: userinfo is not allowed")
	// ErrInvalidHost host 不是合法的域名或 IP。
	ErrInvalidHost = errors.New("ssrf: invalid host")
	// ErrNonASCIIHost host 含有非 ASCII 字符，可能是 IDN 同形异义绕过。
	ErrNonASCIIHost = errors.New("ssrf: non-ascii host is not allowed")
)

// hostInfo 是标准化后的主机信息。
type hostInfo struct {
	host string     // 规范化后的主机名或 IP 字符串（小写、无括号、无端口）
	addr netip.Addr // 当 host 是 IP 字面量时有效
	isIP bool       // host 是否为 IP 字面量
}

// Normalize 把用户输入的地址标准化为 *url.URL。
// 标准化内容：丢弃控制字符、补全 scheme、小写化、剥离末尾点号、
// 把各种畸形 IP 写法统一成点分十进制 / 规范 IPv6、去除 IPv6 zone。
func (f *Filter) Normalize(raw string) (*url.URL, error) {
	u, _, err := f.normalize(raw)
	return u, err
}

func (f *Filter) normalize(raw string) (*url.URL, hostInfo, error) {
	var zero hostInfo

	cleaned := stripControlAndSpace(raw)
	if cleaned == "" {
		return nil, zero, ErrEmptyInput
	}

	// 没有 scheme 时补全，例如 "example.com/a"、"127.0.0.1:8080"
	if !hasScheme(cleaned) {
		cleaned = f.cfg.DefaultScheme + "://" + cleaned
	}

	u, err := url.Parse(cleaned)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if !containsString(f.cfg.AllowedSchemes, scheme) {
		return nil, zero, fmt.Errorf("%w: %q", ErrBadScheme, u.Scheme)
	}
	u.Scheme = scheme

	if u.User != nil && !f.cfg.AllowUserInfo {
		return nil, zero, ErrUserInfo
	}

	rawHost := u.Hostname() // 已剥离 [] 与端口
	if rawHost == "" {
		return nil, zero, fmt.Errorf("%w: empty host", ErrInvalidHost)
	}

	host, addr, isIP, err := f.normalizeHost(rawHost)
	if err != nil {
		return nil, zero, err
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, zero, fmt.Errorf("%w: bad port %q", ErrInvalidHost, port)
		}
		port = strconv.Itoa(n)
	}

	switch {
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	case isIP && addr.Is6():
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}
	// fragment 不参与请求，清掉避免干扰后续判断
	u.Fragment = ""
	return u, hostInfo{host: host, addr: addr, isIP: isIP}, nil
}

// normalizeHost 把主机名标准化为「小写域名」或「规范的 IP 字符串」。
func (f *Filter) normalizeHost(rawHost string) (string, netip.Addr, bool, error) {
	h := foldConfusables(strings.ToLower(strings.TrimSpace(rawHost)))
	// 末尾点号：example.com. / 127.0.0.1. 都指向同一目标，是常见绕过
	for strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	if h == "" {
		return "", netip.Addr{}, false, fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	// IPv6 zone，例如 fe80::1%eth0
	if i := strings.LastIndexByte(h, '%'); i >= 0 && strings.Contains(h, ":") {
		h = h[:i]
	}

	// 1) 标准 IP 字面量（含 IPv4-mapped IPv6，如 ::ffff:127.0.0.1）
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = normalizeAddr(addr.WithZone(""))
		return addr.String(), addr, true, nil
	}
	// 2) 非标准 IPv4 写法：十进制整数、八进制、十六进制、简写
	if addr, ok := parseLooseIPv4(h); ok {
		return addr.String(), addr, true, nil
	}

	// 3) 域名
	if !isASCII(h) {
		// IDN 是常见的同形异义绕过（如 "аpple.com" 使用西里尔字母 а），默认直接拒绝。
		// 需要支持时请在配置中开启，并自行保证已在更上层做过 punycode 归一。
		if !f.cfg.AllowNonASCIIHost {
			return "", netip.Addr{}, false, fmt.Errorf("%w: %q", ErrNonASCIIHost, h)
		}
		if err := validateDomain(h, false); err != nil {
			return "", netip.Addr{}, false, err
		}
		return h, netip.Addr{}, false, nil
	}
	if err := validateDomain(h, true); err != nil {
		return "", netip.Addr{}, false, err
	}
	return h, netip.Addr{}, false, nil
}

// stripControlAndSpace 丢弃控制字符（\t \n \r NUL 等，浏览器/部分库会忽略它们，
// 因此常被用来构造 "127.0.0.1\t" 这类绕过），并去掉首尾空白。
func stripControlAndSpace(raw string) string {
	if !containsControlOrSpace(raw) {
		return raw // 常见情况：输入本来就干净，无需重新分配
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimFunc(b.String(), unicode.IsSpace)
}

// containsControlOrSpace 判断字符串里是否出现了控制字符或空白字符。
// 只要出现就说明需要走清理逻辑，所以这里判得宽一些是安全的。
func containsControlOrSpace(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// foldConfusables 把全角字符与各种 Unicode 点号折叠成 ASCII，
// 避免 "１２７．０．０．１" 之类的同形异义绕过。
func foldConfusables(s string) string {
	if isASCII(s) {
		return s // 可折叠的字符都在非 ASCII 区，ASCII 输入必定原样保留
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 0x3002, 0xFF0E, 0xFF61, 0x2024, 0xFE52: // 。 ． ｡ ․ ﹒
			b.WriteByte('.')
			continue
		case 0x3000: // 全角空格
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E { // 全角 ASCII
			b.WriteRune(r - 0xFEE0)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// parseLooseIPv4 按 inet_aton 的宽松规则解析 IPv4：
//
//	"2130706433"     -> 127.0.0.1
//	"0x7f.0.0.1"     -> 127.0.0.1
//	"0177.0.0.1"     -> 127.0.0.1
//	"127.1"          -> 127.0.0.1
//
// 空标签（"127." / "1..2"）与超过 4 段一律判非法。每个域名都要经过这里，
// 属于热路径，因此全程零分配（段值放在栈上的定长数组里）。
func parseLooseIPv4(h string) (netip.Addr, bool) {
	var vals [4]uint32
	n := 0
	for h != "" {
		if n == len(vals) {
			return netip.Addr{}, false // 超过 4 段
		}
		part := h
		if i := strings.IndexByte(h, '.'); i >= 0 {
			if i == 0 || i == len(h)-1 {
				return netip.Addr{}, false // 以点开头 / 结尾，即存在空标签
			}
			part, h = h[:i], h[i+1:]
		} else {
			h = ""
		}
		v, ok := parseIPv4Part(part)
		if !ok {
			return netip.Addr{}, false
		}
		vals[n] = v
		n++
	}

	var n32 uint32
	switch n {
	case 1:
		n32 = vals[0] // parseIPv4Part 已保证不超过 0xFFFFFFFF
	case 2:
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		n32 = vals[0]<<24 | vals[1]
	case 3:
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		n32 = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		for _, v := range vals {
			if v > 0xFF {
				return netip.Addr{}, false
			}
		}
		n32 = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	default: // 空字符串
		return netip.Addr{}, false
	}

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n32)
	return netip.AddrFrom4(b), true
}

// parseIPv4Part 解析单个段，支持十进制、0x 十六进制、0 前缀八进制。
// 位宽固定为 32 位，所以返回值一定能放进 uint32，调用方无需再判越界。
func parseIPv4Part(p string) (uint32, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(p) > 2 && (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	v, err := strconv.ParseUint(p, base, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func validateDomain(h string, strictChars bool) error {
	if len(h) > 253 {
		return fmt.Errorf("%w: domain too long", ErrInvalidHost)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%w: %q", ErrInvalidHost, h)
		}
		if !strictChars {
			continue
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return fmt.Errorf("%w: %q", ErrInvalidHost, h)
			}
		}
	}
	// 纯数字结尾的「域名」只可能是一个没被识别出来的 IP，直接拒绝
	if isAllDigits(labels[len(labels)-1]) {
		return fmt.Errorf("%w: %q", ErrInvalidHost, h)
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasScheme 判断输入是否已带 "scheme://"。
func hasScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			return i > 0 && i+2 < len(s) && s[i+1] == '/' && s[i+2] == '/'
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '+', c == '-', c == '.':
			continue
		default:
			return false
		}
	}
	return false
}

// defaultPort 返回 scheme 的默认端口。
func defaultPort(scheme string) int {
	switch scheme {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	default:
		return 0
	}
}

// portOf 返回 URL 的端口；未显式指定时返回 scheme 默认端口。
func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return defaultPort(u.Scheme)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
