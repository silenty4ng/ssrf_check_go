package ssrf

import (
	"fmt"
	"net/netip"
	"strings"
)

// normalizeHostPatterns 规范化并校验主机名名单条目，返回可交给 newHostMatcher 的形式。
//
// 为什么必须做：匹配用的 host 已经过 normalizeHost 处理（小写、折叠全角、剥离末尾点号），
// 如果名单条目不做同样的处理，两者就永远对不上，而且是**静默**对不上：
// 黑名单里写 "evil.internal." 会变成一条永不命中的规则，防护无声失效；
// 白名单里写 ".example.com." 同样永不命中，请求被无声拒绝。
// 因此这里用与 normalizeHost 完全相同的规则处理名单，并让无法匹配的写法直接报错，
// 而不是留到运行时才发现「配置明明写了却不生效」。
func normalizeHostPatterns(patterns []string, allowNonASCII bool) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(patterns))
	for i, raw := range patterns {
		p, err := normalizeHostPattern(raw, allowNonASCII)
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// normalizeHostPattern 规范化单条名单写法，保留 ".example.com" / "*.example.com" 前缀。
func normalizeHostPattern(raw string, allowNonASCII bool) (string, error) {
	p := foldConfusables(strings.ToLower(strings.TrimSpace(raw)))

	prefix := ""
	switch {
	case strings.HasPrefix(p, "*."):
		prefix, p = "*.", p[2:]
	case strings.HasPrefix(p, "."):
		prefix, p = ".", p[1:]
	}
	for strings.HasSuffix(p, ".") {
		p = p[:len(p)-1]
	}
	if p == "" {
		return "", fmt.Errorf("%w: empty pattern %q", ErrInvalidHost, raw)
	}
	if strings.Contains(p, "/") {
		return "", fmt.Errorf("%w: %q looks like a CIDR, use AllowedCIDRs/DeniedCIDRs instead", ErrInvalidHost, raw)
	}

	// 与输入侧保持一致：IP 字面量（含十进制 / 八进制 / 十六进制等宽松写法）统一成规范形式，
	// 否则 "0177.0.0.1" 这种写法在名单里永远匹配不到已归一为 127.0.0.1 的 host。
	if addr, err := netip.ParseAddr(p); err == nil {
		if prefix != "" {
			return "", fmt.Errorf("%w: %q cannot combine a wildcard prefix with an IP literal", ErrInvalidHost, raw)
		}
		return normalizeAddr(addr).String(), nil
	}
	if addr, ok := parseLooseIPv4(p); ok {
		if prefix != "" {
			return "", fmt.Errorf("%w: %q cannot combine a wildcard prefix with an IP literal", ErrInvalidHost, raw)
		}
		return addr.String(), nil
	}

	if !isASCII(p) && !allowNonASCII {
		// 输入侧的这类主机名同样会被拒（AllowNonASCIIHost 默认关闭），
		// 留在名单里是一条永不命中的规则，不如直接报错。
		return "", fmt.Errorf("%w: %q (set allow_non_ascii_host to enable IDN hosts)", ErrNonASCIIHost, raw)
	}
	if err := validateDomain(p, isASCII(p)); err != nil {
		return "", err
	}
	return prefix + p, nil
}

// hostPatternKind 是主机名名单里一条写法支持的形式。
type hostPatternKind uint8

const (
	kindExact hostPatternKind = iota // "example.com"        只匹配 example.com
	kindApex                         // ".example.com"       匹配 example.com 及其所有层级的子域
	kindSub                          // "*.example.com"      只匹配 example.com 的子域
)

// hostRule 汇总同一个域名上可能配置的三种写法，空串表示该写法未配置。
// 用三个字段而不是一条规则，是为了在报错时能给出「确实匹配到了该主机名」的那条原始写法。
type hostRule struct {
	exact string
	apex  string
	sub   string
}

// hostMatcher 是主机名黑 / 白名单的索引。
//
// 为什么不线性扫描：真实场景里这两份名单常常有几万条（威胁情报、内网域名清单、
// 分租户的域名白名单），而每个请求都要查一次；线性扫描意味着每次 O(名单长度) 次
// 字符串比较，名单一大就把请求延迟拖成「与名单规模成正比」。
//
// 这里按「域名标签」自上而下逐级匹配（com -> example.com -> a.example.com，
// 即从顶级标签开始每轮向前扩一个标签），每个后缀做一次 map 查找，
// 复杂度只与主机名的标签数有关（通常 2~5 次），与名单规模无关。
// 它和后缀字典树等价，但没有指针跳转、内存更省，代码也短得多。
type hostMatcher struct {
	rules map[string]hostRule
}

// newHostMatcher 预编译名单：一次性完成去空白、小写化和前缀解析，
// 使每个请求的匹配路径上不再有 ToLower / TrimSpace / 字符串拼接。
//
// 调用方应先经 normalizeHostPatterns 规范化：这里只做小写化，
// 不会折叠全角或剥离末尾点号（那些属于「配置校验」的职责，见 normalizeHostPatterns）。
func newHostMatcher(patterns []string) hostMatcher {
	m := hostMatcher{}
	if len(patterns) == 0 {
		return m
	}
	m.rules = make(map[string]hostRule, len(patterns))
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case strings.HasPrefix(p, "*."):
			m.add(p[2:], kindSub, raw)
		case strings.HasPrefix(p, "."):
			m.add(p[1:], kindApex, raw)
		default:
			m.add(p, kindExact, raw)
		}
	}
	return m
}

// add 登记一条规则。同一域名上的同一种写法只保留首次出现的原始写法，
// 与线性扫描「第一条命中即返回」的行为保持一致。
func (m hostMatcher) add(key string, kind hostPatternKind, raw string) {
	// 形如 "" / "." / "*." 的规则在任何主机名上都不可能命中（host 已被标准化为
	// 非空且无结尾点号的形式），直接丢弃，与原先的线性实现保持一致。
	if key == "" {
		return
	}
	r := m.rules[key]
	switch kind {
	case kindExact:
		if r.exact == "" {
			r.exact = raw
		}
	case kindApex:
		if r.apex == "" {
			r.apex = raw
		}
	case kindSub:
		if r.sub == "" {
			r.sub = raw
		}
	}
	m.rules[key] = r
}

// match 返回命中的原始写法（未做小写化，便于错误信息里回显用户配置的原样）。
//
// 判定结果与原先的顺序扫描完全一致：host 必须已经被 normalizeHost 规范化过
// （小写、无结尾点号、标签非空）。
//
// 遍历方向自上而下：从顶级标签开始逐级向前扩（com -> example.com -> a.example.com），
// 先命中的那条就返回。因此当多条规则同时覆盖同一个主机名时，返回的是离 TLD 最近、
// 覆盖范围最大的那条：同时配置 ".example.com" 和 ".a.example.com" 时，
// a.example.com 的命中写法是 ".example.com" 而不是 ".a.example.com"。
func (m hostMatcher) match(host string) (string, bool) {
	if len(m.rules) == 0 || host == "" {
		return "", false
	}
	// end 是「本层后缀」前面那个点的位置：每轮用 host[:end] 里最后一个点
	// 把后缀往前扩一个标签，host[from:] 始终是主机名结尾的连续若干标签。
	for end := len(host); ; {
		i := strings.LastIndexByte(host[:end], '.')
		from := i + 1 // 已无点号时 i == -1、from == 0，即完整主机名
		full := from == 0
		if r, ok := m.rules[host[from:]]; ok {
			switch {
			// "example.com" 只认完整主机名
			case full && r.exact != "":
				return r.exact, true
			// ".example.com" 认 apex 与任意层级子域
			case r.apex != "":
				return r.apex, true
			// "*.example.com" 只认子域
			case !full && r.sub != "":
				return r.sub, true
			}
		}
		if i < 0 {
			return "", false
		}
		end = i
	}
}
