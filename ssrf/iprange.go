package ssrf

import "net/netip"

// blockedPrefixes 是内建的黑名单地址段：这些地址永远不应该成为外部可控的访问目标。
// 参考 IANA Special-Purpose Address Registry 与各云厂商 metadata 服务地址。
// 构造后只读：Filter 直接共享这个切片，不要在运行时修改它。
var blockedPrefixes = []netip.Prefix{
	// ---- IPv4 ----
	netip.MustParsePrefix("0.0.0.0/8"),       // 本网络
	netip.MustParsePrefix("10.0.0.0/8"),      // 私有
	netip.MustParsePrefix("100.64.0.0/10"),   // 运营商级 NAT（云内网常用）
	netip.MustParsePrefix("127.0.0.0/8"),     // 回环
	netip.MustParsePrefix("169.254.0.0/16"),  // 链路本地（含 169.254.169.254 云 metadata）
	netip.MustParsePrefix("172.16.0.0/12"),   // 私有
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF 协议分配
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 中继任播
	netip.MustParsePrefix("192.168.0.0/16"),  // 私有
	netip.MustParsePrefix("198.18.0.0/15"),   // 基准测试
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // 组播
	netip.MustParsePrefix("240.0.0.0/4"),     // 保留（含广播 255.255.255.255）

	// ---- IPv6 ----
	netip.MustParsePrefix("::/128"),         // 未指定
	netip.MustParsePrefix("::1/128"),        // 回环
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64（内嵌 IPv4，见 embeddedIPv4）
	netip.MustParsePrefix("64:ff9b:1::/48"), // 本地 NAT64
	netip.MustParsePrefix("100::/64"),       // 丢弃前缀
	netip.MustParsePrefix("2001::/32"),      // Teredo（内嵌 IPv4）
	netip.MustParsePrefix("2001:2::/48"),    // 基准测试
	netip.MustParsePrefix("2001:db8::/32"),  // 文档
	netip.MustParsePrefix("2002::/16"),      // 6to4（内嵌 IPv4）
	netip.MustParsePrefix("fc00::/7"),       // 唯一本地地址 ULA
	netip.MustParsePrefix("fe80::/10"),      // 链路本地
	netip.MustParsePrefix("ff00::/8"),       // 组播
}

// defaultDeniedHosts 是内建的黑名单主机名（云 metadata 服务别名）。
var defaultDeniedHosts = []string{
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata",
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
	"metadata.azure.com",
}

// defaultDeniedPorts 是内建的高危端口黑名单：这些端口上通常跑着不该被外部触达的服务。
var defaultDeniedPorts = []int{
	22, 23, 25, 111, 135, 137, 138, 139, 445, 512, 513, 514,
	1433, 1521, 2049, 2375, 2379, 3306, 3389, 5432, 5900, 5984,
	6379, 7001, 9200, 9300, 11211, 27017,
}

// 下面三个前缀在 blockedPrefixes 里也有，单独命名是为了提取其中内嵌的 IPv4。
var (
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4Prefix = netip.MustParsePrefix("2002::/16")
	teredoPrefix = netip.MustParsePrefix("2001::/32")
)

// embeddedIPv4 提取 IPv6 地址中内嵌的 IPv4 地址（NAT64 / 6to4 / Teredo）。
// 攻击者可以用 "64:ff9b::7f00:1" 绕过只检查 IPv4 黑名单的实现。
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() || a.Is4In6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64Prefix.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixTo4Prefix.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case teredoPrefix.Contains(a):
		// Teredo 中客户端 IPv4 是取反存储的
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	}
	return netip.Addr{}, false
}

// normalizeAddr 统一地址表示：IPv4-mapped IPv6 一律还原成 IPv4，去掉 zone。
func normalizeAddr(a netip.Addr) netip.Addr {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a
}

// matchPrefix 返回第一个包含 addr 的前缀。
func matchPrefix(list []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	for _, p := range list {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
