package ssrf

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// maxRedirects 是 CheckRedirect 允许的最大重定向跳数。
const maxRedirects = 3

// Control 可直接赋给 net.Dialer.Control。
// 它在 TCP 建连时（DNS 已解析完成、拿到真实目标 IP）再做一次校验，
// 用于拦住「Check 时解析到公网 IP、建连时解析到内网 IP」的 DNS Rebinding。
//
// 注意：Control 只能看到 IP，看不到域名，因此白名单模式下如果只配置了
// AllowedHosts，这里无法感知域名。要彻底消除该窗口，请使用 DialContext / NewTransport。
func (f *Filter) Control(_, address string, _ syscall.RawConn) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return block(ReasonNotAllowedIP, "unexpected dial address %q: %v", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return block(ReasonNotAllowedIP, "unexpected dial host %q", host)
	}
	addr = normalizeAddr(addr)

	if err := f.checkDialIP(addr); err != nil {
		return err
	}
	if p, err := strconv.Atoi(portStr); err == nil {
		if err := f.checkPort(p); err != nil {
			return err
		}
	}
	return nil
}

// checkDialIP 是建连兜底路径上的单地址校验，Control 与 DialContext 共用。
// 这条路径只能看到 IP、看不到域名，因此白名单模式下要求地址必须落在
// AllowedCIDRs 内；未配置 AllowedCIDRs 时只剩内建黑名单可用（见 Control 的说明）。
func (f *Filter) checkDialIP(a netip.Addr) error {
	allowed := matchesPrefix(f.cfg.AllowedCIDRs, a)
	if err := f.checkIP(a, allowed); err != nil {
		return err
	}
	if f.cfg.Mode == ModeWhitelist && len(f.cfg.AllowedCIDRs) > 0 && !allowed {
		return block(ReasonNotAllowedIP, "%s is not in allowed cidrs", a)
	}
	return nil
}

// NewDialer 返回带 SSRF 兜底校验的 Dialer。
func (f *Filter) NewDialer(timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   f.Control,
	}
}

// DialContext 在建立连接前解析域名、校验全部 IP，然后固定使用第一个 IP 建连。
// 因为不再做二次 DNS 解析，可以彻底消除 Rebinding 窗口。
//
// 直接拨 IP 会丢失域名信息，HTTPS 场景请改用 NewTransport（自动处理 ServerName）。
func (f *Filter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, block(ReasonNotAllowedIP, "unexpected address %q: %v", address, err)
	}

	var ips []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{normalizeAddr(a)}
	} else {
		ips, err = f.cfg.LookupIP(ctx, host)
		if err != nil {
			return nil, block(ReasonResolveFailed, "cannot resolve %q: %v", host, err)
		}
		if len(ips) == 0 {
			return nil, block(ReasonResolveFailed, "%q resolved to no address", host)
		}
		for i := range ips {
			ips[i] = normalizeAddr(ips[i])
		}
	}

	for _, ip := range ips {
		if err := f.checkDialIP(ip); err != nil {
			return nil, err
		}
	}

	d := f.NewDialer(f.cfg.DialTimeout)
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// NewTransport 返回使用 DialContext（IP 固定，无二次解析）的 http.Transport。
// 不设置 Proxy，避免请求被交给代理从而绕过校验。
func (f *Filter) NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           f.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// CheckRedirect 可直接赋给 http.Client.CheckRedirect，对每一跳重定向重新校验。
// 最多允许跳 maxRedirects 次，比 http.Client 默认的 10 跳更严格。
func (f *Filter) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return block(ReasonTooManyRedirects, "too many redirects (%d)", len(via))
	}
	_, err := f.Check(req.Context(), req.URL.String())
	return err
}
