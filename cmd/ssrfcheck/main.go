// Command ssrfcheck 是一个演示 CLI：对输入的地址做 SSRF 校验并打印结论。
//
// 用法示例：
//
//	# 用配置文件（推荐）
//	ssrfcheck -config examples/ssrf.yaml http://a.example.com/
//	ssrfcheck -print-config -config examples/ssrf.yaml
//
//	# 命令行参数（会覆盖配置文件里的同名项）
//	ssrfcheck -mode whitelist -allow-hosts .example.com -allow-ports 80,443 http://a.example.com/
//
//	# 生成配置文件模板
//	ssrfcheck -dump-config yaml > ssrf.yaml
//
//	echo "http://2130706433/" | ssrfcheck
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"ssrfguard/ssrf"
)

type options struct {
	configPath  string
	mode        string
	allowHosts  string
	allowCIDRs  string
	allowPorts  string
	denyHosts   string
	denyCIDRs   string
	denyPorts   string
	dialTimeout time.Duration
}

func main() {
	var opts options
	var dumpConfig string
	var outputPath string
	var printConfig bool
	var timeout time.Duration

	flag.StringVar(&opts.configPath, "config", "", "配置文件路径（.yaml/.yml/.json）")
	flag.StringVar(&opts.mode, "mode", "blacklist", "过滤模式: blacklist | whitelist")
	flag.StringVar(&opts.allowHosts, "allow-hosts", "", "主机白名单，逗号分隔，如 .example.com,api.github.com")
	flag.StringVar(&opts.allowCIDRs, "allow-cidrs", "", "地址段白名单，逗号分隔，如 10.0.0.0/8")
	flag.StringVar(&opts.allowPorts, "allow-ports", "", "端口白名单，逗号分隔，如 80,443")
	flag.StringVar(&opts.denyHosts, "deny-hosts", "", "主机黑名单，逗号分隔")
	flag.StringVar(&opts.denyCIDRs, "deny-cidrs", "", "地址段黑名单，逗号分隔")
	flag.StringVar(&opts.denyPorts, "deny-ports", "", "端口黑名单，逗号分隔")
	flag.DurationVar(&opts.dialTimeout, "dial-timeout", 0, "建连超时，默认取配置文件或 10s")
	flag.DurationVar(&timeout, "timeout", 3*time.Second, "校验（DNS 解析）超时")
	flag.StringVar(&dumpConfig, "dump-config", "", "打印示例配置后退出: yaml | json")
	flag.StringVar(&outputPath, "o", "", "-dump-config 的输出文件，默认写到标准输出")
	flag.BoolVar(&printConfig, "print-config", false, "打印最终生效的配置（含内建黑名单）后退出")
	flag.Parse()

	if dumpConfig != "" {
		format := ssrf.FormatYAML
		if strings.EqualFold(dumpConfig, "json") {
			format = ssrf.FormatJSON
		}
		out := ssrf.ExampleConfig(format)
		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(out), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "已写入 %s\n", outputPath)
			return
		}
		fmt.Print(out)
		return
	}

	set := map[string]bool{}
	flag.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	cfg, source, err := buildConfig(opts, set)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	f, err := ssrf.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(1)
	}

	if printConfig {
		fmt.Printf("# 配置来源: %s\n", source)
		fmt.Print(f.Config().String())
		return
	}

	inputs := flag.Args()
	if len(inputs) == 0 {
		inputs = readLines(os.Stdin)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "请通过参数或标准输入提供待校验地址")
		flag.Usage()
		os.Exit(2)
	}

	fmt.Printf("配置来源: %s (mode=%s allowedHosts=%v allowedCIDRs=%v allowedPorts=%v)\n\n",
		source, cfg.Mode, cfg.AllowedHosts, cfg.AllowedCIDRs, cfg.AllowedPorts)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		res, err := f.Check(ctx, in)
		if err != nil {
			fmt.Printf("REJECT  %-46s %v\n", in, err)
			continue
		}
		fmt.Printf("ALLOW   %-46s -> %s (host=%s port=%d ips=%v)\n",
			in, res.Normalized, res.Host, res.Port, res.IPs)
	}
}

// buildConfig 以配置文件为底，用「命令行里显式出现过的」参数覆盖它。
// set 来自 flag.Visit，只包含用户真正传了的 flag，避免默认值把配置文件覆盖掉。
func buildConfig(opts options, set map[string]bool) (ssrf.Config, string, error) {
	cfg := ssrf.Config{}
	source := "命令行参数/默认值"

	if opts.configPath != "" {
		loaded, err := ssrf.LoadConfig(opts.configPath)
		if err != nil {
			return cfg, "", err
		}
		cfg = loaded
		source = opts.configPath
	}

	if set["mode"] {
		switch strings.ToLower(strings.TrimSpace(opts.mode)) {
		case "whitelist":
			cfg.Mode = ssrf.ModeWhitelist
		case "blacklist":
			cfg.Mode = ssrf.ModeBlacklist
		default:
			return cfg, "", fmt.Errorf("无效的 -mode %q，可选 blacklist 或 whitelist", opts.mode)
		}
	}
	if set["allow-hosts"] {
		cfg.AllowedHosts = splitList(opts.allowHosts)
	}
	if set["deny-hosts"] {
		cfg.DeniedHosts = splitList(opts.denyHosts)
	}
	if set["allow-cidrs"] {
		ps, err := parsePrefixes(opts.allowCIDRs, "-allow-cidrs")
		if err != nil {
			return cfg, "", err
		}
		cfg.AllowedCIDRs = ps
	}
	if set["deny-cidrs"] {
		ps, err := parsePrefixes(opts.denyCIDRs, "-deny-cidrs")
		if err != nil {
			return cfg, "", err
		}
		cfg.DeniedCIDRs = ps
	}
	if set["allow-ports"] {
		ps, err := parseInts(opts.allowPorts, "-allow-ports")
		if err != nil {
			return cfg, "", err
		}
		cfg.AllowedPorts = ps
	}
	if set["deny-ports"] {
		ps, err := parseInts(opts.denyPorts, "-deny-ports")
		if err != nil {
			return cfg, "", err
		}
		cfg.DeniedPorts = ps
	}
	if set["dial-timeout"] {
		cfg.DialTimeout = opts.dialTimeout
	}
	return cfg, source, nil
}

func readLines(r *os.File) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInts(s, flagName string) ([]int, error) {
	var out []int
	for _, p := range splitList(s) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%s: %q 不是合法端口", flagName, p)
		}
		out = append(out, n)
	}
	return out, nil
}

func parsePrefixes(s, flagName string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range splitList(s) {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			if a, aerr := netip.ParseAddr(p); aerr == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			return nil, fmt.Errorf("%s: %q 不是合法地址段（如 10.0.0.0/8）", flagName, p)
		}
		out = append(out, prefix)
	}
	return out, nil
}
