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
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"ssrfguard/ssrf"
)

type options struct {
	configPath   string
	mode         string
	allowHosts   string
	allowCIDRs   string
	allowPorts   string
	denyHosts    string
	denyCIDRs    string
	denyPorts    string
	dialTimeout  time.Duration
	checkTimeout time.Duration

	dumpConfig  string
	outputPath  string
	printConfig bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func registerFlags(fs *flag.FlagSet, opts *options) {
	fs.StringVar(&opts.configPath, "config", "", "配置文件路径（.yaml/.yml/.json）")
	fs.StringVar(&opts.mode, "mode", "blacklist", "过滤模式: blacklist | whitelist")
	fs.StringVar(&opts.allowHosts, "allow-hosts", "", "主机白名单，逗号分隔，如 .example.com,api.github.com")
	fs.StringVar(&opts.allowCIDRs, "allow-cidrs", "", "地址段白名单，逗号分隔，如 10.0.0.0/8")
	fs.StringVar(&opts.allowPorts, "allow-ports", "", "端口白名单，逗号分隔，如 80,443")
	fs.StringVar(&opts.denyHosts, "deny-hosts", "", "主机黑名单，逗号分隔")
	fs.StringVar(&opts.denyCIDRs, "deny-cidrs", "", "地址段黑名单，逗号分隔")
	fs.StringVar(&opts.denyPorts, "deny-ports", "", "端口黑名单，逗号分隔")
	fs.DurationVar(&opts.dialTimeout, "dial-timeout", 0, "建连超时，默认取配置文件或 10s")
	fs.DurationVar(&opts.checkTimeout, "timeout", 3*time.Second, "校验（DNS 解析）超时")
	fs.StringVar(&opts.dumpConfig, "dump-config", "", "打印示例配置后退出: yaml | json")
	fs.StringVar(&opts.outputPath, "o", "", "-dump-config 的输出文件，默认写到标准输出")
	fs.BoolVar(&opts.printConfig, "print-config", false, "打印最终生效的配置（含内建黑名单）后退出")
}

// run 是 CLI 的入口（main 只负责把进程级资源接进来），返回进程退出码。
// 参数与输出都被显式传入，因此可以直接在测试里覆盖各种分支。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var opts options
	fs := flag.NewFlagSet("ssrfcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "用法: ssrfcheck [选项] [地址...]（地址也可从标准输入逐行读取）")
		fs.PrintDefaults()
	}
	registerFlags(fs, &opts)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if opts.dumpConfig != "" {
		format := ssrf.FormatYAML
		if strings.EqualFold(opts.dumpConfig, "json") {
			format = ssrf.FormatJSON
		}
		out := ssrf.ExampleConfig(format)
		if opts.outputPath != "" {
			if err := os.WriteFile(opts.outputPath, []byte(out), 0o644); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			fmt.Fprintf(stderr, "已写入 %s\n", opts.outputPath)
			return 0
		}
		fmt.Fprint(stdout, out)
		return 0
	}

	// set 只包含用户真正传了的 flag，避免默认值把配置文件里的同名项覆盖掉
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	cfg, source, err := buildConfig(opts, set)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	f, err := ssrf.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "配置错误:", err)
		return 1
	}

	if opts.printConfig {
		fmt.Fprintf(stdout, "# 配置来源: %s\n", source)
		fmt.Fprint(stdout, f.Config().String())
		return 0
	}

	if cfg.Mode == ssrf.ModeBlacklist && len(cfg.AllowedCIDRs) > 0 {
		// 这个组合极易被误读成「多允许一点」，实际效果是让这些网段跳过内建保留地址段检查。
		fmt.Fprintf(stderr, "注意: blacklist 模式下 allowed_cidrs 是信任标记，以下网段会跳过内建保留地址段检查: %v\n",
			cfg.AllowedCIDRs)
	}

	inputs := fs.Args()
	if len(inputs) == 0 {
		inputs = readLines(stdin)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "请通过参数或标准输入提供待校验地址")
		fs.Usage()
		return 2
	}

	fmt.Fprintf(stdout, "配置来源: %s (mode=%s allowedHosts=%v allowedCIDRs=%v allowedPorts=%v)\n\n",
		source, cfg.Mode, cfg.AllowedHosts, cfg.AllowedCIDRs, cfg.AllowedPorts)

	ctx, cancel := context.WithTimeout(context.Background(), opts.checkTimeout)
	defer cancel()

	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		res, err := f.Check(ctx, in)
		if err != nil {
			fmt.Fprintf(stdout, "REJECT  %-46s %v\n", in, err)
			continue
		}
		fmt.Fprintf(stdout, "ALLOW   %-46s -> %s (host=%s port=%d ips=%v)\n",
			in, res.Normalized, res.Host, res.Port, res.IPs)
	}
	return 0
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

func readLines(r io.Reader) []string {
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
