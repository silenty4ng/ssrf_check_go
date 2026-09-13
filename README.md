# ssrfguard

`ssrfguard` 是一个 Go 语言实现的 SSRF（服务端请求伪造）防御组件，包含两层能力：

- 库 `ssrfguard/ssrf`：地址标准化 + 黑白名单过滤 + 建连兜底校验；
- 命令行工具 `cmd/ssrfcheck`：用配置文件对一批地址做批量校验，方便调试策略、排查绕过。

校验分三层，任一环节失败都直接拒绝（fail closed）：

1. **标准化 `Normalize`**：把十进制/八进制/十六进制 IP、简写 IP、IPv4-mapped IPv6、
   全角字符、末尾点号、控制字符等畸形写法统一成规范形式；
2. **过滤 `Check`**：按黑名单或白名单校验 scheme / host / port，并解析 DNS、逐个校验全部 IP；
3. **运行时兜底 `Control` / `DialContext`**：在真正建连时用已固定的 IP 再校验一次，
   防止「校验时解析到公网 IP、建连时解析到内网 IP」的 DNS Rebinding。

## 环境要求

- Go 1.21+
- 唯一的第三方依赖是 `gopkg.in/yaml.v3`（仅用于解析配置文件）

## 快速开始

```bash
make build                                   # 产物在 bin/ssrfcheck
make demo                                    # 用 examples/ssrf.yaml 跑一组示例
make help                                    # 查看全部 Makefile 目标
```

也可以不经过 Makefile：

```bash
go run ./cmd/ssrfcheck -config examples/ssrf.yaml http://10.0.0.5/
```

### 命令行用法

```bash
# 用配置文件校验（推荐）
ssrfcheck -config examples/ssrf.yaml http://a.example.com/ http://10.0.0.5/

# 直接传参数（会覆盖配置文件里的同名项）
ssrfcheck -mode whitelist -allow-hosts .example.com -allow-ports 80,443 http://a.example.com/

# 从标准输入读取，一行一个地址
echo "http://2130706433/" | ssrfcheck

# 生成配置模板并落盘
ssrfcheck -dump-config yaml -o ssrf.yaml
ssrfcheck -dump-config json

# 打印最终生效的配置（含内建黑名单），便于确认「到底哪份配置在起作用」
ssrfcheck -print-config -config examples/ssrf.yaml
```

输出示例（`make demo`）：

```
配置来源: examples/ssrf.yaml (mode=whitelist allowedHosts=[.example.com api.github.com] allowedCIDRs=[10.0.0.0/8] allowedPorts=[80 443])

ALLOW   http://10.0.0.5/                               -> http://10.0.0.5/ (host=10.0.0.5 port=80 ips=[10.0.0.5])
REJECT  http://2130706433/                             ssrf blocked (host_not_allowed): "127.0.0.1" is not in allowed hosts
REJECT  http://169.254.169.254/                        ssrf blocked (host_not_allowed): "169.254.169.254" is not in allowed hosts
REJECT  http://10.0.0.5:6379/                          ssrf blocked (port_denied): port 6379 is denied
```

`ALLOW` 行会回显标准化后的 URL、主机、端口与解析出的 IP；`REJECT` 行会带上拦截原因。

命令行参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-config` | 空 | 配置文件路径，支持 `.yaml` / `.yml` / `.json` |
| `-mode` | `blacklist` | 过滤模式：`blacklist` \| `whitelist` |
| `-allow-hosts` / `-deny-hosts` | 空 | 主机名单，逗号分隔 |
| `-allow-cidrs` / `-deny-cidrs` | 空 | 地址段名单，逗号分隔，可省略掩码 |
| `-allow-ports` / `-deny-ports` | 空 | 端口名单，逗号分隔 |
| `-dial-timeout` | 取配置文件 / 10s | 建连超时 |
| `-timeout` | `3s` | 校验（DNS 解析）超时 |
| `-dump-config` | 空 | 打印示例配置后退出：`yaml` \| `json` |
| `-o` | 空 | 配合 `-dump-config` 输出到文件 |
| `-print-config` | `false` | 打印最终生效配置后退出 |

只有**显式传入**的命令行参数才会覆盖配置文件，默认值不会把配置覆盖掉。

### 作为库使用

```go
f, err := ssrf.New(ssrf.Config{
    Mode:          ssrf.ModeWhitelist,
    AllowedHosts:  []string{".example.com"},
    AllowedCIDRs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
    AllowedPorts:  []int{80, 443},
})
if err != nil {
    log.Fatal(err)
}

// 1) 请求前校验
if _, err := f.Check(ctx, userInput); err != nil {
    // 拒绝请求
}

// 2) 建连兜底：使用固定 IP 的 Transport，彻底消除 Rebinding 窗口
client := &http.Client{Transport: f.NewTransport()}
// 3) 每一跳重定向都重新校验（最多 3 跳）
client.CheckRedirect = f.CheckRedirect
```

也可以直接从配置文件构建：

```go
f, err := ssrf.LoadFilter("ssrf.yaml")
```

主要 API：

| 成员 | 说明 |
| --- | --- |
| `New(cfg)` / `MustNew(cfg)` | 构建过滤器，配置非法时返回错误，绝不静默放行 |
| `(*Filter).Config()` | 返回生效配置的副本（含内建黑名单），适合打日志审计 |
| `(*Filter).Normalize(raw)` | 只做标准化，返回 `*url.URL` |
| `(*Filter).Check(ctx, raw)` | 完整校验，返回 `*Result`（标准化 URL、host、port、IPs） |
| `(*Filter).NewTransport()` | 使用 `DialContext` 的 `http.Transport`，不设置 Proxy 以免绕过校验 |
| `(*Filter).DialContext` | 解析域名 → 校验全部 IP → 固定第一个 IP 建连 |
| `(*Filter).Control` | 可直接赋给 `net.Dialer.Control`，在 TCP 建连时做最后一道 IP 校验 |
| `(*Filter).CheckRedirect` | 可直接赋给 `http.Client.CheckRedirect` |
| `LoadConfig` / `ParseConfig` / `ExampleConfig` / `LoadFilter` | 配置文件的加载、解析与模板生成 |

## 配置

`examples/ssrf.yaml` 与 `examples/ssrf.json` 是内容等价的完整示例（有测试保证二者与
`ExampleConfig` 输出一致）。所有字段均可省略，缺省即取安全默认值；解析是**严格模式**，
出现未知字段（通常是拼写错误）会直接报错，避免配置静默失效。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | `blacklist` | `blacklist` 只拒绝命中的目标；`whitelist` 只放行显式允许的目标（推荐） |
| `allowed_schemes` | `[http, https]` | 允许的 URL scheme |
| `default_scheme` | `http` | 输入未带 scheme 时补全的 scheme |
| `allowed_hosts` | 空 | 主机白名单，支持 `example.com`（精确）/ `.example.com`（本域及子域）/ `*.example.com`（仅子域） |
| `allowed_cidrs` | 空 | 地址段白名单，可省略掩码；详见下方「信任标记」 |
| `allowed_ports` | 空 | 端口白名单，留空表示不限制，仅 `whitelist` 模式生效 |
| `denied_hosts` | 空 | 主机黑名单，写法同 `allowed_hosts` |
| `denied_cidrs` | 空 | 追加拒绝的地址段，叠加在内建保留地址段之上 |
| `denied_ports` | 空 | 追加拒绝的端口，叠加在内建高危端口之上 |
| `allow_non_ascii_host` | `false` | 是否允许非 ASCII 主机名（IDN），默认拒绝以规避同形异义绕过 |
| `allow_user_info` | `false` | 是否允许 URL 中出现 `user:pass@` |
| `disable_resolve` | `false` | 关闭 DNS 解析；黑名单模式的 IP 层防护会随之失效，请谨慎使用 |
| `dial_timeout` | `10s` | `DialContext` 使用的建连超时 |

### 内建规则

下列规则始终叠加在内建黑名单之上，无法通过配置删除（内建保留地址段仅在 `allowed_cidrs`
显式信任时豁免，见下文「信任标记」）：

- 保留地址段：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、
  `169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、组播与保留段，
  以及 `::1/128`、`fc00::/7`、`fe80::/10` 等（完整列表见 `ssrf/iprange.go`）；
- 内嵌 IPv4：NAT64（`64:ff9b::/96`）、6to4（`2002::/16`）、Teredo（`2001::/32`）
  里内嵌的 IPv4 会被提取出来**递归校验**，避免用 `64:ff9b::7f00:1` 绕过只查 IPv4 的实现；
- 主机名：`localhost`、`metadata.google.internal`、`metadata.azure.com` 等云 metadata 别名；
- 端口：`22`、`3306`、`6379`、`9200`、`11211`、`27017` 等常见高危端口。

### 信任标记

`allowed_cidrs` 既是白名单，也是**信任标记**：只有显式写在这里的网段才会跳过内建保留地址段检查。
换句话说，需要访问内网服务时必须在 `allowed_cidrs` 里显式放行，而不能靠把域名加进
`allowed_hosts` 来「漂白」——即使白名单域名被解析到内网或 metadata 地址，依然会被拦下。

## 错误处理

拦截错误分两类，都意味着「这次请求必须拒绝」：

- **标准化错误**：`ErrEmptyInput`、`ErrInvalidURL`、`ErrBadScheme`、`ErrUserInfo`、
  `ErrInvalidHost`、`ErrNonASCIIHost`，用 `errors.Is` 判定；
- **策略拦截**：统一为 `*BlockedError`，满足 `errors.Is(err, ssrf.ErrBlocked)`，
  通过 `Reason` 字段区分原因（`host_denied`、`host_not_allowed`、`resolve_failed`、
  `reserved_ip`、`ip_denied`、`ip_not_allowed`、`port_denied`、`port_not_allowed`、
  `too_many_redirects`）。

```go
var blocked *ssrf.BlockedError
switch {
case errors.As(err, &blocked):
    log.Printf("被策略拦截: %s (%s)", blocked.Reason, blocked.Detail)
case errors.Is(err, ssrf.ErrNonASCIIHost):
    log.Print("输入非法：主机名含非 ASCII 字符")
}
```

## 开发

```bash
make all      # fmt + vet + test（提交前跑这个）
make test     # go test ./...
make race     # go test -race ./...
make cover    # 覆盖率报告，输出 coverage.html
make bench    # 跑 ssrf 包的全部基准，默认 BENCHTIME=100ms
make clean    # 清理 bin/ 与 coverage.*
```

测试覆盖了标准化、宽松 IPv4 解析、黑白名单判定、内嵌 IPv4、DNS Rebinding、
重定向校验与配置文件往返等场景；基准主要衡量主机名单匹配与完整校验路径的开销。

## 目录结构

```
cmd/ssrfcheck/     命令行工具
ssrf/              核心库
  normalize.go     标准化与畸形地址解析
  filter.go        Config / Filter / Check / 错误定义
  hostmatch.go     主机名单索引（按域名标签逐级匹配）
  iprange.go       内建保留地址段、内嵌 IPv4 提取
  dialer.go        Control / DialContext / NewTransport / CheckRedirect
  config.go        YAML/JSON 配置的加载、解析与模板
examples/          等价的 YAML / JSON 示例配置
Makefile           常用命令入口
```

## 注意事项

- 主机名单在 `New` 时被预编译成索引，单次匹配只与域名的标签数有关（通常 2~5 次 map 查找），
  与名单规模无关，可以放心配置上万条。
- `Filter` 构造后只读，可并发使用。
- `Control` 只能看到 IP、看不到域名，因此白名单模式下若只配置了 `allowed_hosts`，
  它无法感知域名。要彻底消除 Rebinding 窗口，请使用 `DialContext` / `NewTransport`。
- 直接拨 IP 会丢失域名信息，HTTPS 场景请使用 `NewTransport`（它会自动处理 `ServerName`）。
- `disable_resolve` 仅建议在纯域名白名单场景下使用；关闭后黑名单模式的 IP 层防护会失效。
- 本组件只负责「把目标地址限制在允许范围内」，不替代鉴权、限流、出网代理等其他防护手段。
