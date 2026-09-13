# ssrfguard

`ssrfguard` 是一个 Go 语言实现的 SSRF（服务端请求伪造）防御组件，包含两层能力：

- 库 `ssrfguard/ssrf`：地址标准化 + 黑白名单过滤 + 建连兜底校验；
- 命令行工具 `cmd/ssrfcheck`：用配置文件对一批地址做批量校验，方便调试策略、排查绕过。

校验分三层，任一环节失败都直接拒绝（fail closed）：

1. **标准化 `Normalize`**：把十进制/八进制/十六进制 IP、简写 IP、IPv4-mapped IPv6、
   全角字符、末尾点号、控制字符等畸形写法统一成规范形式；
2. **请求级校验 `Check`**：按黑名单或白名单校验 scheme / host / port，并解析 DNS、逐个校验全部 IP；
3. **运行时兜底 `Control` / `DialContext`**：在真正建连时用已固定的 IP 再校验一次，
   防止「校验时解析到公网 IP、建连时解析到内网 IP」的 DNS Rebinding。

第 3 层发生在建连阶段，只能看到 IP，因此**覆盖不到域名维度**。要把三层都接全，
直接用 `(*Filter).NewClient()`：它对每个请求（含首个）跑第 2 层，其余交给底层 Transport。

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
# 没给地址时也会读标准输入；若 stdin 就是交互式终端（没管道也没重定向），
# 直接打印用法并退出码 2，而不是静静地等你输入

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

推荐直接用 `NewClient`，三层校验一次接全：

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

// 每个请求（含首个）都会走一遍 Check：域名白名单在此生效；
// 建连时由 DialContext 固定已解析的 IP，重定向逐跳校验（最多跟随 2 跳）。
client := f.NewClient()
resp, err := client.Get(userInput)
```

需要自定义 `*http.Client` 时，用 `NewRoundTripper` / `WrapTransport` 保留这层校验：

```go
client := &http.Client{
    Transport:     f.NewRoundTripper(),               // 等价于 WrapTransport(nil)
    CheckRedirect: f.CheckRedirect,
    Timeout:       5 * time.Second,
}
```

只做校验、自己发起请求时，仍然可以单独用 `Check`：

```go
if _, err := f.Check(ctx, userInput); err != nil {
    // 拒绝请求
}
```

也可以直接从配置文件构建：

```go
f, err := ssrf.LoadFilter("ssrf.yaml")
```

主要 API：

| 成员 | 说明 |
| --- | --- |
| `New(cfg)` / `MustNew(cfg)` | 构建过滤器，配置非法（含名单写法非法）时返回错误，绝不静默放行 |
| `(*Filter).Config()` | 返回生效配置的副本（含内建黑名单与规范化后的名单），适合打日志审计 |
| `(*Filter).Normalize(raw)` | 只做标准化，返回 `*url.URL` |
| `(*Filter).Check(ctx, raw)` | 完整校验，返回 `*Result`（标准化 URL、host、port、IPs） |
| `(*Filter).NewClient()` | **推荐入口**：请求级校验 + IP 固定建连 + 逐跳重定向校验 |
| `(*Filter).NewRoundTripper()` | 请求级校验 + IP 固定建连的 `http.RoundTripper` |
| `(*Filter).WrapTransport(base)` | 给任意 `RoundTripper` 套上请求级校验（`base` 为 nil 时用 `NewTransport`） |
| `(*Filter).NewTransport()` | 仅建连兜底：`DialContext` 的 `http.Transport`，不设置 Proxy 以免绕过校验 |
| `(*Filter).DialContext` | 解析域名 → 校验全部 IP → 固定第一个 IP 建连 |
| `(*Filter).Control` | 可直接赋给 `net.Dialer.Control`，在 TCP 建连时做最后一道 IP 校验 |
| `(*Filter).CheckRedirect` | 可直接赋给 `http.Client.CheckRedirect` |
| `LoadConfig` / `ParseConfig` / `ExampleConfig` / `LoadFilter` | 配置文件的加载、解析与模板生成 |

> **只用 `NewTransport()` 时，`allowed_hosts` 不会生效。** 建连路径拿不到域名，
> 因而只保留内建黑名单与 `denied_cidrs` 等 IP 维度规则。要么每个请求前先 `Check`，
> 要么改用 `NewClient` / `NewRoundTripper`。

## 配置

`examples/ssrf.yaml` 与 `examples/ssrf.json` 是内容等价的完整示例（有测试保证二者与
`ExampleConfig` 输出一致）。所有字段均可省略，缺省即取安全默认值；解析是**严格模式**，
出现未知字段（通常是拼写错误）会直接报错，避免配置静默失效。

`allowed_hosts` / `denied_hosts` 的条目在 `New` 时会先按与输入侧**完全相同**的规则规范化
（小写、折叠全角、剥掉末尾点号、宽松 IP 写法归一），再预编译进索引：

- `"evil.internal."`（末尾点号，zone file / `dig` 输出里很常见）与 `"evil.internal"` 等价，
  不会变成一条永不命中的规则；
- `"ｅｘａｍｐｌｅ.com"`（全角）与 `"example.com"` 等价；
- 无法匹配的写法——`"**.example.com"`、空串、CIDR、`example.com:8080`、通配与 IP 字面量混用——
  会让 `New` 直接报错并指出是哪个字段的第几条，不会留到运行时静默失效。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | `blacklist` | `blacklist` 只拒绝命中的目标；`whitelist` 只放行显式允许的目标（推荐） |
| `allowed_schemes` | `[http, https]` | 允许的 URL scheme |
| `default_scheme` | `http` | 输入未带 scheme 时补全的 scheme |
| `allowed_hosts` | 空 | 主机白名单，支持 `example.com`（精确）/ `.example.com`（本域及子域）/ `*.example.com`（仅子域） |
| `allowed_cidrs` | 空 | 地址段白名单，可省略掩码；详见下方「信任标记」 |
| `allowed_ports` | 空 | 端口白名单，留空表示不限制，仅 `whitelist` 模式生效 |
| `denied_hosts` | 空 | 主机黑名单，写法同 `allowed_hosts`（同样会被规范化与校验） |
| `denied_cidrs` | 空 | 追加拒绝的地址段，叠加在内建保留地址段之上 |
| `denied_ports` | 空 | 追加拒绝的端口，叠加在内建高危端口之上 |
| `allow_non_ascii_host` | `false` | 是否允许非 ASCII 主机名（IDN），默认拒绝以规避同形异义绕过 |
| `allow_user_info` | `false` | 是否允许 URL 中出现 `user:pass@` |
| `disable_resolve` | `false` | 关闭 `Check` 的 DNS 解析；黑名单模式的 IP 层防护会随之失效，请谨慎使用（建连路径仍会解析域名） |
| `dial_timeout` | `10s` | `DialContext` 使用的建连超时，必须为正数 |

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

但在 `blacklist` 模式下没有「必须命中白名单」这道闸门，此时 `allowed_cidrs` 里的每个网段
**只起豁免作用**：写 `127.0.0.1/32` 的效果是放行回环地址，而不是「多允许一点」。
这个组合很容易在评审时被误读成无害的加白，所以 `ssrfcheck` 遇到它会向 stderr 打印提醒。

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
make fuzz     # 跑解析器/配置的 fuzz 目标，默认 FUZZTIME=30s
make clean    # 清理 bin/ 与 coverage.*
```

测试覆盖了标准化、宽松 IPv4 解析、黑白名单判定、内嵌 IPv4、DNS Rebinding、
重定向边界、名单写法规范化、请求级校验（`NewClient` / `NewRoundTripper`）、
CLI 的参数覆盖语义与 `-print-config` / `-dump-config` 输出，以及配置文件往返等场景；
基准主要衡量主机名单匹配与完整校验路径的开销。

两个 fuzz 目标守着最容易出错的入口，`make fuzz` 或 CI 都会跑：

- `FuzzCheck`：随机输入不得 panic；且一旦某个输入被接受，它产出的标准化结果必须
  也能被接受、且再次标准化保持不变（幂等），否则「先 Check 再使用 `Normalized`」的
  调用方会拿到与校验结果不一致的地址；
- `FuzzParseConfig`：随机字节不得 panic，解析成功的配置必须能通过 `Config.String()` 稳定往返。

## 目录结构

```
cmd/ssrfcheck/     命令行工具
ssrf/              核心库
  normalize.go     标准化与畸形地址解析
  filter.go        Config / Filter / Check / 错误定义
  hostmatch.go     主机名单的规范化、校验与索引（按域名标签逐级匹配）
  iprange.go       内建保留地址段、内嵌 IPv4 提取
  dialer.go        Control / DialContext / NewTransport / WrapTransport / NewClient
  config.go        YAML/JSON 配置的加载、解析与模板
examples/          等价的 YAML / JSON 示例配置
.github/workflows/ CI（gofmt / vet / test / -race / fuzz）
Makefile           常用命令入口
LICENSE            MIT
```

## 注意事项

- 主机名单在 `New` 时被规范化并预编译成索引，单次匹配只与域名的标签数有关（通常 2~5 次 map 查找），
  与名单规模无关，可以放心配置上万条。
- `Filter` 构造后只读，可并发使用。
- 单用 `NewTransport()` 时 `allowed_hosts` **不会生效**（建连路径拿不到域名），
  请改用 `NewClient` / `NewRoundTripper`，或确保每个请求前都调用了 `Check`。
- `Control` 只能看到 IP、看不到域名，因此白名单模式下若只配置了 `allowed_hosts`，
  它无法感知域名；它适合当作 IP 维度的最后一道兜底，而不是唯一防线。
- `NewClient` / `NewRoundTripper` 会对每个请求多做一次 DNS 解析（`Check` 需要解析结果
  才能判断 IP 维度），换来的是域名维度的确定性校验。
- 直接拨 IP 会丢失域名信息，HTTPS 场景请使用 `NewClient` / `NewTransport`
  （它们经由 `DialContext`，会自动处理 `ServerName`）。
- `DialContext` 固定使用解析出的第一个 IP 建连：这是消除 Rebinding 窗口的代价，
  多 A 记录的主机不会自动回退到后续 IP，可用性上需要心里有数。
- `disable_resolve` 仅建议在纯域名白名单场景下使用；关闭后黑名单模式的 IP 层防护会失效，
  且它只影响 `Check`，建连路径仍会解析域名。
- 本组件只负责「把目标地址限制在允许范围内」，不替代鉴权、限流、出网代理等其他防护手段。

## 许可证

MIT，见 [LICENSE](LICENSE)。
