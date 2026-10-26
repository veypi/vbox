# vbox 下一阶段设计与实现 TODO

状态：2026-10-26。规则语言、`level + 原表序`、严格子域通配、loopback 归一、
`compileNetPlan` / `NetCaps`、Manager 快照缓存及 darwin 内建出站代理已经实现。
本文件保留这些设计契约作为验收依据，只把实机验证与发布收口列为剩余工作；现行行为以
代码和 README 为准。

## 0. 剩余目标与不变量

剩余工作：

1. 在具备真实后端的 darwin 主机完成 Seatbelt + 双代理协议 + detach 宽限期验收。
2. 在 Linux / Windows 实机复核规则核心与 FS/NET 后端；跨编译和 vet 不算行为验证。
3. 发布前复核 CHANGELOG、版本号和三仓集成结果。

不可改变的原则：

- 每次 `RunProcess` 以本次 `Policy` 快照为唯一权威；缓存不提供“当前权限”，也不接收权限更新。
- 求值只按 `level + 原表序`；不自动改成具体规则优先，不因死行或冲突行本身拒绝。
- vbox 只是原生进程沙箱库，不管理命令注册、命令准入或调用方配置。
- 合法且仍有效的规则无法落实时返回 `UnsupportedError` 并拒绝启动；不过滤、降级或改道。
- 配置语法错误与平台能力不支持保持不同类型。

本阶段仍不做：TLS 终止、HTTP 方法/路径过滤、UDP ASSOCIATE、OPA/Rego、K8s 编排、
Linux 透明出口拦截、Windows MXC/WFP 后端切换、通用 FS 静态产物缓存、通用 cache 框架、
Linux/Windows 选择性出站代理。

## 1. PR3：快照派生产物缓存（已实现）

### 1.1 范围与缓存键

只保留两类缓存：

1. deny 实例化结果（迁移现有 `denyCoverAllCached`）：TTL 30s，容量/生命周期跟随 Manager。
2. net endpoint 注册表：按 netKey 复用不可变代理 endpoint。

FS 与 Net 分别计算 key，FS 变化不得导致 Net endpoint 无谓重建。

netKey 至少覆盖：

- `NetRuleSet.Default`；
- 全部规则及原始顺序；
- 每条规则的 `HostPort / Allow / Level`；
- 后端类型与缓存格式版本；
- 地址防护语义版本；
- loopback 归一语义版本；
- 显式上游代理配置。

netKey 必须是代理实际执行的完整 net 表，不是 Seatbelt 的 loopback 投影，也不能只按
open/deny 姿态缓存。fsKey 至少覆盖 `DefaultWrite`、完整有序 FS 规则及每行
`Pattern / Effect / Level`、后端类型和缓存格式版本。`Class` 不进入执行或 key。

key 使用确定性的长度前缀编码后哈希，建议 SHA-256；命中时仍比对完整规范 key。
FS/Net 使用不同域标签，不能用有歧义的字符串拼接。

### 1.2 缓存的是产物，不是权限状态

| 产物 | 缓存内容 | 生命周期 |
|---|---|---|
| Net endpoint | 深拷贝的不可变 Net 快照、HTTP/SOCKS listener、端口、认证 token、代理服务 | command 引用 + 活跃连接 + 空闲驱逐 |
| FS deny 实例化 | deny 目标列表 | TTL + 容量驱逐 |
| Windows ACE | 现有持久状态文件和对账机制 | 不作为普通内存缓存 |
| command 私有数据 | argv、env、workdir、token、job、stdio、cleanup | 不缓存 |

统一 acquire/release、同 key 单飞构造、引用计数、容量与空闲驱逐和 `Manager.Close`。
不可变纯数据不需要 TTL；文件系统实例化结果需要新鲜度 TTL；listener/tunnel 需要显式关闭。
TTL 只用于资源回收或宿主对象新鲜度，绝不用于判断权限是否变化。

### 1.3 endpoint 语义

- 相同 netKey 的并发 acquire 只创建一个 endpoint，复用端口和 token。
- 任意有效 net 规则、level 或顺序变化都得到新 netKey 和新 endpoint。
- 旧 endpoint 继续绑定旧快照，服务仍在使用它的 command，但不接受新的 acquire。
- 缓存中的 Net 快照必须深拷贝；调用方修改原始切片不得污染缓存。
- listener 已死时 acquire 必须检测并重建，不能分发死端口。
- command 退出时 release；detach 子进程可能仍存活，最后一个命令退出后保留可配置宽限期，默认建议 30s。
- 容量建议 8–16 个 endpoint；只驱逐空闲项，全部活跃时新建或返回明确错误。
- `Manager.Close` 关闭 listener、tunnel 和回收 goroutine。
- `RunProcess` 所有错误路径都必须 release；尤其覆盖 plan 成功但 track/start 失败的路径。

当前按 per-netKey endpoint 实现。端口分配与策略快照保持解耦，便于以后评估 Manager 级
单代理 + per-policy token，但本阶段不切换模型。实现位于 `resource_cache.go` 与
`egress_endpoint.go`；缓存带 busy 回调，活跃请求/隧道不参与空闲驱逐。

## 2. PR4a + PR4b：darwin 内建出站代理（已实现，待真实 Seatbelt 验收）

骨架和硬化可以分提交实现，但必须作为同一个安全验收单元；未硬化的代理不得发布。

### 2.1 启动条件与统一投影

一期仅：

```text
confined == true
platform == darwin
NetRuleSet.Default == deny
```

open 姿态保持原行为，不创建代理、不注入 proxy env；open 下不可落实的选择性 deny
仍报 `UnsupportedError`。`NoSandbox` 不创建或使用代理。

扩展 `compileNetPlan`：

- `kernelForms`：darwin loopback 内核项；
- `proxyPolicy`：深拷贝的完整 net 表；
- `landings`：逐行区分 `Kernel / Proxy / Absorbed / Reserved`；
- `CheckNetPolicy` 和实际启动共享同一投影；
- 获得真实 transport 端口后再次编译，静态预检通过而运行时失败仍不得启动；
- 任一步失败都回收 acquire，不退回无代理运行。

Seatbelt 的具体端口与通配端口语义必须与 matcher 一致。代理 endpoint 的 HTTP/SOCKS
端口作为 synthetic 最高优先级 specific transport 项输出；调用方同端口的直连规则从
kernelForms 丢弃，但完整 proxyPolicy 不变。Reserved 诊断必须明确它是内部 transport，
不是调用方授权。

### 2.2 三种网络通道

1. 到内部代理 endpoint 的 transport 连接，由 launch plan 单独放行。
2. 经代理访问最终目标，由代理使用本次不可变快照判定。
3. 直连 loopback，继续按调用方规则由 Seatbelt 落实。

代理不是唯一出站通道：它是非 loopback 出站的受控通道；loopback 是否可直连仍由规则表
决定。即使规则拒绝 transport 同端口，内部 transport 仍可连接；代理对最终目标仍按原表判定。

### 2.3 endpoint 认证

- 每个 endpoint 使用随机 token；HTTP 用 `Proxy-Authorization: Basic`，SOCKS5 用用户名/密码。
- token 建议 32 字节随机值，URL-safe 编码；不写日志，endpoint 重建时重新生成。
- 同 netKey 后续 command 可以复用 endpoint/token，不同快照不得混用。
- 同 UID 进程不是隔离边界：token 不防御能读取其他进程环境的同 UID 恶意进程；文档必须明确。

### 2.4 协议

一期使用两个 listener（HTTP + SOCKS5），不做单端口首字节分流：

- HTTP `CONNECT`；
- HTTP absolute-form（plain HTTP 转发）；
- SOCKS5 `CONNECT`。

要求：

- 严格解析 absolute-form，拒绝控制字符、CRLF、非法 host、端口 0 和代理自环；
- 丢弃 hop-by-hop 头，转发请求行改 origin-form；
- `http.Transport` 使用 `Proxy: nil` 和自定义 `DialContext`，不读取宿主环境代理；
- 设置 `MaxHeaderBytes`、header/idle/read-write timeout、连接与隧道上限和慢客户端背压；
- 隧道两端关闭互相传播；取消与 `Manager.Close` 中断活动隧道；
- HTTP 403/407 和 SOCKS5 标准错误码带简短原因，异步日志使用 endpoint/policy id；
- 优先 stdlib 实现；引入第三方 SOCKS 库前必须单独获得批准并修改依赖约束。

一期不做 UDP、TLS 终止、HTTP/2 代理、WebSocket 专门处理、方法/路径过滤。

### 2.5 DNS 与地址防护

这是 vbox 内建语义，不是可选 Policy 字段：

- 域名行只对解析结果为外网 IP 的连接生效；解析到内网、回环、link-local、metadata
  或本机网卡地址时，域名行不生效，这些地址只能由 IP 字面量行显式放行。
- IP 行与域名行仍按同一 `level + 原表序` 竞争。
- 多 A/AAAA 逐个检查，只拨通过检查的地址，允许有限顺序重试；解析一次后不再二次解析。
- 解析失败或所有地址被拒绝则连接失败；混合结果中外网地址可用域名行，内网地址只认 IP 行。
- 拒绝范围包括 loopback、RFC1918、IPv6 ULA、link-local、CGNAT、unspecified、multicast、
  broadcast、cloud metadata、本机接口地址，以及 IPv4-mapped/6to4/NAT64 中携带的被拒地址。
- 使用 `netip` + `net.InterfaceAddrs`，IPv4-mapped 解码后同时检查。
- `localhost` / `.localhost` 已归为 loopback 类，显式 loopback/IP 行仍可放行本机服务。
- 地址防护语义版本进入 netKey，名单升级必须使旧 endpoint 失效。

### 2.6 env 与上游代理

一期注入：

```text
HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
http_proxy / https_proxy / all_proxy
NO_PROXY / no_proxy
```

- `ALL_PROXY` 使用 `socks5h://`。
- 代理模式下这些保留变量由 vbox 最后强制设置，调用方 `Env` 不能覆盖内部 endpoint。
- 清理继承和调用方的同名变量，注意大小写；`NO_PROXY` 合并而非整体覆盖，建议包含
  `127.0.0.1,localhost,::1`，让 loopback 直连按规则表处理。
- token 位于代理 URL userinfo，日志与错误必须脱敏。
- 显式实现 `Policy.Net.UpstreamProxy`，纳入 netKey；不得隐式继承宿主 ambient proxy。
- `JAVA_TOOL_OPTIONS`、`GIT_SSH_COMMAND`、`RSYNC_PROXY` 和 Node 专用开关不进入首个代理 PR。

### 2.7 已知限制

- 只支持 TCP；不读代理 env 的客户端会被 Seatbelt 拒绝，不能绕过。
- `ssh`、git over ssh、部分 JVM 和旧 Node 客户端可能无法使用代理。
- 允许一个域名意味着允许该域名上的任意 TCP 服务，也可能允许其成为 relay。
- TLS 不终止，代理只能按 host:port 判定。
- per-netKey token 不提供同 UID 跨策略隔离。
- 代理只服务 deny 姿态；open 下的全量代理和选择性 deny 是另一项工作。

## 3. PR4c：最终预检、文档与实机验收

已完成：`NetCaps`、静态预检和真实 transport 共用 `compileNetPlan`；Reserved/transport
诊断与语法/`UnsupportedError` 分类有测试；README、AGENTS、CHANGELOG 已同步；vbox
普通测试、race、vet、linux/windows 交叉编译通过，aic-pod 非沙箱全量测试通过。

剩余：

- darwin 在真实 Seatbelt 可用环境做端到端代理验证；当前开发执行环境无可用后端，相关
  集成测试会明确 skip，不能记为通过。
- linux/windows 做规则核心与 FS 后端实机验证。
- 跨 `GOOS` 编译或 vet 不等于沙箱行为通过。
- 版本号按发布纪律另行确认，不在本次实现中升级。

## 4. 实施顺序

```text
PR3 → PR4a + PR4b（同一安全验收单元）→ PR4c
```

规则核心与统一命令集成不需要等待代理。代理所需缓存生命周期先稳定，再实现 endpoint，
避免把 listener 泄漏和权限快照混用留到末尾返工。

## 5. 剩余验收矩阵

### 缓存

- 相同 netKey 并发 acquire 只创建一个 endpoint。
- 规则内容、level 或顺序变化得到新 key；仅 FS 改变时复用 Net endpoint。
- 调用方修改原始 Rules 切片不污染缓存；旧 endpoint 不被新快照更新。
- 活跃 command/tunnel 不被空闲驱逐；死 listener 能检测并重建。
- 父命令退出后，宽限期内的后台子进程仍能通过代理。
- `Manager.Close` 后无 listener、goroutine、tunnel 泄漏；完整 key 比对防止错误碰撞命中。

### 代理

- 相同快照的多个 command 安全复用端口，不同快照不混用权限。
- 代理启动失败时 command 未执行且 acquire 已回收。
- 删除或覆盖客户端代理设置不能形成非 loopback 直连。
- open 与 NoSandbox 行为完全不变。
- loopback transport、loopback 最终目标、非 loopback 最终目标分别符合规则。
- HTTP CONNECT、absolute-form、SOCKS5 都按 host:port 判定。
- 认证成功/失败/缺失均有覆盖，token 不出现在日志。
- 自环 CONNECT、端口 0、控制字符、CRLF、非法 host 全部拒绝。
- 取消与 Close 中断活动隧道；IPv4-mapped loopback 有明确结果。

### 地址防护

- 域名解析到 loopback/私网/link-local/metadata/本机地址时，域名行不生效。
- 显式 IP 行可以放行上述地址，IP deny 仍生效。
- 多 A/AAAA 只拨通过检查的地址；全部被拒则失败，不二次解析。
- `localhost` / `.localhost` 仍能匹配内建 loopback 规则。
- 地址防护语义版本变化使旧 endpoint 失效。

### 通用 API 与文档

- 每次调用使用完整 FS/NET 快照；调用方切片不会被缓存或投影修改。
- 语法错误与能力不支持是不同错误；不支持时进程未启动。
- README、AGENTS、CHANGELOG 只描述通用沙箱契约并与实现一致。
- linux/windows 实机验证 level 优先级、终局写根和 deny/ro/rw 后端行为。

## 6. 已确定的实现选择与剩余风险

- loopback 使用两个 listener（HTTP + SOCKS5）。
- endpoint 按 per-netKey 缓存。
- 一期包含最小 HTTP absolute-form 和显式 `UpstreamProxy`。
- 地址防护排除全部私网/ULA/CGNAT 等范围，内网目标需要显式 IP 行。
- 同 UID token 边界作为已知限制文档化；需要更强隔离时必须使用独立 OS 用户或 broker。
- level、解析和代理属于用户可见语义/API 变化，major/minor 版本号必须先确认。

## 7. 后续候选项（不属于本阶段）

1. `EnforcementReport`：结构化返回 bwrap 挂载、洞源缺失、不可表达规则和可写根降级事实。
2. audit 灰度：只作为后端诊断能力评估，不改变默认 fail-closed。
3. Linux 后续可研究 `--unshare-net` + 宿主 unix socket bind 的代理通道；本阶段只留接口。
4. Windows MXC/AppContainer 只跟踪，不切换后端。

## 8. 当前代码锚点

| 文件 | 作用 |
|---|---|
| `vbox.go` | `Rule.Level`、`Decision.Level`、FS 终局求值 |
| `fsrule.go` | FS level 解析、编译、level-aware `IneffectiveRows` |
| `net.go` | 具体目标/规则模式解析、通配、loopback、net level 求值 |
| `netplan.go` | `NetCaps`、`compileNetPlan`、kernel/proxy landings |
| `sandbox.go` | 终局写根/deny 行、deny cache、Seatbelt、策略验证 |
| `process.go` | `RunProcess`、forced env、track/start/exit 的 lease 清理 |
| `manager.go` / `resource_cache.go` | 缓存与 endpoint 生命周期、单飞、busy/idle 驱逐、`Close` |
| `env.go` | 继承/调用方 env 与最后的代理 forced 阶段 |
| `egress_endpoint.go` | endpoint lease、双 listener、认证、连接上限、关闭与隧道 |
| `egress_dial.go` | DNS/IP 防护、规则竞争、有限重试与显式上游 |
| `egress_http.go` / `egress_socks.go` | HTTP/CONNECT/absolute-form 与 SOCKS5 协议 |
| `sandbox_linux.go` / `sandbox_windows.go` | 终局 FS 后端落地 |
