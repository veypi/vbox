# vbox 下一阶段设计与实现 TODO

状态：2026-10-25 设计定稿，尚未实现。实现时以本文为准；当前行为以代码为准。
本文取代旧的 `docs/openshell-调研.md`（该文件已删除），其中仍然有效的结论并入第 10 节。

---

## 0. 目标与两条核心原则

本次升级只做四件事：

1. 规则行增加 `level`，优先级从「纯行序」变为「`level` + 原表序」。
2. net 规则支持严格子域通配 `*.example.com`。
3. 把快照派生产物（deny 实例化、net endpoint）收进 Manager 生命周期，不保存「当前权限表」。
4. darwin 在 `net_policy=deny` 下增加内建出站代理，使选择性 allow 规则第一次可以在内核层之外被忠实执行。

两条不可动摇的原则：

- **每次 `RunProcess` 以本次 `Policy` 快照为唯一权威；缓存的只是由快照派生的执行产物。**
  代理解析结果、Seatbelt 片段、endpoint 都可以缓存，但缓存不提供「当前权限」，也不接受权限更新。
- **vbox 不评价规则顺序是否合理。**
  只按 `level + 原表序` 求值；不自动改成「具体规则优先」，不因为死行、冲突行而纠正调用方。
  只有规则表在后端无法忠实落地、且忽略它会放宽权限时，才 fail-closed。

明确不做（本阶段）：

- TLS 终止、HTTP 方法/路径过滤、UDP ASSOCIATE。
- OPA/Rego、gateway/supervisor/driver 分层、K8s 编排。
- Linux 透明出口拦截（seccomp user notification + broker）。
- Windows MXC / WFP 后端切换（只跟踪）。
- 通用 FS 静态产物缓存、通用死行消除、通用 cache 框架。
- Linux/Windows 的选择性出站代理（本阶段只有 darwin；Linux 留 unix socket 接口，后续再做）。

---

## 1. 规则语言与求值

### 1.1 level 语法

```text
rule      := level* [ "tool:" level* ] effect ":" target
level     := "!"
```

- 每个 `!` 增加一级；`level=0` 是默认值。
- net 同时接受 `!tool:deny:x` 与 `tool:!deny:x`；`String()` 统一输出 `!…tool:…` 形态。
- FS 不接受 `tool:`；`tool:` 只用于 net/ssh 的工具层行。
- `Level` 使用 `uint8`；`!` 超过 255 个必须报错，不能溢出。
- `!` 只能在行首（或 `tool:` 前后），出现在 effect 之后属于 target 的一部分；路径里合法的 `!` 不能被误剥。
- 具体目标入口（`ParseEntry` / `ValidateEntries` / `ParseTargetRule`）不接受 `!` 与 `tool:`。
- `Rule.Level`、`NetRule.Level`、`Decision.Level` 新增；`Matched=-1` 表示兜底。

### 1.2 唯一优先级定义

```text
先比较 level：高 level 优先
level 相同：原表下标较小者优先
命中即停止
未命中：使用 RuleSet.Default
```

等价于 `(level 降序, 原表下标升序)` 稳定排序后 first-wins。

不增加任何额外语义：

- 更具体的路径优先；
- 精确域名优先于通配域名；
- 具体端口优先于 `*`；
- deny 天然优先；
- `Class` 或规则来源天然优先。

实现要求：

- `FSRuleSet.MatchPath` / `NetRuleSet.Resolve` **不能原地排序调用方切片**（并发命令会共享同一个快照）。
- 单次线性扫描求「最高 level + 最早下标」即可：只有 `level > bestLevel` 才替换；同 level 保留先出现者。
- 需要输出顺序的后端（Seatbelt）在本地构造副本后排序。
- `Class` 仍然只用于调用方拼接，不进入匹配、不进入 cache key。

### 1.3 FS 求值

采用两阶段：

1. 只按模式与优先级选出胜出行。
2. 只对胜出行调用一次 `Rule.Resolve`。

保持现有行为：

- `Handled=false` 回退该行静态 `Effect`，不是继续匹配后续行。
- 未命中时读默认开放，写使用 `DefaultWrite`。
- `MatchNoFollow`（unlink/rename 语义）不变。
- `Decision` 增加 `Level`；兜底时以 `Matched=-1` 区分。

现状说明：`FSRuleSet.MatchPath` 已经只对命中行调用一次 `Resolve`（`vbox.go:164-183`）。
PR1 的这一项主要是回归测试，不是行为改造；真正新增的是「胜出行选择」要按 level 比较。

### 1.4 死行与冲突行

vbox 的职责是执行，不是批改权限表：

- 能**静态证明**永不生效的行，可以从内核投影中省略，因为省略前后结果完全一致。
- 不能证明死掉的行必须保留。
- `IneffectiveRows` 继续作为诊断工具，不影响求值，不因此拒绝编译。
- 不再以「同端口效果冲突」「顺序不合理」为理由拒启；冲突先按 level + 行序解析出胜者，败者若可证明是死行则省略。
- 只有某条**仍然有效**的规则无法被后端表达、并且忽略它会放宽权限时，才 fail-closed。

死行证明的范围（保守）：

- 只做现有 `patternCovers` 能证明的单行覆盖：前序 `rw` 行覆盖后续行（相同模式、`/**` 前缀、裸路径子树）。
- 不做多行 union 覆盖证明；不做通配行的通用包含证明。
- `IneffectiveRows` 必须感知 level：前序低 level 行不再压后续高 level 行；当前实现只按行序，直接沿用会误报。
- 死行动态行（`Rule.Resolve != nil`）：OS 后端仍拒绝**仍然有效**的动态行；只有能证明被更高优先级行完全覆盖时才可省略，保守起见第一版不做。

### 1.5 level 赋值契约（2026-10-25 定稿）

| level | 来源 | 例子 |
|---|---|---|
| 0 | 所有 grant（AI 申请、人工 session、`grant --permanent`）、便利根、`.git/.aws` protected 行、普通 owner cfg 行 | `rw:/workspace` |
| 1 | pod 内建硬保护 | `!deny:~/.aic/config.yaml` |
| 2+ | 设备所有者直接编辑 cfg 的显式逃逸 | `!!rw:~/.aic/config.yaml` |

约定：

- **`Class` 不推导 `Level`。** hard list 单独维护，编译成 `!deny:`；`.git/.aws` 的 protected 行显式 `Level: 0`（2026-10-25 定稿：temp grant 仍可覆盖，保持现有行为）。
- **`grant --permanent` 仍是 level 0。** 永久化不是提权；要覆盖内建保护，必须由所有者直接编辑配置。
- **直接编辑 cfg 是用户行为，允许写任意 level。** `!` 是 level 1，与内建同级时按表序（cfg 行在 builtin 之前，通常会赢）；要无条件覆盖写 `!!`。文档/UI 要说明这一点。
- **AI 来源的规则写入必须被强制 clamp 到 level 0。** 只有所有者直接编辑 cfg 或 pod 内建才能产生 `!`。如果 AI 能通过工具写 cfg，config 文件本身必须在 level 1 deny 里，堵住这条提权路径。
- **内建只是针对大多数人的一般 AI 行为护栏，不是对设备所有者的硬边界。** 所有者可以通过直接编辑 cfg 覆盖。
- hard list 首批建议只放「AI 绝不该碰」的项：aic-pod 配置、设备密钥、`ssh_config`、browser 状态；普通凭证 deny（`~/.ssh/**`、`~/.aws/**` 等）保持 level 0，保留「用户批准 grant 可以覆盖」的现有路径。**具体范围待所有者确认。**
- `IneffectiveRows` / `grant status` 必须能报告「level 0 行被 level 1 内建行压住」。
- `writeRoots()` / `denyPatterns()` 必须按终局求值过滤，不能把被 level 1 deny 覆盖的 level 0 rw 根继续挂载/授 SID。

---

## 2. net 规则模式

### 2.1 具体目标与规则模式分开解析

不再让同一个 `ParseEntry` 同时承担两种职责：

```text
ParseEntry      → 具体查询目标，禁止通配符、禁止 ! / tool:
ParseRuleEntry  → 权限表规则，允许受支持的通配形态与 level
```

- `NetRuleSet.Resolve` 的查询参数永远是具体 host:port。
- `ValidateEntries`、`grant net` 目标等入口不受通配规则影响，仍是具体目标。
- 规则行解析失败仍然 fail-closed。

顺手收紧 `ParseEntry` 的现有多冒号分支：目前 `strings.Count(s, ":") > 1` 会把任意多冒号串当作 bare IPv6 host（`net.go:46-56`），例如 `tool:allow:example.com` 会被接受。新规则：

- 多冒号必须是合法 IPv6 字面量（`netip.ParseAddr` 成功），否则报错；
- 拒绝控制字符、空白、`!`、`tool:`；
- 主机长度/标签长度上限（253 / 63）；
- 通配只允许出现在规则模式侧。

### 2.2 一期只增加严格子域通配

支持：

```text
*.example.com
*.example.com:443
```

语义：

- 匹配 `a.example.com`、`a.b.example.com`。
- 不匹配裸域 `example.com`。
- 不匹配 `badexample.com`。
- 通配符只能是最左侧完整标签。
- 端口继续沿用现有保守交集语义。
- 不匹配 IP 字面量；`*.example.com` 不适用于 IP 目标。

一期暂缓：

```text
allow:*
deny:*
*:443
```

全域姿态继续由 `NetRuleSet.Default` 表达，避免同时引入第二套全域语义。

vbox 不做 Public Suffix List 或「这个域名范围太宽」的产品判断；只验证语法并严格执行。
`*.com` 这种宽通配在 vbox 层合法，产品层（pod/UI）可以另行提示。

### 2.3 loopback 拼写归一（建议在 PR2 做）

现状：

- `EntryMatch` 用 host 字符串精确相等，`localhost` 与 `127.0.0.1` / `::1` 是三个不同 host。
- darwin Seatbelt 把所有 loopback 拼写坍缩成一个端口表；两套口径不一致。
- 第 4 节的地址防护要求「域名解析结果必须是外网 IP」，而 pod 内建 `allow:localhost:*` 是宿主名；如果不特殊处理，内建本机放行会被判成回环地址而失效。

建议：

- 增加 `CanonicalNetHost`：把 `localhost`、`*.localhost`、`127.0.0.1`、`::1` 归入同一个 loopback 类，匹配时等价。
- `String()` 保留 `localhost` 作为规范拼写。
- 这样内建 `allow:localhost:*` 仍匹配所有回环地址，`deny:localhost:*` 也覆盖所有拼写。
- 如果评审决定不做归一，则保留「同端口混合拼写效果相反 → 拒启」的现有行为，并在 README 里明确要求统一拼写。

### 2.4 net 诊断

可选但建议：增加一个保守的 net 死行诊断（类似 `IneffectiveRows`），只报告「前序通配 allow 覆盖后续精确 deny」这类可证明情况。
诊断只输出日志/`grant status`，不拒启，不改变求值。

---

## 3. 快照派生产物缓存

### 3.1 范围

只保留两个缓存：

1. **deny 实例化结果**（现有 `denyCoverAllCached`，`sandbox.go:647-696`）：TTL 30s，容量/生命周期跟随 Manager。
2. **net endpoint 注册表**：按 netKey 复用不可变代理 endpoint。

不做：

- FS Seatbelt 静态片段缓存（收益只是省一次字符串拼接，key 仍要遍历规则）；
- 通用 cache 框架；
- 把 TTL 当作权限失效机制。

### 3.2 缓存键

FS 与 Net 分别计算 key，避免 FS 变化导致网络代理无谓重建。

netKey 至少覆盖：

- `NetRuleSet.Default`；
- 全部规则及原始顺序；
- 每条规则的 `HostPort / Allow / Level`；
- 后端类型与缓存格式版本；
- 地址防护语义版本（第 4.6 节）；
- loopback 归一语义版本（如果启用）；
- 上游代理配置（如果第 4.7 节启用）。

**netKey 必须是「代理实际执行的完整 net 表」**，不是 Seatbelt 的 loopback 投影。
不能只按 `net_policy=open/deny` 缓存；即使姿态相同，规则、level 或顺序不同就是不同 key。

fsKey 至少覆盖：

- `DefaultWrite`；
- 完整有序 FS 规则（顺序参与 key）；
- 每条规则的 `Pattern / Effect / Level`；
- 后端类型与缓存格式版本。

`Class` 不参与执行，可以不进入 key；`ToolOnly` 行不进入原生代理，可以只在 key 中排除（同时确保代理求值也跳过）。

key 使用确定性的长度前缀编码后哈希，不能用容易歧义的字符串拼接；建议 SHA-256，并在命中时比对完整规范 key（消除碰撞风险）；FS/Net 加不同域标签。

### 3.3 缓存的是产物，不是权限状态

| 产物 | 缓存内容 | 生命周期 |
|---|---|---|
| Net endpoint | 深拷贝的不可变 Net 快照、HTTP/SOCKS listener、端口、认证 token、代理服务 | command 引用计数 + 活跃连接计数 + 空闲驱逐 |
| FS deny 实例化 | deny 目标列表 | TTL + 容量驱逐 |
| Windows ACE | 现有持久状态文件和对账机制 | 不作为普通内存缓存处理 |
| command 私有数据 | argv、env、workdir、token、job、stdio、cleanup | 不缓存 |

统一的是：

- key 构造；
- acquire/release；
- 同 key 单飞构造，避免并发重复创建；
- 引用计数；
- 容量与空闲驱逐；
- `Manager.Close` 统一回收。

不统一的是：

- 不可变纯数据不需要 TTL；
- 文件系统实例化结果需要新鲜度 TTL；
- listener/tunnel 需要引用计数和显式关闭。

**TTL 只用于资源回收或宿主对象新鲜度，绝不用于判断权限表是否变化。**
权限表是否变化只由本次快照计算出的 key 决定。

### 3.4 endpoint 语义

```text
command A → acquire(netKey) → endpoint(P)
command B → acquire(netKey) → endpoint(P)   // 复用同一 token + 端口
command C → 修改任意有效 net 规则 → 新 netKey → endpoint(Q)
```

- 旧 endpoint 仍绑定旧快照，继续服务仍在使用它的 command；不再接收新 command 的 acquire。
- 引用和活跃连接归零后，按空闲策略回收。
- 缓存中的 Net 快照必须深拷贝，避免调用方修改原切片后「key 是一种策略、代理实际执行另一种策略」。
- endpoint 被缓存但 listener 已死时，acquire 必须检测并重建，不能把死端口交给命令。
- 命令退出时 release；detach 的子进程可能仍在用代理，因此需要「最后一个命令退出后再保持 N 秒」的宽限期；宽限期可配置，默认建议 30s。测试必须覆盖「父命令退出后后台子进程仍能通过代理」。
- 容量：建议上限 8–16 个 endpoint；超过时驱逐空闲项；全部活跃时新建（策略数量通常很少），或返回明确错误。具体值在实现时定。

### 3.5 与 Manager 生命周期

- 所有缓存改为 per-Manager；`NewManager` 初始化，`Manager.Close` 关闭 listener、tunnel、reaper goroutine。
- `planConfined` 需要拿到 Manager 的资源句柄（通过 `confineSpec` 传入，或新增 `resources` 参数）；所有平台文件与测试同步改。
- `process.go:112` 现在在 `planConfined` 成功后、`cmd.Start` 前 `track` 失败会直接 return，既不 close token 也不 cleanup；加 endpoint 后这是 listener 泄漏。必须在 acquire 后 `defer release`，或先 track 再 acquire。
- `RunProcess` 的所有错误路径都要释放本次 acquire。

### 3.6 单代理 vs per-netKey（评审项）

本文按**per-netKey endpoint**写：每个不同的 net 表有自己的 HTTP/SOCKS 端口和 token，Seatbelt 放行对应端口。

备选：Manager 级单代理，用 per-policy token 在代理内部选择策略。优点是一次只开一个端口、Seatbelt transport 固定、生命周期更简单；缺点是要在代理内维护 token→快照表。

当前不切换，但实现时保留这个切换点：endpoint 的「端口分配」与「策略快照」解耦，代理核心只依赖 `policySnapshot + token`。

---

## 4. darwin 内建出站代理

### 4.1 启动条件

一期仅：

```text
confined == true
platform == darwin
NetRuleSet.Default == deny
```

open 姿态保持原行为：

- 不创建代理；
- 不注入 proxy env；
- 不改变现有 Seatbelt 姿态；
- open 下不可落实的选择性 deny 仍按现有能力模型处理（拒启或 `tool:`）。

`NoSandbox` 不创建或使用代理。

### 4.2 权限表 → Seatbelt 表：唯一投影函数

新增：

```text
compileNetPlan(platform, NetRuleSet, caps) →
    kernelForms   // SBPL 行（darwin loopback 投影）
    proxyPolicy   // 深拷贝的完整 net 表（代理执行）
    landings      // 每行：kernel landed / proxy landed / absorbed / reserved
```

- `CheckNetPolicy` 变成 `compileNetPlan(caps)` 的薄封装；配置期校验和 `grant status` 共用。
- `seatbeltNetForms` 只消费 `kernelForms`，不再自己写一套近似算法。
- `validateProcessPolicy` 用实际 transport 端口再跑一次 `compileNetPlan`，保证：
  - 静态预检（无端口）通过 → 运行时投影（有端口）也必须通过；
  - 任何一步失败：回收 acquire，不启动命令，不退回无代理运行。
- `NetRowLanding` 从单一 `Landed` 扩成两维：`Kernel` / `Proxy` / `Absorbed` / `Reserved`，并带原因。
  例：`allow:example.com:443` 在 deny 姿态下是「kernel 不落地、proxy 落地」；`allow:localhost:8080` 可能两者都落地。
- pod 的 `grant status` 文案随之更新：区分「内核 loopback 落地」「出站代理落地」「被姿态吸收」「transport 端口保留」。

Seatbelt 事实（必须写进注释与测试）：

- **具体端口优先于通配端口**，不是纯 last-match；当前 `sandbox.go:762-764` 已记录。
- 按统一优先级遍历：
  - 每个端口，最高优先级的 specific 行胜出；
  - 遇到第一条 `*` 端口行后，所有更低优先级行（specific 或 `*`）都死亡；
  - 只输出幸存行。
- **transport 端口保留**：代理 endpoint 的 HTTP/SOCKS 端口作为 synthetic 最高优先级 specific 行输出；调用方同端口的 specific 行从 `kernelForms` 丢弃，但 `proxyPolicy` 仍保留（代理对最终目标仍按表判定）。
- `(remote ip "localhost:PORT")` 匹配 `127.0.0.1` 与 `::1`，不匹配 `::ffff:127.0.0.1`。Go listener 建议绑 `127.0.0.1`（需要时同时绑 `::1`），env 写 `127.0.0.1`；补 IPv4-mapped 测试。
- `network-outbound` 基线 `(deny network-outbound)` 之后，transport allow 必须是 specific 规则，不能用 `*`。

FS 侧：

- `seatbeltArgs` 输出顺序严格按优先级逆序：
  - 低 level 先输出；
  - 同 level 原表后行先输出；
  - 高 level / 原表前行后输出。
- 这样 SBPL 后命中胜与 vbox 优先级一致。
- `fs_policy` 基线（`deny file-write*` / `allow file-write*`）永远在所有 level 之下。

### 4.3 Seatbelt 中的三种网络通道

1. **到内部代理 endpoint 的连接**
   - 属于 transport，由 launch plan 单独放行。
   - 它不是调用方的 allow 行，但内核看到的确实是一条 loopback connect 放行；必须诚实文档化。
2. **经代理访问最终目标**
   - 由代理使用本次不可变 Net 快照判定。
3. **直连 loopback**
   - 继续按调用方规则表现有逻辑落地。

因此：

- 即使权限表包含 `deny:localhost:*`，代理 transport 仍必须能连；做法是保留 transport 端口、覆盖同端口调用方行。
- `deny:localhost:PORT`（PORT = transport 端口）在直连层面被 transport 覆盖；代理仍会对「最终目标 = localhost:PORT」的 CONNECT 按表判定。
- 文档不能再宣称「代理口是唯一出站通道」。准确说法：
  > 代理是非 loopback 出站的受控通道；loopback 是否可直连仍由规则表决定。
- pod 内建 `allow:localhost:*` 意味着 deny 姿态下本机回环仍然全开；代理不是唯一通道。这是产品层要明确的事实。

### 4.4 endpoint 认证

每个缓存 endpoint 带随机 token：

```text
netKey → endpoint + token
```

- token 与 listener 同生命周期；同一 netKey 的后续 command 复用相同 endpoint/token。
- HTTP 使用 `Proxy-Authorization: Basic`。
- SOCKS5 使用用户名/密码认证。
- token 使用 URL-safe 字符（建议 32 字节随机、hex 或 base64url）；不写入日志；endpoint 重建时重新生成。
- 不防御「已经能读取其他进程全部环境的同 UID 恶意进程」；这属于同 UID 信任边界，README 要明确。
  注意：per-netKey token 不提供跨策略隔离；如果同一 OS 用户下并发运行不同 net 策略的命令，恶意命令理论上可以读取另一个命令的 env 并借用更宽的策略。要真正隔离需要独立 OS 用户或 broker，不在本阶段。

### 4.5 协议与请求判定

一期支持：

- HTTP `CONNECT`；
- HTTP absolute-form（plain HTTP 转发）；
- SOCKS5 `CONNECT`。

**建议一期开两个 listener（HTTP 端口 + SOCKS 端口）**，而不是一个端口首字节分流：

- Seatbelt 放行两个 specific 端口；
- env 分别指向；
- 少一个 mux，少一类解析 bug；
- 如果坚持单端口，再写 first-byte mux（HTTP 方法 vs SOCKS5 0x05）。

HTTP 转发要求：

- 严格解析 absolute-form；拒绝控制字符、CRLF、非法 host、端口 0；
- 拒绝 `CONNECT` 到代理自身（自环）；
- 丢弃 hop-by-hop 头（`Proxy-*`、`Connection` 等），请求行改 origin-form；
- `http.Transport` 必须 `Proxy: nil`、自定义 `DialContext`（地址防护接管拨号），不读宿主环境代理；
- `MaxHeaderBytes`、`ReadHeaderTimeout`、`IdleTimeout`、连接/隧道上限、读写超时；
- 慢客户端背压；隧道两端关闭要互相传播；
- 403/407 响应带简短原因；SOCKS5 用标准错误码；
- 不向某个 `RunProcess` 的 stderr 异步写拒绝原因；日志使用 run-independent 的 endpoint/policy id。

一期不做：

- UDP ASSOCIATE、TLS 终止、HTTP 方法/路径过滤；
- HTTP/2 代理、WebSocket 特殊处理（隧道天然支持）；
- 上游代理链（见 4.7）。

### 4.6 DNS 与地址防护（vbox 内建，2026-10-25 定稿）

这是 vbox 的内建语义，不是可选 Policy 字段：

- **域名行只对「解析结果是外网 IP」的连接生效。**
- 解析到内网/回环/link-local/metadata/本机网卡地址时，域名行不生效；这些地址**只能由 IP 字面量行**显式放行。
- 仍然按同一 `level + 原表序` 首命中：IP 行与域名行在同一张表里竞争；IP 行是显式逃逸口。
- 多 A/AAAA：逐个地址判定；只拨通过检查的地址；允许按顺序有限重试；解析一次后不再二次解析。
- 解析失败/不可解析地址直接丢弃；全部被丢弃则拒绝。
- 域名解析结果混合外网/内网：外网地址可用域名行；内网地址只认 IP 行；代理只会拨通过检查的地址。

「外网」定义（建议，实现时固化）：

- 拒绝：loopback、RFC1918、IPv6 ULA、link-local、CGNAT（100.64.0.0/10）、unspecified、multicast、broadcast、cloud metadata、本机接口地址、IPv4-mapped/6to4/NAT64 中携带的被拒地址。
- 其余视为外网。
- 用 `netip` + `net.InterfaceAddrs` 实现；IPv4-mapped 要解码后同时检查。
- 语义版本号进入 netKey；升级防护名单必须使旧 endpoint 失效。

`localhost` 特殊处理：

- `localhost` / `*.localhost` 归入 loopback 类（见 2.3），否则 pod 内建 `allow:localhost:*` 会被判成回环地址而失效。
- 显式的 loopback/IP 行仍然可以放行本机服务。

可选：如果产品要防止 AI grant 到 metadata，再加一条 level 1 的内建 IP deny（169.254.169.254、云厂商 metadata 段等）。

### 4.7 环境变量

一期只注入标准变量：

```text
HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
http_proxy / https_proxy / all_proxy
NO_PROXY / no_proxy
```

- `ALL_PROXY` 使用支持远端解析的 `socks5h://`。
- 在代理执行模式下，这些保留变量由 vbox **最后统一设置**，调用方 `Env` 不能覆盖内部 endpoint。
  当前 `processEnv` 是 `inherited + plan.env + opts.Env`（`env.go:11-16`），调用方最后会覆盖；需要新增 forced 阶段。
- 代理模式下清掉继承/调用方的 `*_PROXY`（Windows 大小写不敏感，不能同时出现 `HTTP_PROXY` 与 `http_proxy` 两种拼写）；`NO_PROXY` 合并而不是整体覆盖。
- 建议 `NO_PROXY` 包含 `127.0.0.1,localhost,::1`，让 loopback 直连走规则表。
- token 在 `HTTP_PROXY` 的 userinfo 里；日志、错误信息必须脱敏。
- deny 姿态下即使没有代理（Linux），也应考虑剥离宿主 ambient proxy，避免工具指向不可达代理后报错难查。

后续适配（不进入首个代理 PR）：

- `JAVA_TOOL_OPTIONS`（JVM 不读 HTTPS_PROXY）；
- `GIT_SSH_COMMAND`（ssh 不读代理变量，git over ssh 会失败）；
- `RSYNC_PROXY`；
- Node `NODE_USE_ENV_PROXY`（只在明确支持的版本矩阵启用；不笼统声称整个 Node 22 都支持）；
- 各语言第三方 HTTP client 的专门配置。

**上游代理（待定）**：

- 设计原则「不经过宿主默认 HTTP_PROXY 再转发」是对的；但设备经常在 `127.0.0.1:7897` 这类上游代理后面，vbox 代理直连会让 GitHub/HF 失败。
- 建议一期就留一个显式的 `Policy.Net.UpstreamProxy`（纳入 netKey、脱敏日志），或至少在文档写明「需要直连外网」。
- 不能隐式读取宿主 `HTTP_PROXY`，否则会变成第二套策略源。

### 4.8 实现选型

- HTTP：stdlib `net/http` + `Hijacker` 做 CONNECT，absolute-form 用 `http.Transport{Proxy: nil, DialContext: 自定义}`。约 200 行，解析、auth、限流、DNS 防护全部可控。
- SOCKS5：优先自己写（约 200 行）；如果引入库，候选 `github.com/things-go/go-socks5`（维护中的 fork，支持 auth/UDP/自定义 Dial/Resolver）或 `github.com/txthinking/socks5`。
- **不要用 `elazarl/goproxy` / `google/martian` 这类偏 MITM 的框架**，除非马上要做 TLS 终止；它们会扩大审计面，并且 auth/限流/地址防护仍要自己写。
- 依赖约束：`AGENTS.md` 目前写明依赖只允许 `golang.org/x/sys` 和 `golang.org/x/text`。引入任何第三方 SOCKS 库之前，必须先改这条约束并拿到用户明确批准；否则用 stdlib 自己写。
- 共享的 HTTP/SOCKS 逻辑放在独立文件（如 `egress_http.go` / `egress_socks.go`），不要污染 matcher/规则求值核心。

### 4.9 明确不支持/已知限制

- 只支持 TCP；UDP/QUIC 客户端在 deny 姿态下直接失败。
- 只约束会读取代理环境变量的客户端；不读取的客户端会被 Seatbelt 拒绝（fail-closed），不会绕过。
- `ssh`、`git over ssh`、部分 JVM、旧 Node 的 `fetch` 可能无法通过代理；见 4.7。
- 允许一个域名就意味着允许该域名上的任意 TCP 服务；允许的 host 可以被当作 relay（域名 allowlist 的固有风险）。
- loopback 直连仍然按规则表；宽泛 loopback 授权意味着本机 relay 可用。
- 同 UID 进程不是隔离边界；token 不能防同 UID 的 env 读取。
- TLS 不终止，代理只能按 host:port 过滤，看不到方法/路径。
- 默认 `net_policy=open` 的产品不受益；代理只在 deny 姿态启用。

### 4.10 平台矩阵

| 平台 | fs | net deny 姿态 | 选择性 allow | 选择性 deny |
|---|---|---|---|---|
| darwin | Seatbelt | Seatbelt 全断 + 代理 | 代理（一期） | open 下仍不支持；deny 下由 default deny 吸收 |
| linux | bwrap | `--unshare-net` 全断 | 不支持（后续可做 unix socket 代理） | 不支持（`tool:`） |
| windows | 令牌 + ACL | 拒启 | 不支持 | 不支持（`tool:`） |

Linux 后续：`--unshare-net` + 把宿主 unix socket bind 进沙箱（OpenShell/srt 同构）。这不受 netns 隔离影响，是可行的；本阶段只留接口，不实现。

---

## 5. FS 与内核落地

### 5.1 darwin FS

见 4.2：按优先级逆序输出，保持 SBPL 后命中胜。

### 5.2 Linux / Windows FS

继续以 `evaluateFSPolicy` 求终局（linux `sandbox_linux.go:52`，windows `sandbox_windows.go:851`）：

- 每个候选路径都通过新的 level-aware Match。
- 只有能静态证明永不生效的 deny 行，才能从实例化输入中剔除。
- 不能把 `ro` 与 `rw` 都笼统当作「放行」处理。
- Windows token、Job Object、每调用临时目录仍然每次创建，不进缓存。
- Windows 持久 ACE 继续经状态文件对账，不能因内存缓存命中而跳过必要的安全校验。

### 5.3 原始行 vs 终局

`writeRoots()` / `denyPatterns()` 现在直接遍历原始规则（`sandbox.go:95-117`），level 引入后会出问题：

- 一条被更高优先级行完全压死的 level 0 `rw` 行，仍会被 bwrap `--bind` / Windows 授 SID，基底比终局宽，靠后续 overlay 回补；一旦回补不完整就是放宽。
- 建议：`writeRoots()` 对每个字面 rw 行用终局 `Match` 检查；终局不是 rw 就跳过。
- `denyPatterns()` 用保守死行过滤；不可证明的死行仍保留（fail-closed）。
- `evaluateFSPolicy` 的候选集合与 `writableMountRoots` 同步使用过滤后的结果。

### 5.4 `IneffectiveRows`

- 必须感知 level：前序低 level 行不压后续高 level 行。
- 只报告能证明的死行；per-op 语义要保守（前序 `rw` 覆盖后续 `deny`/`ro` 是当前唯一证明）。
- 不要因为 level 引入就扩大证明范围；误报会导致调用方删掉有效行，漏报只是诊断缺失。

---

## 6. aic-pod 集成

### 6.1 level

- `defaultDenyPaths` 里挑出 hard list，编译为 `!deny:`；`.git/.aws` 的 protected 行显式 `Level: 0`。
- `grant fs` / `grant net` 产出的行强制 level 0；`--permanent` 也一样。
- AI 能写 cfg 的路径必须被 level 1 保护；AI 写出的规则强制 level 0。
- `grant status` 标注 level 与「被内建保护压制」。
- `fsSnapshotLocked` 的拼接顺序不变（temp → base → protected → convenience），level 负责跨层压制；不要再用 Class 推导优先级。
- 直接编辑 cfg 的所有者可以写 `!` / `!!`；文档说明 `!!` 才是无条件覆盖。

### 6.2 net

- `compileAuth` 的 `CheckNetPolicy` 调用改为带 `NetCaps`（egress proxy 是否可用、transport 端口是否已知）。
- 配置期可以假设 darwin 具备代理能力；运行时启动失败仍然 fail-closed。
- `grant status` / `grant net` 文案区分 kernel/proxy landings。
- `netSnapshotForNative` 继续剔除 `ToolOnly`；代理侧也跳过。
- `netBuiltin = allow:localhost:*` 保持 level 0；配合 2.3 的 loopback 归一。
- `net_policy` 默认 open 不变；deny 姿态的平台矩阵见 4.10。

### 6.3 env / 上游代理

- pod 传入的上游代理（如果有）走显式 `Policy.Net.UpstreamProxy`，不要依赖宿主 env。
- 内部代理 env 必须最后强制写入；pod 的 `Env` 不能覆盖。
- 文档写明：deny 姿态下本机回环仍按 `netBuiltin` 放行；代理不是唯一通道。

### 6.4 文档与发布

- `aic/docs/permission.md`：level 语义、优先级、level 赋值契约、loopback 归一、地址防护、代理行为。
- `aic-pod/docs/host_sandbox.md`：net 平台矩阵、grant status 文案、上游代理。
- `vbox/README.md` / `README.en.md` / `AGENTS.md`：把「first-wins 是全部语义」改成「level + 原表序」；更新 net 能力矩阵与代理说明。
- `CHANGELOG`：vbox 与 pod 各一条；版本号升级按规则 17，major/minor 必须先问用户。

---

## 7. PR 拆分与顺序

### PR0：清理工作区

- 先单独提交当前 vbox 未提交的 prlimit 改动（`proc_unix.go` / `process.go` / `rss_other.go` / `sandbox_linux.go` / `sandbox_test.go`），不要和本次设计混在一起。
- 顺手修 `process.go:112` 的 track 失败清理（close token / cleanup / release）。

### PR1a：level 求值与 FS 落地（先做，有明确用例）

- 通用 `!` 前缀解析；
- `Rule.Level` / `Decision.Level`；
- 唯一优先级比较实现（不原地排序）；
- FS 两阶段求值与 `Resolve` 单次调用测试；
- darwin FS 输出重排；
- Linux/Windows 终局求值回归；
- `IneffectiveRows` level 感知；
- `writeRoots()` / `denyPatterns()` 终局过滤；
- pod hard list + `.git/.aws` Level 0 + `grant status` 注解；
- 文档（vbox + pod）。

### PR2：net 域名模式 + 解析收紧

- `ParseEntry` / `ParseRuleEntry` 拆分；
- 严格子域通配；
- `ParseEntry` 多冒号清理；
- `String()` 往返；
- loopback 归一（如果评审通过）；
- 不做全域 `*`；不改变 open/deny 姿态语义。

### PR1b：net level + darwin 投影

- `NetRule.Level` / `NetRuleSet.Resolve` level 感知；
- `compileNetPlan`（可先 `EgressProxy=false`）；
- `NetRowLanding` 两维；
- `CheckNetPolicy` / `seatbeltNetForms` 共用投影；
- transport 端口保留逻辑（即使代理还没上，测试可注入假端口）；
- 死行诊断（保守）。

### PR3：资源缓存基础

- Manager 内 cache；
- FS/Net 独立 key；
- 单飞构造、引用计数、容量与空闲驱逐；
- 迁移 `denyCoverAllCached`；
- `Manager.Close` 统一清理；
- endpoint 注册表接口 + fake resource factory 测试（不依赖真实代理）。

### PR4a：darwin 代理骨架

- 基于 netKey 的 endpoint 缓存；
- 两个 listener（HTTP + SOCKS）或单端口 mux（按评审）；
- endpoint 认证；
- HTTP CONNECT + absolute-form；
- SOCKS5 CONNECT；
- Seatbelt transport 放行；
- 标准 env（forced 阶段）；
- 失败回收和并发测试。

### PR4b：代理硬化

- DNS 解析与固定拨号；
- 内建地址防护；
- 上游代理（如果一期做）；
- 限流/背压/超时/最大隧道；
- 解析攻击测试（CRLF、控制字符、自环、端口 0、IPv4-mapped）；
- 取消与 Close 中断活动隧道；
- 文档明确 TCP 范围、loopback 边界和不支持的客户端。

### PR4c：pod 集成

- `NetCaps` / `CheckNetPolicy` 调用；
- `grant status` / `grant net` 文案；
- 配置期校验；
- 文档、版本 pin、CHANGELOG。

推荐顺序：

```text
PR0 → PR1a → PR2 → PR3 → PR4a → PR4b → PR4c → PR1b
```

如果配置保护是当前最紧急的诉求，PR1a 可以最先做；如果代理是当前最紧急的诉求，PR2 → PR4 可以提前，PR1a 并行。PR1b 依赖 PR4a 的 `compileNetPlan`，所以放在 PR4a 之后（或在 PR4a 里一起做）。

---

## 8. 验收矩阵

### 求值

- level 高于行序；同 level 严格行序。
- 精确规则不比通配规则天然优先。
- `MatchPath` 只对胜出行调用一次 `Resolve`；`Handled=false` 回退该行静态 Effect，不继续匹配。
- `Decision.Level` 在命中与兜底两种情况下都正确；兜底 `Matched=-1`。
- `!` 超过 255 报错；`!` 在 target 内部不被误剥；`tool:` 与 `!` 的四种排列都能解析并规范化。
- `IneffectiveRows` 不误报「前序低 level、后续高 level」的行。
- 死行不改变求值，也不因「顺序不合理」单独报错。

### FS 后端

- darwin 输出顺序：低 level 先、同 level 后行先、高 level 后；SBPL 后命中胜与 matcher 一致。
- Linux/Windows 终局求值与 level 一致。
- 被 level 1 deny 覆盖的 level 0 rw 根不进入 `writeRoots` / 不授 SID。
- 不可表达但已死的行不拒启；不可表达且仍有效的行仍拒启。
- Windows ACE 对账在缓存命中时不被跳过；per-call 临时目录/令牌仍每次创建。
- `.git/.aws` level 0：temp grant 仍可覆盖；level 1 内建行不可被 temp 覆盖。

### net 后端

- 具体端口 vs 通配端口的投影：高优先级 `*` 关闭更低优先级行；同端口只留胜者。
- transport 端口保留：调用方同端口 specific 行从 kernel forms 丢弃，proxy policy 保留。
- `CheckNetPolicy` 与 `seatbeltNetForms` 输出一致（同一份投影）。
- `CheckNetPolicy` 带代理能力时，deny 姿态下的 allow 行标记为 proxy landed，而不是 absorbed。
- 静态预检通过 → 运行时投影通过。
- loopback 拼写归一（如果启用）下，`localhost`/`127.0.0.1`/`::1` 行为一致；未启用时，同端口冲突仍拒启。
- open 姿态与 NoSandbox 行为完全不变。
- Windows deny 姿态仍拒配；Linux deny 姿态仍全断。

### 通配

- `*.example.com` 匹配子域、不匹配裸域、不匹配 `badexample.com`。
- 不匹配 IP 字面量；`*.com` 在 vbox 层合法（产品层可另行提示）。
- 端口 `*` 与具体端口的保守交集语义。
- `String()` 往返。
- `ParseEntry` 拒绝 `!`、`tool:`、控制字符、非法多冒号；`ValidateEntries` 不再接受 `tool:allow:example.com` 这类串。

### 缓存

- 相同 netKey 并发 acquire 只创建一个 endpoint。
- 规则内容、level 或顺序变化都会得到新 key。
- 仅 FS 改变时复用 Net endpoint。
- 仅 ToolOnly 改变时复用原生 Net endpoint（且代理跳过 ToolOnly）。
- 调用方修改原始 Rules 切片不会污染缓存。
- 旧快照 endpoint 不会被新快照更新。
- 活跃 command/tunnel 不被空闲驱逐。
- endpoint listener 死亡后 acquire 能检测并重建。
- 父命令退出后，宽限期内的后台子进程仍能通过代理。
- `Manager.Close` 后无 listener、goroutine、tunnel 泄漏。
- key 碰撞时完整 key 比对能拒绝错误命中。

### 代理

- 相同快照的多个 command 可以安全复用端口。
- 不同快照不会混用权限。
- 代理启动失败时 command 未执行；acquire 被回收。
- 删除或覆盖客户端代理设置不能形成非 loopback 直连。
- `ToolOnly` 不影响原生代理。
- open 与 NoSandbox 行为完全不变。
- loopback transport、loopback 最终目标、非 loopback 最终目标分别符合规则。
- HTTP CONNECT / absolute-form / SOCKS5 三条路径都能按 host:port 判定。
- 认证成功/失败/缺失三种情况；token 不出现在日志。
- 自环 CONNECT、端口 0、控制字符、CRLF、非法 host 全部拒绝。
- `::ffff:127.0.0.1` 场景有明确结果（当前预期：Seatbelt transport 不匹配，需 env 用 127.0.0.1 或 listener 同时绑 v4/v6）。
- 取消与 Close 能中断活动隧道。

### 地址防护

- 域名解析到 loopback/私网/link-local/metadata/本机地址时，域名行不生效。
- 显式 IP 行可以放行上述地址；IP deny 仍然生效。
- 多 A/AAAA：只拨通过检查的地址；全部被拒则失败；不二次解析。
- 解析失败/不可解析地址被丢弃。
- `localhost`/`*.localhost` 作为 loopback 类仍能匹配内建 `allow:localhost:*`。
- 地址防护语义版本变化会使旧 endpoint 失效。

### pod 集成

- hard list 行 level 1；`.git/.aws` level 0；grant 全部 level 0；`--permanent` 不能提权。
- 所有者直接编辑 cfg 写 `!!` 可以覆盖 level 1；AI 写出的规则被 clamp 到 0。
- `grant status` 能显示 level、kernel/proxy 落地、被内建保护压制。
- `aic/docs/permission.md` / `host_sandbox.md` / vbox README/AGENTS 与实现一致。
- 版本 pin 与 CHANGELOG 更新。

---

## 9. 待拍板 / 风险

1. **hard list 的具体范围**：首批是否只放 aic-pod 配置、设备密钥、`ssh_config`、browser 状态；普通凭证 deny 是否保持 level 0。
2. **loopback 是否归一**：建议归一（消掉 Seatbelt 拼写坍缩与 exact matcher 的不一致，并让内建 `localhost:*` 在地址防护下存活）；不归一就要保留冲突拒启。
3. **两个 listener 还是单端口 mux**：建议两个 listener。
4. **per-netKey endpoint 还是 Manager 级单代理**：当前按 per-netKey；实现时保留切换点。
5. **上游代理是否一期支持**：建议至少留显式字段，否则设备在 `127.0.0.1:7897` 后面时代理直连会失败。
6. **HTTP absolute-form 是否一期做**：plain HTTP 客户端需要；如果只做 CONNECT，`curl http://` 会失败。建议一期做最小 absolute-form。
7. **地址防护的「外网」名单**：是否排除全部私网/ULA/CGNAT，还是只排除 loopback/link-local/metadata；本文建议全部排除，内网只能走 IP 行。
8. **默认 `net_policy=open` 的产品价值**：代理只服务 deny 姿态；如果目标是默认安全，需要另做「全量代理 + 选择性 deny」，工作量更大。
9. **同 UID token 边界**：per-netKey token 不能防同 UID env 读取；如果需要跨会话隔离，需要独立 OS 用户或 broker。
10. **版本号**：level + 代理是语义/API 变更，按规则 17 由用户决定 minor/major，不自动升。

---

## 10. 附录：OpenShell 调研保留结论

旧的 `docs/openshell-调研.md` 已删除；仍然有效的结论：

值得做但尚未做（按优先级）：

1. **EnforcementReport**：把 bwrap 落了多少挂载、哪些洞源不存在被跳过、哪些 ro 通配不可表达、哪些可写根 ACL 降级等「原生事实」收成结构体，grant status / 日志 / AI 自诊断共用。
2. **方法/路径级出口策略**：`vsh/network` 的 HTTPClient 已有 `allowedURLPrefixes` / `allowedMethods` / `denyPrivateRanges`，pod 的 `NetClient` 未接线；差的是配置语法 + 接线。
3. **exec 摘要固定**：grant cmd 只认 basename；参考 `ExecutableIdentity`（首次记录 SHA-256，变了就拒）。
4. **audit 灰度**：`enforcement: audit`（只记不拦）用于新规则观察期。
5. **grant 风险启发式**：审批时对私网 IP / 高位端口 / 数据库端口打旗。
6. **loopback 跨拼写残余**：如果第 2.3 节不做归一，darwin 上「allow 具体端口 + deny 通配端口、拼写不同」的组合仍可能比策略宽；完整收口需要目标集合交叉验证或策略层归一。

明确不做：

- 不抄 OPA/Rego、gateway/supervisor/driver 分层、providers、K8s 编排。
- 不换首命中语义去追「加法式 + deny 优先」；本阶段只加 level + 行序。
- Linux 透明出口拦截（seccomp user notification + broker）不做；pathname AF_UNIX 可以 bind 进沙箱，但透明拦截与 TCP loopback 代理是另一回事。
- Windows MXC（wxc-exec，AppContainer，Win11 ≥26100）只跟踪，不切换。

参考：

- OpenShell 源码：`/Users/veypi/test/OpenShell`（main 分支）。
- 完整调研报告：会话空间 `openshell-vs-vbox-vsh.md`（2026-10-10）。

---

## 11. 现状代码锚点（2026-10-25）

| 文件 | 位置 | 作用 |
|---|---|---|
| `vbox.go` | 55-78 / 82-96 / 151-199 | `Class` / `Rule` / `FSRuleSet.Match*` |
| `net.go` | 28-72 / 141-168 / 176-191 / 237-335 | `ParseEntry` / `NetRule` / `Resolve` / `CheckNetPolicy` |
| `fsrule.go` | 29-51 / 116-136 / 151-168 | `ParseFSRule` / `CompileFSRules` / `IneffectiveRows` |
| `sandbox.go` | 95-117 / 274-344 / 647-696 / 705-796 / 965-1002 | `denyPatterns`/`writeRoots` / `evaluateFSPolicy` / deny cache / Seatbelt / `validateProcessPolicy` |
| `process.go` | 39-166（track 在 112） | `RunProcess` 与错误清理 |
| `manager.go` | 78-101 | `Close` |
| `env.go` | 11-16 | `processEnv` |
| `sandbox_linux.go` | 39-63 | bwrap plan |
| `sandbox_windows.go` | 833-863 | deny ACE / 终局求值 |
| `aic-pod/libs/host/permissions.go` | 62 / 104-116 / 286-315 | `netBuiltin` / `CheckNetPolicy` 预检 / FS 快照拼接 |
| `aic-pod/cfg/config.go` | 78 | `net_policy` 默认 open |
