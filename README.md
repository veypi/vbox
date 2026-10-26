# vbox

**Go 原生子进程沙箱。** 在真实宿主上启动一个子进程，它「能读什么、能写什么、能连哪里」由
**一张有序规则表**表达，并交给内核兜底执行。

**中文** | [English](README.en.md)

```go
code, err := mgr.RunProcess(ctx, vbox.StartOptions{
	Exec:    []string{"/usr/bin/curl", "-sS", "https://api.example.com/x"},
	Workdir: "/srv/work",
	Policy:  policy, // 有序 fs/net 规则快照
}, nil, os.Stdout, os.Stderr)
```

vbox 只做一件事：拿到**你**给的规则快照，让操作系统为一个子进程落实它。配置解析、审批、
授权生命周期、审计都在调用方——vbox 不读你的配置，也不替你决定策略。

本文描述现行规则契约；Manager 快照缓存与 darwin deny 姿态内建出站代理已经实现，
实机验收与后续工作见 [docs/development/todo.md](docs/development/todo.md)。

## 它能给你什么

- **一张有序规则表，`level + 原表序` 生效**：高 level 先匹配，同 level 按原表首命中；
  没有「更具体的规则胜」或隐式覆盖层，`Class` 不推导 level。
- **内核执行，不是模拟**：macOS Seatbelt（SBPL）、Linux bubblewrap、Windows 受限令牌 +
  显式拒绝 ACE。纯 Go、无 cgo（只依赖 `golang.org/x/sys` 与 `x/text`）。
- **fail-closed**：本平台无法表达的规则在启动前就被拒绝；没有可用沙箱后端时报错且
  **命令不执行**——绝不静默裸跑。
- **自带进程托管**：`context` 取消整棵进程树、输出捕获（文本或原始字节）、环境清洗、
  资源限制、可选的阶段计时日志。
- **只判定不启动**：同一张表能当纯函数回答「这个进程能不能写 `/srv/work/out.txt`」，
  便于预检与测试。

## 安装

```sh
go get github.com/veypi/vbox
```

所需 Go 版本见 [go.mod](go.mod)。

## 快速开始

```go
rules, err := vbox.CompileFSRules([]string{
	"ro:~/.ssh/known_hosts", // 只读
	"deny:**/.ssh/**",       // 读写双拒（上面那行已把 known_hosts 变成例外）
	"rw:/srv/work/**",       // 读写
}, vbox.ClassCfg)
if err != nil {
	return err // 本平台不可表达：拒绝，而不是放宽
}

policy := vbox.Policy{
	FS: vbox.NewFSRuleSet(rules, vbox.EffDeny), // 未命中写兜底 = deny（读默认开放）
	Net: vbox.NetRuleSet{
		Rules:   []vbox.NetRule{{HostPort: "api.example.com:443", Allow: true}},
		Default: false, // deny 姿态；逐条规则的落地口径见「网络规则落地」
	},
}

mgr := vbox.NewManager()
defer mgr.Close(ctx) // 终止所有在跑的子进程

code, err := mgr.RunProcess(ctx, vbox.StartOptions{
	Exec:    []string{"/usr/bin/curl", "-sS", "https://api.example.com/x"},
	Workdir: "/srv/work",
	Policy:  policy,
}, nil, os.Stdout, os.Stderr)
```

只想判定、不启动进程时，直接问规则集：

```go
d := policy.FS.Match("/srv/work/out.txt", vbox.OpWrite)
// d.Allow、d.Matched（命中行号，-1 = 走兜底）、d.Effect、d.Level

allow := policy.Net.Match("api.example.com:443")
```

`Match` 跟随末段符号链接（open/connect 语义）；`MatchNoFollow` 用于 `unlink`/`rename`
（作用于链接本身）。`MatchPath` 接收已归一化的路径，不碰宿主文件系统。

## 规则表

行首每个 `!` 增加一级 level（0–255），随后是三种效果前缀；例如 `!!deny:/secret`
是 level 2 的拒绝行。`Class` 不推导 level。

三种效果前缀：

| 前缀 | 含义 |
| --- | --- |
| `deny:` | 读写双拒 |
| `ro:` | 读放行、写拒 |
| `rw:` | 读写放行 |

模式：裸路径覆盖整棵子树（`/srv/work` 覆盖 `/srv/work/a/b`）；`*` 匹配段内任意字符、
`?` 匹配单字符、`**` 匹配零或多段（所以 `/etc/ssh/**` 连 `/etc/ssh` 自身也匹配）。
匹配先比较 level：高 level 优先；同 level 按原表顺序扫描，首命中生效。

`Class`（`ClassTemp` / `ClassCfg` / `ClassBuiltin` / `ClassConvenience`）只用于调用方把
不同来源的行拼成稳定顺序（temp grant → 配置 → 出厂内建 → 便利根）；判定本身不看
`Class`，也不从 `Class` 推导 level。

### 两个容易踩的点

**优先级陷阱：被压住的行是安静的。** 如果更高优先级的 `rw:` 行已经覆盖了其他 `deny:` /
`ro:` 目标，后者永远轮不到求值，执行端会直接放行。高 level 行优先，同 level 前行优先。
装配期用 `IneffectiveRows(rules)` 拿到「被更高优先级 `rw` 行完全覆盖」的行下标——
判定保守（只报能静态证明的包含关系），编译本身不因死行失败。注入 `Manager.SetLogf` 时，
执行路径也会打一条 `shadowed by a higher-priority rw row` 日志。

**规则表请用 `NewFSRuleSet` / `CompileFSRules` 构造，不要用结构体字面量。** 字面构造的
`FSRuleSet` 必须自带 canonical 模式：`Match` 入口只归一化**路径**侧，模式用了别的拼写就会
两侧错位、行形同虚设——在 Windows 上这会把可写根误判成只读目标，子进程连自己的工作区都
写不了。两个构造入口都会替你归一模式（`CompileFSRules` 另外做变量展开，并把本机无法
执行的规则直接拒绝）。

## 平台支持

| 平台 | 状态 |
| --- | --- |
| macOS（arm64 / amd64） | **支持**：Seatbelt 后端；CI 构建 + 全量测试 |
| Linux（amd64 / arm64） | **支持**：bubblewrap 后端（需 `bwrap` 与可用 user namespace）；CI 构建 + 全量测试 |
| Windows（amd64 / arm64） | **支持**：受限令牌 + 显式拒绝 ACE；CI 构建，ACL 用例需实机 |
| freebsd / netbsd / openbsd / dragonfly / solaris / illumos / aix / android | 未承诺：可编译，无内核沙箱后端（fail-closed），未做行为验证 |
| plan9 / js / wasip1 | **不支持**：缺进程/信号/沙箱语义，构建在包边界显式失败 |

未列出的平台按「未承诺」处理。同一张表在各平台如何落地：

| 平台 | 机制 | 说明 |
| --- | --- | --- |
| macOS | Seatbelt（SBPL profile） | 按 `level + 原表序` 的统一优先级**逆序**写出（SBPL 后规则胜）；`ro` 行同时显式下沉写拒，可写根内的只读洞在内核真实生效 |
| Linux | bubblewrap | 整机只读视图 + 终局可写根绑定；可实例化目标的 `ro`/`rw` 洞按终局判定回补；需要 bwrap 与 user namespace 可用 |
| Windows | 受限令牌 + 显式拒绝 ACE | 句柄版 ACL（`\\?\` 长路径、`Get/SetSecurityInfo`）；终局 `rw` 目标跳过 ACE，`deny` 与独立 `ro` 行落拒绝 ACE；有效嵌套只读洞无法完整落实时明确报不支持 |
| 其他 | 无内核沙箱 | 明确报错，不静默裸跑 |

### 网络规则落地

net 域的落地能力与 fs 不同，按「姿态 + 逐条」分开说：

| 平台 | 姿态（Default） | 逐条规则 |
| --- | --- | --- |
| macOS | deny 由 Seatbelt 全断姿态 + 内建出站代理共同落实；open 保持原行为 | loopback 由 Seatbelt 逐条落实；deny 下非 loopback 规则由内建 HTTP/SOCKS5 代理按完整快照落实；open 下不可落实的选择性 deny 仍拒启 |
| Linux | 内核落实（deny = `--unshare-net` 全断，新 netns 的 loopback 未配置，回环同样不可达） | 不可表达 |
| Windows | 仅 open；deny 姿态整体拒启 | 不可表达 |

不可内核落实的行按方向处理，**永不比策略更宽**：

- **deny 行**：跳过它沙箱就比策略宽——启动前拒绝（fail-closed）。
- **allow 行**：Linux deny 姿态下可被吸收（目标在该姿态的沙箱里本不可达，收窄与
  fail-closed 同向）；darwin deny 姿态下非 loopback allow 改由代理真实执行，不再
  被当成不可达行吸收。open 姿态下无法落地时，省略 allow 只会收窄。darwin 的
  loopback 有效胜出行则由内核真实落地。
- **没有执行层标记**：规则只描述子进程的 FS/NET 目标，不接受执行层前缀或字段。
  当前后端无法完整落实有效规则时，明确返回「不支持」并拒绝启动；不过滤规则、
  不改道，也不以其他执行层代替本库落地。

net 规则模式支持严格子域通配 `*.example.com`（不匹配裸域或 IP）；`localhost`、
`.localhost` 子名与回环 IP 归一为同一类，`*.localhost` 匹配该类。

启动前预检用 `CheckNetPolicy(platform, rules)`：逐条返回 `Kernel` / `Proxy` /
`Absorbed` / `Reserved` 分类。语法错误与 `UnsupportedError` 是两类错误；能力不支持
只拒绝依赖该能力的进程启动，不改变规则语义。静态预检与 darwin Seatbelt 输出共用
`compileNetPlan`。

### darwin 内建出站代理

仅在 `confined && darwin && NetRuleSet.Default == false` 时启动；open 与 `NoSandbox`
不创建 endpoint、不注入代理环境。代理监听两个仅 loopback 的端口，分别提供 HTTP
`CONNECT` / plain HTTP absolute-form 与 SOCKS5 `CONNECT`。每个 endpoint 使用独立随机
认证 token；只转发 TCP，不终止 TLS、不支持 UDP。

- 启动计划为两个 transport 端口生成最高优先级 Reserved loopback 放行；最终目标仍按
  本次完整规则快照判定，loopback 直连继续由 Seatbelt 规则决定。
- `HTTP_PROXY / HTTPS_PROXY / ALL_PROXY` 及小写形式由 vbox 最后强制设置，`ALL_PROXY`
  使用 `socks5h://`；`NO_PROXY / no_proxy` 合并并包含 `127.0.0.1,localhost,::1`，
  调用方 `Env` 不能覆盖内部 endpoint。
- `NetRuleSet.UpstreamProxy` 可显式指定 `http://`、`socks5://` 或 `socks5h://` 上游；
  该值进入 netKey，绝不隐式继承宿主 ambient proxy。
- 域名先解析再按每个具体 IP 判定；内网、回环、link-local、metadata、本机接口等地址
  不接受域名行放行，只能由匹配的 IP/loopback 行放行。下游连接只使用已授权 IP，避免
  上游再次解析域名造成 DNS 重绑定。
- endpoint 按完整 netKey 在 Manager 内单飞复用，进程结束 release；默认空闲宽限期
  30s，活跃请求/隧道不被空闲驱逐，`Manager.Close` 关闭 listener、连接与 handler。

代理 token 不是同 UID 恶意进程之间的隔离边界；能读取其他进程环境的同 UID 进程仍可能
获得它。需要更强隔离时必须使用独立 OS 用户或独立 broker。

Windows 侧为拒绝 ACE 的幂等对账保留一份状态文件（默认
`{UserConfigDir}/vbox/sandbox/deny_acl_state.json`，可用 `Manager.SetStateDir` 指定），
并使用确定性派生的能力 SID —— 因此 ACE 跨调用/重启稳定，宿主机其他进程不受影响。

**可写根授不上 ACL 只降级该根，不中断 exec。** 一个可写根可能授权时还不存在（spawn
时由存在性过滤），也可能存在却授不上——典型是属主为 `Administrators` / `SYSTEM` 而
当前用户只有 `Modify`（Modify 不含改安全描述符的权限）。此时该根在沙箱内只读，日志
按目录告警一次（固定标记 `write-root unavailable in sandbox`），同一次执行的其余可写
根与进程本身照常；每次调用仍会重试授权，ACL 修好或目录重建后自动恢复可写。授权侧
可以在授权那一刻用 `CheckFSGrantTarget(abs)`（要求原生态路径）预判同一件事。
反方向不降级：`deny` 目标无法落实时仍然拒绝执行——沙箱绝不允许比策略更宽。

## 进程托管

`RunProcess` 是唯一入口（`Manager.Close` 统一终止在跑进程）：

- **环境**：默认在清洗后的宿主环境上应用 `Env` 覆盖；`ReplaceEnv` 让 `Env` 成为完整
  环境（空列表 = 空环境）。
- **`Argv0`**：只改展示名，不参与路径查找或权限身份；Unix 沙箱包装不支持时明确报错。
- **`RawOutput`**：保留 stdout/stderr 原始字节与写错误，关闭 Windows 文本转码与行缓冲，
  供协议管道与二进制命令使用；默认文本模式只刷新自己创建的包装器，不关闭调用方的 writer。
- **`Workdir`**：只设 cwd，不授予目录权限。
- **取消与期限**：全部由 `ctx` 承担；取消会终止整个进程树（Windows 走 Job Object）。
- **日志**：`SetLogf` 注入沙箱/执行阶段计时日志（含上面那条死行提示）；不注入则全链静默。
- **状态目录**：`SetStateDir(dir)` 指定持久状态目录（Windows deny ACE 对账状态文件；
  默认 `{UserConfigDir}/vbox/sandbox`）。

## 不在这里的东西

配置解析、默认规则源、会话授权、grant 生命周期、审批、命令注册和调度都不在本库。
vbox 只接收 FS/NET 快照、做判定并落实原生进程沙箱，不描述或依赖任何特定调用方。

## 测试

```sh
go test ./...
go vet ./...
```

沙箱用例依赖真实平台能力：macOS 需要 Seatbelt、Linux 需要 bwrap + user namespace、
Windows 的 ACL 用例需要真实令牌与对象句柄。缺少能力时用例会**带原因自己跳过**——
跨平台编译通过不等于实机行为已验证。

## 文档、版本与许可

- 文档地图见 [docs/index.md](docs/index.md)。
- 行为变更见 [CHANGELOG.md](CHANGELOG.md)；当前版本见 [VERSION](VERSION)。
- 贡献者与 AI 代理须知（含不可破坏的契约）见 [AGENTS.md](AGENTS.md)。
- MIT（[LICENSE](LICENSE)）。
