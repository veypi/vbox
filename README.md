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

## 它能给你什么

- **一张有序规则表，首命中生效**：行序就是策略，没有覆盖层、没有「更具体的规则胜」；
  新规则插表头。
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
		Default: false,
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
// d.Allow、d.Matched（命中行号，-1 = 走兜底）、d.Effect

allow := policy.Net.Match("api.example.com:443")
```

`Match` 跟随末段符号链接（open/connect 语义）；`MatchNoFollow` 用于 `unlink`/`rename`
（作用于链接本身）。`MatchPath` 接收已归一化的路径，不碰宿主文件系统。

## 规则表

三种效果前缀：

| 前缀 | 含义 |
| --- | --- |
| `deny:` | 读写双拒 |
| `ro:` | 读放行、写拒 |
| `rw:` | 读写放行 |

模式：裸路径覆盖整棵子树（`/srv/work` 覆盖 `/srv/work/a/b`）；`*` 匹配段内任意字符、
`?` 匹配单字符、`**` 匹配零或多段（所以 `/etc/ssh/**` 连 `/etc/ssh` 自身也匹配）。
表从头扫到尾，首命中生效。

`Class`（`ClassTemp` / `ClassCfg` / `ClassBuiltin` / `ClassConvenience`）只用于调用方把
不同来源的行拼成稳定顺序（temp grant → 配置 → 出厂内建 → 便利根）；判定本身不看 `Class`。

### 两个容易踩的点

**行序陷阱：被压住的行是安静的。** 如果靠前的 `rw:` 行已经覆盖了靠后的 `deny:` / `ro:`
目标，后者永远轮不到求值，执行端会直接放行。装配期用 `IneffectiveRows(rules)` 拿到
「被上方 `rw` 行完全覆盖」的行下标——判定保守（只报能静态证明的包含关系），编译本身
不因死行失败。注入 `Manager.SetLogf` 时，执行路径也会打一条
`shadowed by an earlier rw row` 日志。

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
| macOS | Seatbelt（SBPL profile） | 按 first-wins 快照**逆序**写出（SBPL 后规则胜 ⟺ 首命中胜）；`ro` 行同时显式下沉写拒，可写根内的只读洞在内核真实生效 |
| Linux | bubblewrap | 整机只读视图 + 白名单写绑定；可实例化目标的 `ro`/`rw` 洞按行序回补；需要 bwrap 与 user namespace 可用 |
| Windows | 受限令牌 + 显式拒绝 ACE | 句柄版 ACL（`\\?\` 长路径、`Get/SetSecurityInfo`）；终局 `rw` 目标跳过 ACE，`deny` 与独立 `ro` 行落拒绝 ACE；嵌套只读洞只在工具层生效 |
| 其他 | 无内核沙箱 | 明确报错，不静默裸跑 |

Windows 侧为拒绝 ACE 的幂等对账保留一份状态文件（默认
`{UserConfigDir}/vbox/sandbox/deny_acl_state.json`，可用 `Manager.SetStateDir` 指定），
并使用确定性派生的能力 SID —— 因此 ACE 跨调用/重启稳定，宿主机其他进程不受影响。

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

配置解析、默认规则源、会话授权、grant 生命周期与审批都不在本库；vbox 只接收快照、
做判定并落地。参考集成：[aic-pod](https://github.com/veypi/aic-pod) 的 `libs/host`
作为外部使用者负责配置与授权，每次调用编译快照交给 vbox。

## 测试

```sh
go test ./...
go vet ./...
```

沙箱用例依赖真实平台能力：macOS 需要 Seatbelt、Linux 需要 bwrap + user namespace、
Windows 的 ACL 用例需要真实令牌与对象句柄。缺少能力时用例会**带原因自己跳过**——
跨平台编译通过不等于实机行为已验证。

## 文档、版本与许可

- 行为变更见 [CHANGELOG.md](CHANGELOG.md)；当前版本见 [VERSION](VERSION)。
- 贡献者与 AI 代理须知（含不可破坏的契约）见 [AGENTS.md](AGENTS.md)。
- MIT（[LICENSE](LICENSE)）。
