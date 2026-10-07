# vbox

**原生子进程沙箱库**：有序规则表 + 纯判定 + OS 落地 + 进程托管。用来在真实宿主上
启动子进程，并把「能不能读 / 写 / 连」表达成一张有序规则表，由内核机制兜底。

MIT 许可（[LICENSE](LICENSE)）。

## 规则语义

单一有序规则表，**从前向后扫描、首命中生效**（first-wins）；新规则插表头。行为完全
由行序决定，没有「谁压谁」的特殊规则。行首是效果前缀：

```text
ro:~/.ssh/known_hosts      # 只读
deny:**/.ssh/**            # 读写双拒——上面那行先命中，所以 known_hosts 仍是例外
rw:/srv/work/**            # 读写
```

文件与网络各一域（`FSRuleSet` / `NetRuleSet`）；网络域用 `allow:` / `deny:` 加
`host:port`（端口可为 `*`）。**审批策略、配置解析、授权生命周期都不在本库**——调用方
每次调用编译一份快照传进来。

`Class`（`ClassTemp` / `ClassCfg` / `ClassBuiltin` / `ClassConvenience`）只用于调用方
把不同来源的行拼成稳定顺序（temp grant → 配置 → 出厂内建 → 便利根）；判定本身不看
`Class`。

## 三段式接口

1. **规则模型**（`fsrule.go` / `net.go`）：效果、模式、目标条目与解析。
2. **编译**（`CompileFSRules` / `CompileNetRules` / `NewFSRuleSet`）：把规则变成可执行
   快照，模式归一（符号链接前缀展开）在此完成。**fail-closed**——本平台无法表达的规则
   在启动前就被拒绝，不会静默降级成放行。
3. **执行**（`Manager.RunProcess`）：沙箱落地、进程托管、输出捕获、取消与资源限制。

```go
rules, err := vbox.CompileFSRules([]string{
	"ro:~/.ssh/known_hosts",
	"deny:**/.ssh/**",
	"rw:/srv/work/**",
}, vbox.ClassCfg)
if err != nil {
	return err // 规则在本平台不可表达：拒绝，不放行
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
// d.Allow / d.Matched（命中行号，-1 = 走兜底）/ d.Effect

allow := policy.Net.Match("api.example.com:443")
```

`Match` 跟随末段符号链接（open/connect 语义），`MatchNoFollow` 用于 `unlink`/`rename`
（作用于链接本身）。`MatchPath` 接收已归一化的路径，不碰宿主文件系统。

## 平台落地

| 平台 | 机制 | 说明 |
| --- | --- | --- |
| macOS | Seatbelt（SBPL profile） | 按 first-wins 快照**逆序**写出（SBPL 后规则胜 ⟺ 首命中胜）；`ro` 行同时显式下沉写拒，可写根内的只读洞在内核真实生效 |
| Linux | bubblewrap | 整机只读视图 + 白名单写绑定；可实例化目标的 `ro`/`rw` 洞按行序回补；需要 bwrap 与 user namespace 可用 |
| Windows | 受限令牌 + 显式拒绝 ACE | 句柄版 ACL（`\\?\` 长路径、`Get/SetSecurityInfo`）；终局 `rw` 目标跳过 ACE，`deny` 与独立 `ro` 行落拒绝 ACE；嵌套只读洞只在工具层生效 |
| 其他 | 无内核沙箱 | 明确报错，不静默裸跑 |

Windows 侧为拒绝 ACE 的幂等对账保留一份状态文件
（`{UserConfigDir}/aic/sandbox/deny_acl_state.json`），并使用确定性派生的能力 SID——
因此 ACE 跨调用/重启稳定，宿主机其他进程不受影响。相关规则在 `sandbox_windows.go`
中集中说明。

## 进程托管

`RunProcess` 是唯一入口（`Manager.Close` 统一终止在跑进程）：

- **环境**：默认在清洗后的宿主环境上应用 `Env` 覆盖；`ReplaceEnv` 让 `Env` 成为完整
  环境（空列表 = 空环境）。
- **`Argv0`**：只改展示名，不参与路径查找或权限身份；Unix 沙箱包装不支持时明确报错。
- **`RawOutput`**：保留 stdout/stderr 原始字节与写错误，关闭 Windows 文本转码与行缓冲，
  供协议管道与二进制命令使用；默认文本模式只刷新自己创建的包装器，不关闭调用方的 writer。
- **`Workdir`**：只设 cwd，不授予目录权限。
- **取消与期限**：全部由 `ctx` 承担；取消会终止整个进程树（Windows 走 Job Object）。
- **日志**：`SetLogf` 注入沙箱/执行阶段计时日志，不注入则全链静默。

## 与调用方的关系

配置解析、默认规则源、会话授权、grant 生命周期与审批都不在本库；vbox 只接收快照、
做判定并落地。参考集成：[aic-pod](https://github.com/veypi/aic-pod) 的 `libs/host`
负责配置与授权，每次调用编译快照交给 vbox。

## 测试

```sh
go test ./...
go vet ./...
```

沙箱用例依赖真实平台能力：macOS 需要 Seatbelt、Linux 需要 bwrap/user namespace、
Windows 的 ACL 用例需要真实令牌与句柄；跨平台编译通过不等于实机行为已验证。

## 版本与许可

- 当前版本见 [VERSION](VERSION)，变更记录见 [CHANGELOG.md](CHANGELOG.md)。
- MIT（[LICENSE](LICENSE)）。
