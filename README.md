# vbox

vbox 是 ivec.ai 平台的原生子进程沙箱库：规则模型 + 纯判定 + OS 落地 +
进程生命周期。它不知道 shell、审批、grant 持久化的存在——配置解析与
grant 生命周期在调用方（aic-pod `libs/host`），每次调用编译快照传入。

## 规则语义

单一有序规则表，从前向后扫描、**首命中生效**；新规则一律插表头。行为
完全由行序决定，没有「谁压谁」的特殊规则。行首效果前缀：

```text
ro:~/.ssh/known_hosts
deny:**/.ssh/**      # 读写双拒，前面的 known_hosts 例外先匹配
rw:~/.cache/**
```

fs 与 net 两域各有规则集（`FSRuleSet` / `NetRuleSet`）；审批策略属产品层，
不进本包。规则表设计契约见 aic `docs/permission_rules.md`。

## 三段式接口

规则模型（fsrule.go / net.go）→ 编译（`Compile`，fail-closed——当前平台
不可表达的规则在启动前拒绝）→ 执行（`Manager`：RunProcess / Spawn）。

OS 落地（自 aic-pod exec_procs 迁入，2026-09-29；2026-10-01 修订）：darwin
seatbelt 按 first-wins 快照**逆序**输出（SBPL 后规则胜 → 首命中等价）；ro
行同时显式下沉写拒，可写根内的 ro 洞因此在内核真实生效。linux bwrap 先
求值后落措施（可实例化目标的 ro/rw 洞按序回补，W3）。windows 受限令牌+
ACE 求值后 rw 洞跳过 ACE、deny 与独立 ro 行落拒绝 ACE（2026-10-01 修复
ACL 边界路径形态后 ro 行实际生效；嵌套洞仅工具层生效）。工作区元数据保护
（.git/.aws）不是本包逻辑：由调用方（pod）作为内置 ro 行随快照下发。
调用方把公共区/缓存根编成显式规则行传入快照。

## 与 aic-pod 的关系

fs/net/ssh 的解析与匹配只有本包实现；pod 的 fsauth/netauth 只管理配置、grant 和快照。CompileFSRules 校验整个配置，失败不发布部分结果。MatchPath 只匹配已规范化的逻辑路径；Match/MatchNoFollow 用于宿主 canonical 语义，cloud 不能隐式调用宿主路径解析。

`StartOptions.Argv0` 只改变程序展示名称，不参与路径查找或权限身份。直接启动与 Windows 受限令牌启动支持它；Unix 沙箱包装暂不支持时明确报错，不静默忽略、不因此关闭沙箱。

`StartOptions.ReplaceEnv=true` 将 `Env` 作为完整子进程环境，空列表就是空环境；默认仍在继承环境上应用显式覆盖。shell 集成在入口清洗并载入宿主环境，随后使用完整环境模式，避免 `env -i` 或 `unset` 被进程启动器抵消。

`StartOptions.RawOutput=true` 为协议管道和二进制命令保留 stdout/stderr 原始字节与写错误，禁用 Windows 文本转码及行缓冲。输入输出流由调用方管理关闭；双向协议还需在取消时关闭自己的管道，使阻塞读写退出。默认文本模式仅刷新内部转码包装器，不关闭调用方的 writer。
