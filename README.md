# vbox

vbox 是 ivec.ai 平台的原生子进程沙箱库：规则模型 + 纯判定 + OS 落地 +
进程生命周期。它不知道 shell、审批、grant 持久化的存在——配置解析与
grant 生命周期在调用方（aic-pod `libs/host`），每次调用编译快照传入。

## 规则语义

单一有序规则表，从前向后扫描、**首命中生效**；新规则一律插表头。行为
完全由行序决定，没有「谁压谁」的特殊规则。行首效果前缀：

```text
deny:**/.ssh/**      # 读写双拒
ro:~/.ssh/known_hosts
rw:~/.cache/**
```

fs 与 net 两域各有规则集（`FSRuleSet` / `NetRuleSet`）；审批策略属产品层，
不进本包。规则表设计契约见 aic `docs/permission_rules.md`。

## 三段式接口

规则模型（vbox.go / net.go）→ 编译（`Compile`，fail-closed——当前平台
不可表达的规则在启动前拒绝）→ 执行（`Manager`：RunProcess / Spawn）。

OS 落地（自 aic-pod exec_procs 迁入，2026-09-29；2026-10-01 修订）：darwin
seatbelt 按 first-wins 快照**逆序**输出（SBPL 后规则胜 → 首命中等价）；ro
行同时显式下沉写拒，可写根内的 ro 洞因此在内核真实生效。linux bwrap 先
求值后落措施（可实例化目标的 ro/rw 洞按序回补，W3）。windows 受限令牌+
ACE 求值后 rw 洞跳过 ACE、deny 与独立 ro 行落拒绝 ACE（2026-10-01 修复
ACL 边界路径形态后 ro 行实际生效；嵌套洞仅工具层生效）。工作区元数据保护
（.git/.aws）不是本包逻辑：由调用方（pod）作为内置 ro 行随快照下发。
调用方状态（公共区/缓存根）经 hooks.go 注入。

## 与 aic-pod 的关系

本包是 aic-pod `libs/fsauth` / `libs/netauth` 纯 matcher 的 first-wins
重写（语义自 last-wins 反转）；状态层（cfg 耦合 / Reconcile / 持久化）
与默认策略源留在 pod。
