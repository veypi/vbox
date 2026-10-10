# OpenShell 调研与 net 规则平台能力闸（2026-10-10）

本文记录 NVIDIA OpenShell 调研的结论、由此发现的 vbox/aic-pod 两条实测缺陷，
以及 v0.3.2 的修复设计。行文中的 file:line 以 2026-10-10 的代码为准。

## 1. OpenShell 是什么

NVIDIA 开源的 agent 沙箱运行时（Rust）：CLI + Gateway 控制面 + 沙箱内 Supervisor，
compute driver 可插拔（Docker/Podman/K8s/microVM/Windows MXC）。策略 YAML 声明，
内核执行 fs/syscall（Landlock/seccomp），**网络策略统一走用户态 CONNECT 代理**
（内核只负责「禁直连」），并用 SMT solver 对策略变更做边界包含验证。

与我们同构的验证：supervisor-initiated 连接（gateway 永不反连）≡ aic-pod 外连云端；
fail-closed（"reject rather than silently drop"）≡ vbox 启动前拒绝。

## 2. 调研发现的两条实测缺陷（已修复）

探针方法：`validateProcessPolicy` 的 platform 是参数，mbp 上即可跨平台判定。

### 缺陷 A：Linux `net_policy=deny` 全灭

aic-pod `permissions.go` 无条件把内建 `localhost:* allow` 追加进 net 快照
（`netBuiltin`），快照经 `engine_vsh.go nativePolicy` 喂给 vbox。旧
`validateProcessPolicy`：deny 姿态下 allow 行走不进「open 姿态可跳过」分支，
落到 `platform != "darwin"` 直接拒启。**Linux 设备切到最安全的 deny 姿态 =
所有沙箱化原生 exec 拒绝执行。**

另一层语义问题（vbox `sandbox.go` bwrapArgs 注释）：`--unshare-net` 的新 netns
里 loopback 未配置，**回环也不可达**，且沙箱内 loopback ≠ 宿主 loopback——
内建 `localhost:* allow`（意图是宿主回环服务）在该姿态下语义本就不成立。

### 缺陷 B：一条 `deny:` net 规则砖掉原生 exec

open 姿态下一旦存在 deny 行，allow 行不再被跳过，非 loopback 行（darwin 只允许
loopback 逐条；linux/windows 无逐条能力）全部撞拒启。用户为防 SSRF 加最标准的
`deny:169.254.169.254:*` 的代价是原生 exec 全不可用——**安全加固动作触发失败**。

### 修复设计（v0.3.2）

原则：**沙箱绝不比策略更宽；收窄方向的降级显式化**。

- vbox 新增 `CheckNetPolicy(platform, rules)`：逐条分类 landed / absorbed
  （Noop 区分「语义不变」与「收窄」），第一条「落实不了、跳过又会变宽」的行
  （选择性 deny）报错。`validateProcessPolicy` 的 net 段改为调用它。
- 吸收语义：deny 姿态下 deny 行是 no-op；deny 姿态下 allow 行被吸收（目标
  本不可达，收窄方向）；open 姿态下无 deny 行时 allow 行是 no-op；darwin
  open + 仅有 loopback deny 时，非 loopback allow 与可落地行恒不相交 = no-op。
- `tool:` 前缀（`NetRule.ToolOnly` / `ParseNetRule`）：声明该行仅工具层执行，
  内核落地与能力判定一律跳过；`Match` 照常命中。这是选择性 deny 在
  linux/windows 上的合法表达。
- aic-pod 侧：`compileAuth` 配置期过 `CheckNetPolicy`（不再等 exec 期暴雷），
  报文指向 `tool:` 前缀；`nativePolicy` 改用剔除 tool-only 行的
  `netSnapshotForNative`；`grant net` 回执标注原生落地情况（对齐 `grant fs`
  的可写性警告先例）；`grant status` 逐条标注 `[仅工具层生效]` /
  `[原生沙箱内不可达: …]`。
- darwin loopback 端口坍缩（评审返修补牢）：Seatbelt 不区分 loopback 拼写，
  按端口首行生效、首个 `*` 行截断整表。`CheckNetPolicy` 模拟该内核表，同端口
  冲突的 deny 行拒启（统一拼写或 `tool:`），allow 行收窄吸收——堵住「同端口
  混合拼写效果相反」组合穿透逐行分类的口子。

## 3. 值得抄但尚未做的（按优先级）

1. **EnforcementReport**（vbox 返回值）：bwrap 落了多少挂载、哪些洞源不存在被
   跳过、哪些 ro 通配不可表达、哪些可写根 ACL 降级——现在全在日志里。照
   OpenShell `DockerOuterFenceEvidence::project`（driver-docker/isolation.rs）
   的「原生事实 → 保证」投影收成结构体，grant status / 日志 / AI 自诊断共用。
2. **方法/路径级出口策略**：`vsh/network` 的 HTTPClient 已有
   `allowedURLPrefixes`/`allowedMethods`/`denyPrivateRanges`（network.go:84-89），
   aic-pod `NetClient` 未接线。差的是配置语法 + 接线，不是实现。
3. **exec 摘要固定**：grant cmd 只认 basename；参考 OpenShell `ExecutableIdentity`
   （首次见到记 SHA-256，变了就拒），在 grant 审批时钉住路径摘要。
4. **audit 灰度**：`enforcement: audit`（只记不拦）用于新规则观察期；
   NetClient 已有审计回调，接线成本低。
5. **grant 风险启发式**：审批时对私网 IP / 高位端口 / 数据库端口打旗
   （OpenShell proposal risk check 的轻量版，不需要 SMT）。
6. **loopback 跨拼写残余**：darwin 内核不区分 loopback 拼写，`CheckNetPolicy`
   的端口坍缩模拟是逐行口径——「allow 具体端口 + deny 通配端口、拼写不同」
   （如 `allow:127.0.0.1:8080` + `deny:localhost:*`）的组合逃得过逐行判定
   （deny 行自身目标可表达，但具体端口洞在别的拼写下比策略宽）。完整收口需要
   目标集合的交叉验证或策略层拼写归一；目前以「配置统一用 localhost 拼写」
   为约定。

## 4. 明确不做的

- **不抄** OPA/Rego、gateway/supervisor/driver 分层、providers、K8s 编排——
  我们是设备端运行时，不是 agent 机群控制面。
- **不换**首命中语义去追「加法式 + deny 优先」——两边各有静态分析问题
  （它用 ambiguity 检测，我们用 IneffectiveRows），换语义只是换一种问题。
- **Linux 透明出口拦截**（seccomp user notification + broker）：OpenShell 的
  做法（sandbox/network_broker.rs + SO_BINDTODEVICE=lo 钉死，socket_confinement.rs）
  是纯 Go 无 cgo 边界外的大工程。注意第二份调研「纯 bwrap 下 unshare-net +
  可达代理做不到」的说法不准确：pathname AF_UNIX 套接字不受 netns 隔离
  （docker.sock 挂进容器天天在用），bind 进沙箱即可达——真正做不到的是
  透明拦截与 TCP loopback 代理。暂记为不做。
- Windows MXC（wxc-exec，AppContainer，Win11 ≥26100，非管理员可用，支持
  fs readonly/readwrite + network.proxy 重定向）：跟踪为未来后端候选，现在
  是 preview 形态，不切换（OpenShell RFC 0013）。

## 5. 参考

- 完整调研报告（含 OpenShell 架构/策略 schema/prover 细节）：
  会话空间 `openshell-vs-vbox-vsh.md`（2026-10-10）。
- OpenShell 源码：/Users/veypi/test/OpenShell（main 分支）。
