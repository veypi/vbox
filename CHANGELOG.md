# Changelog

版本号见 [VERSION](VERSION)，遵循 SemVer：破坏性变更进位 minor。

## 0.3.2 — 2026-10-11

### 修复

- **net 规则按「能否内核落实」逐条分类，不再一刀切拒启**（修复两条实测缺陷）：
  - 缺陷 A：Linux `net_policy=deny`（全断姿态）下任何 allow 行（含调用方内建的
    `localhost:*` 放行）都会撞「selective network rule is unsupported」拒启——
    最安全的姿态反而所有沙箱化 exec 不可用。现在 deny 姿态下的 allow 行被**吸收**：
    目标在 `--unshare-net` 的沙箱 netns 里本不可达（loopback 未配置亦不通），跳过
    该行的沙箱严格窄于策略，与 fail-closed 同向，记日志不拒启。
  - 缺陷 B：open 姿态下添一条 `deny:` 行会在三平台全部拒启。deny 行的拒启语义
    **保持不变**（跳过即比策略宽，永不发生），但 darwin 上「与可落实的 loopback
    deny 行不相交的 allow 行」现在正确识别为 no-op，不再误伤（典型：配置了
    loopback deny 后，任何非 loopback 的会话 grant 曾会把原生 exec 全部打死）。
- **`CheckNetPolicy(platform, rules)` 导出**：启动前预检入口，逐条返回
  landed / absorbed（`NetRowLanding`，含 Noop 区分「语义不变的吸收」与「收窄的
  吸收」），遇到「落实不了、跳过又会变宽」的行报错——调用方可在配置/授权那一刻
  失败，而不是埋到 exec 期。`validateProcessPolicy` 的 net 段改为调用它，行为变化
  仅限上述两例。
- **darwin loopback 分类按内核真实口径建模**（评审返修）：Seatbelt 把所有
  loopback 拼写（localhost/127.0.0.1/::1…）坍缩为 `localhost:port`、按端口
  首行生效、首个端口 `*` 行之后整表截断；逐行独立分类会在「同端口、混合拼写、
  效果相反」的组合上误放——内核比策略更宽。`CheckNetPolicy` 现在模拟该内核表：
  同端口后续行同效果为 no-op 重复；效果相反时 deny 行报错（指向统一拼写或
  `tool:`），allow 行被吸收（收窄）。已知残余见函数注释与
  docs/openshell-调研.md §3。

### 新增

- **`NetRule.ToolOnly` 与 `tool:` 规则前缀**（`ParseNetRule`；`ParseTargetRule`
  保持不变）：声明该行仅由调用方工具层（进程内 HTTP/MCP 客户端等）执行，内核落地
  与「能否落实」判定一律跳过——用于平台无法落实但工具层可执行的规则（典型：
  linux/windows 上的选择性 deny）。判定入口（`Match`/`Resolve`）不看 ToolOnly。
  `NetRule.String()` 返回含前缀的规范形态，供日志/回执。

### 测试

- 新增 `netpolicy_conformance_test.go`：平台 × 姿态 × 行形态的分类矩阵（判定层
  纯函数，CI 全平台可跑），含上述两条缺陷的探针固化、tool: 行口径与 darwin
  loopback 端口坍缩矩阵（混合拼写冲突 / 端口 * 截断 / 同效果重复）。

## 0.3.1 — 2026-10-10

### 修复

- **可写根授不上 ACL 不再打死整条 exec（Windows）**：`planConfined` 原先逐根调
  `grantDirWrite`，任一失败即 `return` 整个 plan——一个合法但事后方知授不上的目录
  （典型：`C:\models\llama` 属主是 `BUILTIN\Administrators`，当前用户只有
  `Authenticated Users:(M)`；Modify 不含 WRITE_DAC）会让**所有** exec 失败，而错误
  只说得出「grant workspace <dir>」，看不出是哪一环。现在改为逐根独立授权
  （`grantWritableRoots`）：授不上的根只降级——该根在沙箱内写被拒（失败方向恒为
  更严），日志按目录告警一次（固定标记 `write-root unavailable in sandbox`），
  其余可写根与本次 exec 照常。每次调用仍重试授权（不引入负缓存），目录被删重建
  或 ACL 事后修好后自动恢复可写。反方向不降级：`deny` ACE、受限令牌、私有临时
  目录等「更宽」侧的失败仍然 fatal。
- **新增 `CheckFSGrantTarget(abs)`**：授权侧前置探测。Windows 用
  `READ_CONTROL|WRITE_DAC` 试开对象（与真实授权同一条权限判据，无副作用）；
  不存在/非目录与「可授」都返回 nil，只有「存在但当前用户无 WRITE_DAC」返回错误
  ——调用方可在 `grant` 那一刻就告知，而不必等到下一次 spawn。其余平台恒 nil
  （unix 在挂载/profile 层落实可写根，不存在「能不能授上」这一前置条件；已知
  不对称见函数注释）。

### 测试

- 新增用例：`grantRootSIDs` 的纯逻辑（授不上一个根不丢其余根且只告警一次、全部
  失败不报错、SID 派生失败只跳该根、同路径只授权一次）——逻辑与平台无关，放共享
  文件 `sandbox_grantroots_test.go`（sandbox.go 的 `grantRootSIDs`），macOS/Linux/CI
  都能跑；Windows 专有：注入授权失败后端到端存活（其余可写根仍可写）、被降级的根在
  沙箱内确实只读、`deny` 不可实例化仍拒绝执行、`CheckFSGrantTarget` 三态。

## 0.3.0 — 2026-10-08

### 新增

- **规则行动态判定 `Rule.Resolve`（配 `Resolution` / `Decision.Reason`）**：规则行可带
  `Resolve func(path string, op FileOp) Resolution` 回调，在本行命中时按「路径 + 操作」
  现算效果——把「随目标数量增长的一次性枚举行」换成「一行 + 按需判定」（典型场景：云
  `/skills/{id}` 的可见性，只查当前这一个 id，不枚举全库）。行序语义不变：前面的行仍
  先命中、命中本行时不再查后续行；回调不表态（`Handled=false`）落回静态 `Effect`。
  `Resolution.Reason` 经 `Decision.Reason` 回传给调用方做报错文案（静态命中行与兜底
  判定的 `Reason` 为空，由调用方自建文案）。
- **OS 级沙箱计划拒启动态行（fail-closed）**：`validateProcessPolicy`（darwin / linux /
  windows 共用）遇到带 `Resolve` 的行直接拒绝——动态判定无法下推到 seatbelt / bwrap /
  ACL，拿静态 `Effect` 当终局会与真实判定不一致（可能更宽松）。
- **测试**：动态行的行序与 `Reason` 传递、回调不表态落回静态效果、OS 计划拒绝动态行
  （同一张表去掉回调即合法）。

## 0.2.0 — 2026-10-07

### 独立使用收敛（2026-10-07）

- **中性化运行时产物（破坏性）**：Windows 的 deny ACE 对账状态默认路径由
  `{UserConfigDir}/aic/sandbox/deny_acl_state.json` 改为
  **`{UserConfigDir}/vbox/sandbox/deny_acl_state.json`**，并新增
  `Manager.SetStateDir(dir)` 供调用方指定；per-call 私有临时目录前缀
  `aic-sandbox-*` → `vbox-sandbox-*`。（deny 能力 SID 名保持不变：改它会让已打 ACE
  变成无法回收的残留；它只是内部标识，不影响使用者。）
- **平台支持面明确**：darwin / linux / windows 为支持面（README「平台支持」）；
  freebsd/netbsd/openbsd/solaris/aix/android 可编译但未做行为验证；plan9 与 js/wasip1
  缺进程/信号/内核沙箱语义，构建时在包边界显式失败（不再报一堆 undefined）。
- **CI**：新增 `.github/workflows/ci.yml`（gofmt、vet、test 与多平台构建）。
- **测试夹具与注释中性化**：去掉外部参考实现的对照说法与内部模块指针；
  夹具路径改为通用示例；全仓统一 gofmt。

### 变更（破坏性）

- **唯一启动入口**：删除第二套进程启动入口 `Spawn` / `Spawned` / `Confine`，
  `Manager.RunProcess` 成为唯一入口（进程托管、取消、输出捕获收口在同一处）。
- **`Argv0` 语义收窄**：只改 argv[0] 展示名，不参与路径查找或权限身份；Unix 沙箱
  包装无法支持时**明确报错**，不再静默忽略、也不因此关闭沙箱。
- **规则/环境/托管收口**：以编译快照替代增量状态，环境清洗与注入顺序固定
  （沙箱 env 清洗 → 调用方 `Env` 覆盖 → 子进程）。

### 新增

- **`IneffectiveRows(rules []Rule) []int`**：报出被上方 `rw` 行完全覆盖、因而
  **永不生效**的 `deny`/`ro` 行下标（first-wins 行序陷阱）——调用方可在装配配置时
  提示或拒绝；判定保守（只报能静态确定包含关系的行），编译本身不因死行失败。
  执行路径在注入 `Manager.SetLogf` 时会自动打一条 shadowed 行日志（死行在执行端
  本来就是安静的）。README「规则表」补行序陷阱与字面构造 `FSRuleSet` 的
  canonical 契约。
- **文档拆语言 + 新增 AGENTS.md**：`README.md` 保持中文（仓库主入口），英文版移入
  `README.en.md`（两份顶部互相引用、内容同步）；新增 `AGENTS.md` 收纳 AI/贡献者向的
  契约与不变量（first-wins、fail-closed、canonical 模式契约、Windows ACE 模型、
  平台矩阵、测试与发版约定）。
- **Windows ACL 句柄版**：`\\?\` 前缀长路径 + `Get/SetSecurityInfo`，长路径安全。
- **`StartOptions.RawOutput`**：保留 stdout/stderr 原始字节与写错误，禁用 Windows
  文本转码与行缓冲，供协议管道和二进制命令使用。
- **`Manager.SetLogf`**：注入沙箱与执行阶段计时日志（不注入则全链静默）。

### 测试

- **Windows 用例的规则表统一经 canonical 归一**：裸 `Rule` 字面量（OS 原生反斜杠
  路径）在 win 上让 `rw` 行不被识别 → 可写根被当只读目标打写拒 ACE → 子进程写整个
  工作区被拒；改用 `NewFSRuleSet`/`CompileFSRules` 同口径后再断言（契约见 README）。
- **环境能力缺失改 skip（不再报假失败）**：无 `sh`/`bash` 的宿主跳过 shell 见证类
  用例；无符号链接权限跳过链接类用例；`bwrap` 覆盖参数用例在 Windows 平台跳过
  （unix 语义）；`denyCoverAll` 期望改用 `/` 形（win 假失败）。

### 修复

- **ro 语义三平台收口**：求值入口统一为 first-wins 终局；darwin 的 `ro` 行显式下沉写拒
  （此前只渲染读允许，可写根内的只读洞被宽写放行盖掉）；Windows 的 `ro` ACE 此前因
  路径形态不可用被「对象不可读→跳过」吞掉，现经 OS 路径转换后实际生效。
- **Linux / Windows 内核行序映射**：deny 目标按 first-wins 快照求值后落措施——Linux
  bwrap 对可实例化目标的 `ro`/`rw` 洞按序回补（含嵌套洞的字面前缀回补），Windows 终局
  `rw` 目标跳过 ACE（`deny` 与独立 `ro` 行仍落）。
- **变量展开**：`HOME` 与 `~` 同义，避免无 `HOME` 的进程整表编译失败。

### 文档

- README 重写为独立库用法（规则语义、三段式接口、平台落地、进程托管、与调用方的
  职责边界）；新增本变更记录；包文档改为面向库使用者。

## 0.1.0 — 2026-09-29

- 初始发布：规则模型（FS/Net 有序表，首命中生效）+ 纯判定 + OS 落地（Seatbelt /
  bubblewrap / Windows 受限令牌与 ACE）+ 进程托管。OS 落地与进程托管来自本项目的
  早期平台实现（配置解析与授权层随后整体归调用方），规则匹配重写为 first-wins 语义。
