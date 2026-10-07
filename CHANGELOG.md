# Changelog

版本号见 [VERSION](VERSION)，遵循 SemVer：破坏性变更进位 minor。

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
