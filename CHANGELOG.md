# Changelog

版本号见 [VERSION](VERSION)，遵循 SemVer：破坏性变更进位 minor。

## 0.2.0 — 2026-10-07

### 变更（破坏性）

- **唯一启动入口**：删除第二套进程启动入口 `Spawn` / `Spawned` / `Confine`，
  `Manager.RunProcess` 成为唯一入口（进程托管、取消、输出捕获收口在同一处）。
- **`Argv0` 语义收窄**：只改 argv[0] 展示名，不参与路径查找或权限身份；Unix 沙箱
  包装无法支持时**明确报错**，不再静默忽略、也不因此关闭沙箱。
- **规则/环境/托管收口**：以编译快照替代增量状态，环境清洗与注入顺序固定
  （沙箱 env 清洗 → 调用方 `Env` 覆盖 → 子进程）。

### 新增

- **Windows ACL 句柄版**：`\\?\` 前缀长路径 + `Get/SetSecurityInfo`，长路径安全。
- **`StartOptions.RawOutput`**：保留 stdout/stderr 原始字节与写错误，禁用 Windows
  文本转码与行缓冲，供协议管道和二进制命令使用。
- **`Manager.SetLogf`**：注入沙箱与执行阶段计时日志（不注入则全链静默）。

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
  bubblewrap / Windows 受限令牌与 ACE）+ 进程托管。OS 落地与进程托管自集成方
  aic-pod 的 `libs/exec_procs` 迁入本库（`libs/policy`、`fsauth`、`netauth` 的匹配
  逻辑合并重写为 first-wins 语义）。
