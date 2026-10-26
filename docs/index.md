# vbox 文档地图

本仓文档按统一架构组织：`architecture/`（架构设计）、`reference/`（契约规范）、
`guides/`（使用操作）、`development/`（TODO 与过程文档）。vbox 是单一职责的
沙箱库，现行契约直接写在 README，不另设重复文档。

## 入口

| 文档 | 内容 | 何时读 |
| --- | --- | --- |
| [README.md](../README.md) | 定位、快速开始、规则表契约、平台支持矩阵、网络落地、进程托管 | 使用或改动本库前必读 |
| [README.en.md](../README.en.md) | README 的英文镜像 | 与中文版同步更新 |
| [AGENTS.md](../AGENTS.md) | 不可破坏的不变式、测试约定、提交纪律 | 在本仓写代码前必读 |
| [CHANGELOG.md](../CHANGELOG.md) | 已完成的行为变更，破坏性变更在最前 | 发版与升级时 |
| [VERSION](../VERSION) | 当前版本号 | 发版时 |

## development

| 文档 | 内容 | 何时读 |
| --- | --- | --- |
| [development/todo.md](development/todo.md) | 下一阶段设计与实现 TODO（实机验收、后续工作） | 评估未完成的计划时；不是现行契约 |

## 约定

- 文档只描述通用的原生进程沙箱库，不写产品侧的命令体系、配置域或集成方式。
- 已完成的变更写 CHANGELOG，未来计划只写 `development/todo.md`，两者不混。
- 过程性方案落地后归入 `development/` 并标注状态，不与现行契约并列。
