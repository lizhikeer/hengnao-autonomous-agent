# 贡献指南（CONTRIBUTING）

> 本文件为 `hengnao-autonomous-agent` 项目的协作规范总览。
> **详细业务逻辑约束将在课题正式定题后补充。**

---

## 1. 分支模型

- `main`：主分支，受保护，**禁止直接推送**。所有变更必须通过 Pull Request（PR）合并。
- 工作分支命名采用 `类型/简短描述` 的形式，全部小写、以连字符分隔：

  | 前缀 | 用途 | 示例 |
  | --- | --- | --- |
  | `feature/*` | 新功能 | `feature/agent-memory` |
  | `fix/*` | 缺陷修复 | `fix/task-timeout` |
  | `refactor/*` | 重构 | `refactor/planner-core` |
  | `docs/*` | 文档 | `docs/contributing-guide` |
  | `chore/*` | 构建 / 脚手架 / 依赖 | `chore/ci-bootstrap` |

- 建议分支生命周期尽量短，合并后及时删除远端工作分支。

## 2. 提交信息规范（Conventional Commits）

提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/) 规范：

```
<type>(<scope>): <subject>
```

- `type`：`feat` / `fix` / `refactor` / `docs` / `test` / `chore` / `perf` / `build` / `ci`
- `scope`（可选）：改动涉及的模块，如 `agent`、`planner`、`memory`、`core`
- `subject`：简明扼要的描述，使用祈使句

**示例：**

```
feat(agent): 新增基于记忆的自主任务规划能力
fix(core): 修复任务超时未被正确回收的问题
docs(readme): 补充本地启动说明
```

## 3. Pull Request 流程

1. 从最新的 `main` 切出符合命名规范的工作分支。
2. 按 `.github/PULL_REQUEST_TEMPLATE.md` 模板填写 PR 描述。
3. 发起 PR 目标分支为 `main`，并指定审查者（见 `.github/CODEOWNERS`）。
4. 合并前置条件：
   - 至少获得 **1** 个 Approve；
   - PR 收到新提交后，历史批准自动失效，需重新审查；
   - CODEOWNERS 中指定的负责人必须参与审查；
   - 禁止 Force Push、禁止删除受保护分支。

## 4. 代码规范

- 保持与现有代码风格一致，提交前通过本地格式检查 / Lint。
- 不提交密钥、Token、个人隐私数据或临时调试代码。
- 新增功能应尽量附带对应测试。

## 5. 待补充（课题正式定题后）

- [ ] 详细业务逻辑约束
- [ ] 各模块的接口契约与目录职责划分
- [ ] 测试覆盖率要求
- [ ] 发布 / 版本管理策略

---
_如有疑问，请在 Issue 或 PR 中提出。_
