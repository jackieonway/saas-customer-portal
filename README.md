# 客户门户

独立的客户登录入口与本人资料页面。客户门户通过同一认证中心完成 OIDC 登录，只选择已存在且有效的 `CUSTOMER` 成员；员工控制台继续使用自己的员工客户端与会话。

平台身份台账 [Phase 11](../saas-plateform/backend/docs/identity-sso/validation/phase-11.md)已完成，真实 Rust／前端门禁、双 RP 登录／刷新／注销、双向成员撤销和故障恢复均通过；[Phase 12](../saas-plateform/backend/docs/identity-sso/validation/phase-12.md)已完成独立认证部署与同库权限治理。当前 [Phase 13](../saas-plateform/backend/docs/identity-sso/validation/phase-13.md)仍为 IN_PROGRESS，完整容量、灰度、身份感知恢复与最终运维验收尚未完成，生产默认开关仍关闭。本工程不提供客户自助注册、角色菜单、订单、工单或客户通知，不复制管理宿主。生产域名、维护人、切流和运维承诺需按实际部署登记。

| 目录 | 职责 |
| --- | --- |
| `backend` | Rust/Axum BFF，独立 PostgreSQL 会话与加密凭据存储，标准 OIDC 客户端及平台资源 HTTP 适配 |
| `frontend` | React/Vite 客户身份选择、当前组织与本人资料，凭据仅由 HttpOnly Cookie 承载 |

门户自己的 OIDC RP secret 仅用于认证中心端点；平台资源调用使用独立登记的 profile 客户端。OIDC token、refresh 和派生客户 context 留在服务器，浏览器只接收最少账号／客户 DTO 和内存 CSRF。两个入口使用独立 Cookie、版本和跨标签页协调命名空间。

各目录可以独立安装、检查和构建；运行配置与接口见目录内 README。部署时使用明确 HTTPS origin、精确 callback、外部密钥文件和独立数据库账号。示例 `.test` 域名仅供任务隔离验证。
