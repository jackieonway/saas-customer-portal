# 客户门户

独立客户 OIDC BFF 与本人资料入口。门户使用认证中心 canonical `/oauth/*` 及独立客户私有证明，公开 subject 保持 opaque，内部账号 ID 仅来自受认证证明。客户在同一认证中心登录后，只选择真实有效的 CUSTOMER 成员；员工控制台继续使用自己的员工 RP 与会话。

后端在独立 PostgreSQL 数据库执行 `backend/migrations/0001_customer_portal.sql`，服务端加密保存上游凭据。浏览器只持有 HttpOnly Cookie、最小 DTO 与内存 CSRF，不保存 OIDC access/refresh 或派生资源 token。

门户 RP secret 仅用于认证中心；平台本人资料调用使用独立登记的 profile 客户端。两个入口的 Cookie、版本和跨标签页命名空间独立，成员与账号撤销按原始证明实时生效。

本系统提供登录、客户身份选择、当前组织与本人资料，不提供自助注册、员工角色菜单或完整业务后台。HTTPS origin、精确 callback、CA、外部密钥和独立数据库账号由实际部署配置。

[backend](backend/README.md)与[frontend](frontend/README.md)独立安装、检查与构建。新数据库与平台/身份的归属见[全新安装](../saas-plateform/backend/docs/fresh-installation.md)。旧阶段验收与历史环境数据不作为当前部署配置。
