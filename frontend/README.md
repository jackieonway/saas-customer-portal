# 客户空间前端

独立的 React 19、TypeScript 与 Vite 6 页面，只提供统一登录、已有客户身份选择和本人基础资料。它不依赖平台管理宿主、SDK、qiankun、角色菜单或通知组件。

页面采用纸张底色、墨蓝正文与简洁的编辑式排版。桌面端并列展示客户身份与本人资料；窄屏顺序展示。键盘焦点、跳至内容、加载状态、错误提示和减少动态效果均有对应支持。头像字段不会产生外部图片请求。

## 本地命令

依赖版本与工作区平台已锁定版本对齐，另有独立 `package-lock.json`。运行环境为 Node 24.22.1 与 npm 11.x。

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run lint
npm run typecheck
npm run build
npm run dev
```

开发服务器仅绑定 `127.0.0.1:3100`，将 `/auth`、`/api` 和 `/health` 代理到 `127.0.0.1:3101`。通过与后端同源的 HTTPS 反向代理验证完整登录流程；浏览器会话使用 Secure Cookie，直接访问 HTTP 开发服务器不能替代该验证。构建产物位于 `dist/`。部署服务器需对 `/` 和 `/signed-out` 提供页面，并将 `/auth/*`、`/api/*` 保留给门户自己的后端。

## 浏览器与后端合同

| 请求 | 行为 |
| --- | --- |
| `GET /auth/config` | 只接受 `{mode:"BFF"}`；未知模式停止继续请求。 |
| `GET /auth/session` | `portal-session/1`，已登录会话包含账号、客户成员与可选客户上下文。匿名会话为版本 `"0"`、`account:null`、空成员、空上下文以及预登录 CSRF token。 |
| `GET /auth/login-bootstrap` | 仅在用户主动点击继续统一登录或重新确认账号时调用。旧 session Cookie 已失效时仍可返回匿名 `portal-session/1` 与独立 browser CSRF，不能用于普通加载时绕过失效会话。 |
| `POST /auth/login` | 用户主动点击后通过 login-bootstrap 获取 browser CSRF，再提交 `{returnTo:"/"}`；仅接受 HTTPS 登录地址。 |
| `POST /auth/context` | 只提交当前已登记客户成员的 ID 与 `expectedVersion`；结果必须仍属于原账号、精确选中成员且版本递增。 |
| `GET /api/profile` | 沿用 `customer-profile/1` 的 `{context,account}`；必须匹配当前成员、账号、版本、租户、组织和应用。账号代次 `accountVersion` 是从 `"0"` 开始的规范非负 i64 字符串，成员与已登录门户会话版本仍从 `"1"` 开始。 |
| `POST /auth/logout` | 提交 `expectedVersion` 与 `PORTAL` 或 `GLOBAL`，只接受 `{redirectTo:"/signed-out"}`。 |

全部请求携带同源 Cookie，禁止缓存和 HTTP 重定向跟随；全部 POST 携带 `X-CSRF-Token`，由后端同时核验精确 Origin。前端不会保存或发送 OIDC／平台访问或刷新凭据。CSRF token 仅保留于内存。没有浏览器持久存储。

每次加载、切换、注销、跨页失效通知、隐藏页面和恢复焦点，先清除已有个人资料。Abort 与操作代次共同阻止迟到响应恢复旧身份。跨页通过门户专有 BroadcastChannel 发送严格的两字段变更通知，不发送账号、成员、资料或凭据，接收方重新请求服务器。

账号可完成认证但没有客户成员；此时明确显示联系组织管理员的提示，既不自动选择成员，也不创建关系。401 清空所有身份与资料，等待用户主动继续统一登录；503 暂停资料展示并提供手动重试以及明确的重新确认账号入口。失效 session Cookie 不会在普通加载中降级为匿名会话；只有主动继续登录时才调用独立 login-bootstrap。`/signed-out` 即使遇到其他页面较新的登录，也不会自动获取本人资料、bootstrap 或发起登录。

## 验证边界

`npm test` 执行协议、传输和异步状态回归，包括组织／账号／版本混用、伪造成员、401／503、跨页注销、迟到响应、匿名 CSRF 和注销后的显式登录。真实 OIDC、Cookie、安全响应头、服务器权威状态以及同浏览器平台／门户隔离，由阶段 11 的真实端到端验收验证，不能由这些 Node 测试替代。
