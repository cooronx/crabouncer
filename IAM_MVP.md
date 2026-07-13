# Cedar + Rust IAM Server — 第一版 MVP 范围说明

## 1. 项目目标

第一版目标不是完整复刻 Casdoor，而是实现一个最小但完整可用的 IAM Server。

系统需要具备以下核心能力：

1. 管理组织、用户和应用。
2. 支持本地用户名和密码登录。
3. 作为 OIDC Provider，为外部应用提供统一登录能力。
4. 使用 Cedar 管理角色和权限策略。
5. 向业务系统提供统一授权接口。
6. 记录关键登录、管理和授权操作。

第一版最终应能够完成以下完整流程：

```text
管理员创建组织
        ↓
管理员创建用户
        ↓
管理员创建应用
        ↓
业务应用通过 OIDC 跳转到 IAM 登录
        ↓
用户登录成功
        ↓
业务应用获得 ID Token 和 Access Token
        ↓
业务应用调用 IAM 授权接口
        ↓
Cedar 返回 Allow 或 Deny
```

---

## 补充：IAM server的角色模型

### System Admin

平台级管理员，可以管理整个 IAM Server。只有一个，第一次启动的时候，账户名为crabouncer，密码设置为默认的123456

职责示例：

- 创建、禁用和恢复组织
- 管理全局用户
- 管理系统配置
- 恢复组织所有权

### Organization Owner

组织唯一拥有者，语义类似“群主”。

职责示例：

- 修改或删除组织
- 转让组织所有权
- 添加或撤销 Organization Admin
- 管理组织成员
- 管理组织下的 Application、OAuth Client 和 Policy

每个组织只能有一个 Owner。

### Organization Admin

由 Owner 委派的组织管理员，语义类似“群管理员”。

职责示例：

- 邀请和移除普通成员
- 管理组织下的 Application
- 管理 OAuth Client
- 管理组织业务 Policy

默认不能：

- 删除组织
- 转让组织
- 修改 Owner
- 添加或撤销其他 Admin

每个组织可以有多个 Admin。

### Organization Member

普通组织成员，只能使用被授权的组织资源，没有组织管理权限。

# 2. 第一版范围

## 2.1 Organization：组织管理

第一版支持基础多租户模型。

必须实现：

- 创建组织。
- 查看组织列表。
- 查看组织详情。
- 修改组织名称和显示名称。
- 启用或禁用组织。

核心字段：

```text
Organization
├── id
├── name
├── display_name
├── status
├── created_at
└── updated_at
```

范围约束：

- 所有用户、角色、应用和策略必须归属于某个组织。
- 第一版不实现复杂组织层级。
- 第一版不支持组织之间的资源共享。

---

## 2.2 User：用户管理

第一版只支持本地用户。

必须实现：

- 管理员创建用户。
- 查看用户列表。
- 查看用户详情。
- 修改用户名、邮箱和显示名称。
- 启用或禁用用户。
- 管理员重置用户密码。
- 用户使用用户名和密码登录。
- 用户退出登录。
- 用户查看自己的基础信息。

核心字段：

```text
User
├── id
├── organization_id
├── username
├── email
├── display_name
├── status
├── created_at
└── updated_at
```

密码要求：

- 使用 Argon2id 保存密码 Hash。
- 禁止保存明文密码。
- 密码 Hash 单独存放在凭据表中。

第一版不实现：

- 用户自助注册。
- 邮箱验证。
- 手机号验证。
- 忘记密码。
- GitHub 登录。
- Google 登录。
- LDAP。
- MFA。
- TOTP。
- WebAuthn。
- Passkey。

---

## 2.3 Session：IAM 管理端登录会话

IAM 自身的管理页面使用服务端 Session。

必须实现：

- 用户登录后创建 Session。
- Session 保存在 PostgreSQL。
- 浏览器通过 Cookie 保存 Session ID。
- 用户退出时删除或失效 Session。
- Session 到期后自动失效。

Cookie 要求：

```text
HttpOnly = true
Secure = true
SameSite = Lax
```

核心字段：

```text
Session
├── id_hash
├── user_id
├── expires_at
├── created_at
├── ip
└── user_agent
```

范围约束：

- 第一版不使用 Redis。
- 第一版不实现多设备会话管理页面。
- 第一版不实现管理员强制下线所有设备。

---

## 2.4 Application：接入应用管理

管理员可以创建需要接入 IAM 的业务应用。

必须实现：

- 创建应用。
- 查看应用列表。
- 查看应用详情。
- 修改应用名称。
- 启用或禁用应用。
- 配置 Redirect URI。
- 配置允许使用的 Scope。
- 生成 Client ID。
- 生成 Client Secret。
- 重置 Client Secret。

核心字段：

```text
Application
├── id
├── organization_id
├── name
├── client_id
├── client_secret_hash
├── redirect_uris
├── allowed_scopes
├── access_token_ttl
├── enabled
├── created_at
└── updated_at
```

安全要求：

- Client Secret 只在创建或重置时展示一次。
- 数据库只保存 Client Secret 的 Hash。
- Redirect URI 必须精确匹配。
- 第一版不支持 Redirect URI 通配符。

---

## 2.5 OIDC Provider：统一登录

第一版必须能够作为标准 OIDC Provider 使用。

必须实现以下 Endpoint：

```http
GET /.well-known/openid-configuration

GET /.well-known/jwks.json

GET /oauth/authorize

POST /oauth/token

GET /oauth/userinfo

POST /logout
```

第一版只实现：

```text
Authorization Code Flow
+
PKCE S256
+
Refresh Token
```

必须支持的 Scope：

```text
openid
profile
email
```

Token 类型：

### ID Token

- 使用 JWT。
- 默认有效期 15 分钟。
- 包含用户身份信息。

### Access Token

- 使用 JWT。
- 默认有效期 15 分钟。
- 用于调用 UserInfo 和授权接口。

### Refresh Token

- 使用高强度随机字符串。
- 默认有效期 30 天。
- 数据库只保存 Hash。
- 每次刷新必须执行 Refresh Token Rotation。

JWT 最低要求：

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-id",
  "aud": "client-id",
  "org": "organization-id",
  "scope": "openid profile email",
  "iat": 1783650000,
  "exp": 1783650900
}
```

签名要求：

- 第一版使用 RS256。
- 私钥必须持久化。
- 公钥通过 JWKS Endpoint 暴露。
- 禁止服务每次重启都重新生成密钥。

第一版不实现：

- Implicit Flow。
- Resource Owner Password Grant。
- Device Authorization Flow。
- Client Credentials Flow。
- SAML。
- CAS。
- SCIM。
- 上游第三方 OAuth 登录。

---

## 2.6 Role：角色管理

第一版采用简单 RBAC 模型。

必须实现：

- 创建角色。
- 查看角色列表。
- 修改角色。
- 删除角色。
- 将用户加入角色。
- 从角色中移除用户。
- 查看用户拥有的角色。

核心字段：

```text
Role
├── id
├── organization_id
├── name
├── display_name
├── created_at
└── updated_at
```

用户和角色关系：

```text
UserRole
├── user_id
└── role_id
```

范围约束：

- 第一版不实现嵌套角色。
- 第一版不实现角色继承。
- 第一版不实现跨组织角色。

---

## 2.7 Cedar Schema 管理

每个 Application 拥有独立的 Cedar Schema。

必须实现：

- 查看应用当前 Schema。
- 修改 Schema。
- 保存前解析 Schema。
- 保存前验证 Schema。
- 保存 Schema 版本号。
- 记录更新时间。

核心字段：

```text
CedarSchema
├── application_id
├── source
├── version
└── updated_at
```

范围约束：

- 第一版每个应用只有一个当前生效 Schema。
- 第一版可以保留历史版本，但不需要实现复杂版本回滚界面。

---

## 2.8 Cedar Policy 管理

每个 Application 拥有独立的 Cedar Policy 集合。

必须实现：

- 创建 Policy。
- 查看 Policy 列表。
- 查看 Policy 内容。
- 修改 Policy。
- 启用或禁用 Policy。
- 删除 Policy。
- 发布 Policy。
- 保存前执行 Cedar Parse。
- 保存前执行 Schema Validation。
- 返回明确的语法错误和验证错误。

核心字段：

```text
CedarPolicy
├── id
├── application_id
├── name
├── source
├── enabled
├── version
├── created_at
└── updated_at
```

示例 Policy：

```cedar
permit (
    principal in Role::"developer",
    action == Action::"document.read",
    resource
);
```

第一版不实现：

- 可视化 Policy Builder。
- 拖拽式权限编辑器。
- 自动生成复杂 Cedar Policy。
- Policy Git 同步。
- Policy 审批流。

---

## 2.9 Authorization API：统一授权接口

业务应用通过统一接口请求权限判断。

Endpoint：

```http
POST /api/v1/authorize
Authorization: Bearer <access_token>
```

请求示例：

```json
{
  "action": {
    "type": "Action",
    "id": "document.update"
  },
  "resource": {
    "type": "Document",
    "id": "document-100"
  },
  "context": {
    "ip": "192.168.1.1"
  },
  "entities": [
    {
      "uid": {
        "type": "Document",
        "id": "document-100"
      },
      "attrs": {
        "ownerId": "user-001"
      },
      "parents": []
    }
  ]
}
```

授权流程：

```text
验证 Access Token
        ↓
从 Token 获取当前用户
        ↓
读取用户当前拥有的角色
        ↓
构造 Cedar Principal 和 Entities
        ↓
加载当前 Application 的 Schema 和 Policy
        ↓
执行 Cedar Authorizer
        ↓
返回 Allow 或 Deny
```

返回示例：

```json
{
  "decision": "Allow",
  "reasons": [
    "developer-update-document"
  ],
  "errors": []
}
```

或：

```json
{
  "decision": "Deny",
  "reasons": [],
  "errors": []
}
```

重要设计约束：

- 用户角色不要永久写死在 Access Token 中。
- 每次授权时读取用户当前角色。
- 用户角色被移除后，不需要重新登录，新的授权请求应立即生效。

---

## 2.10 Audit Log：审计日志

第一版记录关键安全和管理操作。

必须记录：

```text
LOGIN_SUCCESS
LOGIN_FAILED
LOGOUT

USER_CREATED
USER_UPDATED
USER_DISABLED
PASSWORD_RESET

APPLICATION_CREATED
APPLICATION_UPDATED
CLIENT_SECRET_RESET

ROLE_CREATED
ROLE_UPDATED
ROLE_ASSIGNED
ROLE_REMOVED

SCHEMA_UPDATED

POLICY_CREATED
POLICY_UPDATED
POLICY_ENABLED
POLICY_DISABLED
POLICY_PUBLISHED
POLICY_DELETED

AUTHORIZATION_ALLOW
AUTHORIZATION_DENY
```

核心字段：

```text
AuditLog
├── id
├── organization_id
├── actor_id
├── action
├── resource_type
├── resource_id
├── metadata
├── ip
└── created_at
```

范围约束：

- 第一版允许同时记录 Allow 和 Deny。
- 第一版不做复杂日志分析。
- 第一版不做日志告警。
- 第一版不做 SIEM 集成。

---

# 3. 第一版管理后台页面

第一版 Web 管理后台只需要实现以下页面：

```text
/login

/dashboard

/organizations

/users

/applications

/roles

/policies

/audit-logs
```

Policy 页面至少支持：

- Cedar 源码编辑。
- 基础语法高亮。
- Parse。
- Schema Validation。
- 显示错误位置。
- 测试授权请求。
- 发布 Policy。

推荐使用：

```text
Next.js
+
Monaco Editor
```

第一版不实现：

- 可视化关系图。
- 拖拽式角色管理。
- 图形化 Cedar Builder。
- 多主题系统。
- 复杂仪表盘。

---

# 4. 第一版数据库表

建议第一版控制在以下表：

```text
organizations

users

user_credentials

roles

user_roles

applications

sessions

authorization_codes

refresh_tokens

cedar_schemas

cedar_policies

audit_logs
```

共 12 张核心表。

---

# 5. 推荐技术栈

后端：

```text
Rust
Axum
Tokio
SQLx
PostgreSQL
Cedar Policy
```

推荐依赖：

```toml
axum

tokio

tower-http

serde

serde_json

sqlx

uuid

time

argon2

rand

jsonwebtoken

cedar-policy

tracing

tracing-subscriber

thiserror

validator

utoipa
```

前端：

```text
Next.js
TypeScript
Monaco Editor
```

第一版不需要：

```text
Redis
Kafka
NATS
微服务
Kubernetes
Elasticsearch
```

---

# 6. 推荐项目结构

```text
iam/
├── Cargo.toml
│
├── core/
│   ├── Cargo.toml
│   ├── migrations/
│   └── src/
│       ├── main.rs
│       │
│       ├── identity/
│       │   ├── user.rs
│       │   ├── organization.rs
│       │   ├── role.rs
│       │   └── password.rs
│       │
│       ├── session/
│       │   ├── cookie.rs
│       │   └── service.rs
│       │
│       ├── oidc/
│       │   ├── authorize.rs
│       │   ├── token.rs
│       │   ├── discovery.rs
│       │   ├── jwks.rs
│       │   └── userinfo.rs
│       │
│       ├── authorization/
│       │   ├── cedar.rs
│       │   ├── entities.rs
│       │   ├── policy.rs
│       │   └── schema.rs
│       │
│       ├── application/
│       │
│       ├── audit/
│       │
│       ├── api/
│       │
│       └── infra/
│           ├── database.rs
│           └── config.rs
│
└── web/
    ├── package.json
    └── src/
```

架构约束：

- 第一版使用模块化单体。
- 不拆微服务。
- 所有模块共享一个 PostgreSQL。
- Cedar Authorizer 直接以内嵌 Rust 库方式运行。

---

# 7. 第一版明确不做的功能

以下功能全部推迟到后续版本：

## 身份相关

- 用户自助注册。
- 邮箱验证。
- 手机号验证。
- 忘记密码。
- GitHub 登录。
- Google 登录。
- 企业微信登录。
- LDAP。
- Active Directory。
- MFA。
- TOTP。
- WebAuthn。
- Passkey。

## 协议相关

- SAML。
- CAS。
- SCIM。
- Device Flow。
- Client Credentials Flow。
- Implicit Flow。
- Password Grant。

## 权限相关

- 嵌套角色。
- 角色继承。
- 跨组织权限。
- 可视化 Cedar Builder。
- Cedar 策略审批流。
- GitOps Policy。
- 多阶段 Policy 发布。

## 运维相关

- 微服务。
- Redis。
- 消息队列。
- 多数据中心。
- 高可用集群。
- Kubernetes 部署。
- SIEM 集成。
- 实时安全告警。

---

# 8. MVP 验收标准

第一版完成后，必须通过以下场景。

## 场景一：管理员管理身份

```text
管理员登录 IAM
        ↓
创建 Organization
        ↓
创建 Alice 用户
        ↓
创建 editor 角色
        ↓
将 Alice 加入 editor
```

验收结果：

- Alice 可以正常登录。
- Alice 可以查看自己的基础资料。
- 管理员可以禁用 Alice。
- Alice 被禁用后不能继续登录。

---

## 场景二：业务应用通过 OIDC 登录

```text
管理员创建 Application
        ↓
获得 Client ID 和 Client Secret
        ↓
配置 Redirect URI
        ↓
打开 Next.js Demo
        ↓
跳转到 IAM 登录
        ↓
Alice 登录
        ↓
IAM 返回 Authorization Code
        ↓
Demo 使用 Code + PKCE 换 Token
        ↓
Demo 验证 ID Token
        ↓
页面显示 Alice 的身份信息
```

验收结果：

```text
Hello Alice
```

---

## 场景三：Cedar 授权

创建 Policy：

```cedar
permit (
    principal in Role::"editor",
    action == Action::"document.update",
    resource
);
```

调用：

```text
document.update
```

验收结果：

```json
{
  "decision": "Allow"
}
```

随后移除 Alice 的 editor 角色。

再次调用：

```text
document.update
```

验收结果：

```json
{
  "decision": "Deny"
}
```

并且：

- 不要求 Alice 重新登录。
- 不要求重新签发 Access Token。
- 新权限立即生效。

---

## 场景四：Policy 校验

管理员提交错误 Cedar Policy。

验收结果：

- 系统拒绝发布。
- 返回语法或 Schema Validation 错误。
- 显示错误位置。
- 已发布的旧 Policy 不受影响。

---

## 场景五：审计日志

完成登录、创建用户、分配角色和授权请求。

验收结果：

管理员能够查看：

```text
LOGIN_SUCCESS
USER_CREATED
ROLE_ASSIGNED
POLICY_PUBLISHED
AUTHORIZATION_ALLOW
AUTHORIZATION_DENY
```

---

# 9. 第一版最终定义

第一版可以用一句话描述：

> 一个基于 Rust、Axum、PostgreSQL 和 Cedar 的模块化 IAM Server，支持组织、用户、本地密码登录、OIDC Authorization Code + PKCE、应用管理、角色管理、Cedar Schema/Policy 管理、统一授权 API 和审计日志。

只要以上能力全部完成，第一版 MVP 即可视为完成。
