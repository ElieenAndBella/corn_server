# Corn Server 项目概要

本文档总结了我们目前已经完成的后端服务的设计要点和功能。

## 核心功能

一个基于 Go (Gin) 的安全验证后端，客户端使用一个长期有效的 Key 来换取一个短期有效的 JWT（JSON Web Token），并使用 JWT 访问受保护的 API。

## 架构与设计

1.  **项目结构**:
    *   代码已经从单个 `main.go` 文件重构为多文件结构，按功能划分到 `handlers.go`, `services.go`, `middleware.go`, `config.go`, `models.go`, `redis.go` 中，使得结构清晰、易于维护。

2.  **认证流程 (`POST /validate`)**:
    *   客户端在 `X-Token` 请求头中提供长期 Key。
    *   服务器验证该 Key，并执行风控检查。
    *   验证成功后，服务器签发一个有效期为 24 小时的 JWT 并返回。

3.  **授权流程 (`/api/*`)**:
    *   客户端在 `Authorization: Bearer <jwt>` 请求头中提供 JWT。
    *   服务器的 JWT 中间件负责验证 JWT 的签名和有效期。

4.  **数据库 (Redis)**:
    *   用于存储长期 Key 的信息（特别是地区绑定）。
    *   用于缓存 IP 地址的地理位置信息，有效期 24 小时。

5.  **配置**:
    *   服务器配置（如 Redis 地址、JWT 签名密钥）通过环境变量加载，并带有合理的默认值，方便在不同环境中部署。

## 安全特性

1.  **地理位置风控**:
    *   一个长期 Key 在首次使用时，会与其当时的地理位置（省-市）进行绑定。
    *   后续所有使用该 Key 的请求，都必须来自同一个地理位置，否则将被拒绝。
    *   支持多个用户在同一地区共享一个 Key。

2.  **API 响应加密**:
    *   所有 `/api/` 下的接口返回的数据都经过了应用层加密。
    *   使用 AES-256-GCM 对称加密算法。
    *   加密密钥直接使用用户请求的**长期 Key** (`X-Token`)。
    *   返回格式为 `{"payload": "...encrypted_data..."}`。

3.  **密钥管理**:
    *   **长期 Key (`X-Token`)**: 建议长度为 32 字节。管理员通过 `redis-cli` 手动添加到 Redis 中，并推荐使用 `EXPIRE` 命令为其设置一个有效期（例如 30 天），以提高安全性。
    *   **JWT 签名密钥 (`JWT_SECRET_KEY`)**: **只在服务器端**使用，永不外泄。用于保证 JWT 不被伪造。

## 如何运行和测试

### 1. Redis Key 管理

所有长期 Key 都作为 Hash 类型存储在 Redis 中。请使用 `redis-cli` 进行管理。

#### 添加新 Key

为新用户生成一个唯一的、32 字节的 Key。然后执行以下命令，为其设置 30 天有效期。

```redis
# 语法: HSET <your-key> location ""
HSET user008-another-key-for-testing location ""

# 语法: EXPIRE <your-key> <seconds>
# 2592000 秒 = 30 天
EXPIRE user008-another-key-for-testing 2592000
```

#### 查询 Key

```redis
# 检查 Key 的所有字段和值
HGETALL user008-another-key-for-testing

# 检查 Key 的剩余有效期 (秒)
TTL user008-another-key-for-testing
```

#### 删除 Key

```redis
DEL user008-another-key-for-testing
```

### 2. 启动后端服务

```bash
go run .
```

### 3. 测试客户端

*   我们编写了一个 Go 语言的客户端示例代码，采用**内存方式**存储获取到的 JWT。
*   客户端完整流程包括：认证 -> 获取加密数据 -> 使用长期 Key 解密数据。