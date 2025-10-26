# Corn Server

一个基于 Go (Gin) 的安全后端服务。其核心功能是提供一个安全的认证和数据交换网关，客户端通过一个长期有效的 `X-Token` 来换取一个短期有效的 JWT，并使用该 JWT 访问受保护的、经过加密的 API。

## 核心功能

*   **双层令牌认证**: 长期 Key (`X-Token`) + 短期 JWT。
*   **地理位置风控**: 基于 IP 地址的动态风控，自动封禁异常行为的 Key。
*   **应用层加密**: 所有 API 响应数据均使用基于 `X-Token` 派生的密钥进行 AES-256-GCM 加密。
*   **客户端完整性校验**: 防止未经授权的第三方客户端调用 API。
*   **中心化配置网关**: 通过一个通用 API (`/api/v1/gateway`) 向客户端下发配置和UI元数据。

## 架构与设计

1.  **项目结构**: 代码按功能划分到 `handlers.go`, `services.go`, `middleware.go`, `config.go`, `models.go`, `redis.go` 中，结构清晰、易于维护。
2.  **数据库 (Redis)**:
    *   存储长期 Key 的状态及其风控信息（如绑定的省份和城市列表）。
    *   缓存 IP 地址的地理位置信息，有效期 **120 小时**，以减少对外部 API 的依赖。
3.  **配置**: 通过环境变量加载，并带有合理的默认值，方便在不同环境中部署。

## 认证与授权流程

1.  **认证 (`POST /validate`)**:
    *   客户端在 `X-Token` 请求头中提供长期 Key。
    *   服务器验证该 Key，并执行地理位置风控检查。
    *   成功后，服务器签发一个有效期为 **12 小时** 的 JWT 并返回。

2.  **授权 (`/api/*`)**:
    *   客户端访问所有 `/api/` 下的接口时，必须提供两个 Header：
        1.  `Authorization: Bearer <jwt>`: 用于身份认证。
        2.  `X-Signature` 和 `X-Timestamp`: 用于客户端完整性校验。
    *   服务器通过两个中间件 `authMiddleware` 和 `appIntegrityMiddleware` 对请求进行验证。

## 安全特性

1.  **地理位置风控**:
    *   一个长期 Key 在首次使用时，会永久绑定其当时的 **省份**。
    *   后续使用中，允许该 Key 在此省份下的 **最多三个不同城市** 内使用。
    *   **自动封禁机制**: 一旦检测到有人尝试在绑定的省份之外、或在第四个新城市使用该 Key，系统会自动将此 Key **永久封禁**。（新疆地区有特殊处理）

2.  **API 响应加密**:
    *   所有 `/api/` 接口返回的数据都经过应用层加密。
    *   加密算法: **AES-256-GCM**。
    *   加密密钥派生: 使用 **PBKDF2** 算法，基于用户请求的**长期 Key** (`X-Token`) 和一个随机生成的 `salt` 派生出唯一的加密密钥。
    *   返回格式为 `{"payload": "...base64_encoded_encrypted_data..."}`。

3.  **客户端完整性校验**:
    *   为防止 API 被第三方客户端盗用，所有到 `/api/` 的请求都必须包含 `X-Timestamp` 和 `X-Signature` 头。
    *   `X-Signature` 是对 `请求路径,时间戳,服务器端密钥` 进行 `SHA256` 计算后的签名。
    *   服务器会拒绝时间戳过期或签名无效的请求。

4.  **密钥管理**:
    *   **长期 Key (`X-Token`)**: 建议长度为 32 字节。管理员通过 `redis-cli` 手动添加到 Redis 中，并推荐使用 `EXPIRE` 命令为其设置一个有效期（例如 30 天）。
    *   **JWT 签名密钥 (`JWT_SECRET_KEY`)**: **只在服务器端**使用，永不外泄。用于保证 JWT 不被伪造。
    *   **应用完整性密钥 (`APP_INTEGRITY_SECRET`)**: **只在服务器端**使用，用于生成和校验客户端签名。

## API 端点

### `POST /validate`
用于验证长期 Key 并获取 JWT。

*   **Request Headers**:
    *   `X-Token`: 你的长期 Key。
*   **Success Response (200 OK)**:
    ```json
    {
      "token": "your.jwt.token"
    }
    ```

### `POST /api/v1/gateway`
一个通用的、受保护的网关，用于获取各种配置和数据。

*   **Request Headers**:
    *   `Authorization`: `Bearer your.jwt.token`
    *   `X-Token`: 你的长期 Key (用于解密响应)。
    *   `X-Timestamp`: 当前 Unix 时间戳。
    *   `X-Signature`: 客户端签名。
*   **Request Body**:
    ```json
    {
      "target": "a1",
      "p": "d8a7f1",
      "params": ["param1", "param2"]
    }
    ```
    *   `target`: 必须，用于指定要获取的数据类型 (例如 `a1` 获取主菜单, `c3` 获取配置URL)。
    *   `p`, `params`: 可选，用于传递额外参数。
*   **Success Response (200 OK)**:
    ```json

    {
      "payload": "..."
    }
    ```
    *   `payload` 是加密后的数据，客户端需使用长期 Key 进行解密。

## 如何运行和测试

### 1. 配置环境变量
在启动服务前，请根据需要设置以下环境变量：

| 变量名 | 描述 | 默认值 |
| --- | --- | --- |
| `REDIS_ADDRESS` | Redis 服务器地址 | `localhost:6379` |
| `REDIS_PASSWORD` | Redis 密码 | (空) |
| `REDIS_DB` | Redis 数据库编号 | `0` |
| `JWT_SECRET_KEY` | 用于签发 JWT 的密钥 | `your-super-secret-jwt-key` |
| `APP_INTEGRITY_SECRET` | 用于客户端完整性校验的密钥 | `a-very-secret-string-for-app-integrity` |

### 2. Redis Key 管理
所有长期 Key 都作为 Hash 类型存储在 Redis 中。请使用 `redis-cli` 进行管理。

#### 添加新 Key
新的 Key 结构包含 `province` 和 `cities` 两个字段，初始值都应为空字符串。

```redis
# 语法: HSET <your-key> province "" cities ""
HSET your-new-key-here province "" cities ""

# 强烈建议为其设置一个有效期 (例如 30 天)
EXPIRE your-new-key-here 2592000
```

#### Key 的封禁与解封
风控系统会自动封禁违规的 Key。如果需要手动操作，可以通过 `status` 字段进行管理。

```redis
# 手动封禁一个 Key
HSET your-key-here status "banned"

# 解封一个 Key
HDEL your-key-here status
```

### 3. 启动后端服务

```bash
go run .
```
服务将启动在 `:3839` 端口。

### 4. 测试客户端
项目中的 `client_example_test.go` 提供了一个完整的客户端测试流程，包括：
1.  使用长期 Key 调用 `/validate` 获取 JWT。
2.  使用 JWT 和签名头调用 `/api/v1/gateway` 获取加密数据。
3.  在客户端使用长期 Key 解密 `payload`，得到原始数据。
