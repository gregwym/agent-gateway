# 设计说明

本文回答五件事：为什么不直接用现成的开源 Gateway、架构是什么、哪些是复用的哪些是自己写的、
身份与凭据隔离的关键风险在哪、以及哪些能力**没有实现或无法保证**。部署约束见
[deployment.md](deployment.md)。

## 1. 结论

- 自己写一个很小的 Gateway（约 1,600 行 Python，含注释），协议、传输、鉴权中间件、加密全部复用成熟库。
- 身份只来自客户端出示的 Bearer Token：一个 Token 对应一个 client，一个 client 对应一个 principal。
- 每个 `(service, account)` 是一条独立的上游连接，只拿到自己账号的凭据。
- 默认拒绝；工具必须同时出现在连接的 `tools` 和某条 `policy` 规则里才存在。
- 上游工具定义经人工审阅后写入 lock 文件；上游改了定义，该工具自动下线，直到重新审阅。
- 审批只有接口和「一律拒绝」的默认实现，`approval_required` 的工具现在**永远不会执行**。
- 真正的安全边界是 **Gateway 运行在哪台机器上**，代码管不了这件事。

## 2. 现成开源方案评估（2026-11）

| 项目 | 形态 | 能直接满足的 | 缺口 |
|---|---|---|---|
| [TBXark/mcp-proxy](https://github.com/TBXark/mcp-proxy) | Go 单二进制，MIT | 每个上游一个路径，各自的 `authTokens`；`toolFilter` 白名单 | 没有「principal」概念（按路径+Token 拼出来）；无定义锁定、无参数固定、无结构化审计、无密钥存储、调用路径上没有审批挂载点 |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust，Apache-2.0 | JWT 鉴权 + CEL 规则按 `jwt.sub` / `mcp.tool.name` 授权，会过滤 `tools/list` | 需要自己签发 JWT；功能面大（A2A、LLM 路由、xDS）；同样没有定义锁定、参数固定和凭据存储 |
| [MCPHub](https://github.com/samanhappy/mcphub) | TypeScript，Apache-2.0 | 用户、分组、Dashboard | 带管理后台和数据库，正是本项目不想要的那部分复杂度 |
| [docker/mcp-gateway](https://github.com/docker/mcp-gateway) | Go，MIT | 容器化运行上游、按 profile 的工具白名单 | 围绕 Docker Desktop MCP Toolkit 和 catalog 设计；没有按调用者的身份隔离 |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | Python，Apache-2.0 | 几乎什么都有 | 企业级体量：RBAC、多租户、插件、Redis/数据库 |
| [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | Python，MIT | stdio ↔ HTTP 传输桥 | 只是桥，没有身份和策略 |

结论：

- 如果只需要「鉴权 + 工具白名单 + 多上游聚合」，**TBXark/mcp-proxy 零代码就够用**，agentgateway 是更重但更完整的选择。这是实话，不必为了用自研而用自研。
- 自研的理由是下面四项在以上项目里都没有，而它们正是本项目的安全要求：
  1. **工具定义锁定**：防上游动态变更（rug pull / 描述投毒），也是「未审阅的工具不会自己出现」的实现方式。
  2. **参数固定与取值限制**：资源级限制（只看家庭日历、只看某个邮箱文件夹）不靠模型自觉。
  3. **只含元数据的审计**：不落邮件正文、不落参数值。
  4. **调用路径上的审批挂载点**：Phase 3 的审批必须绑定最终发往上游的参数，这只能在 Gateway 内部做。
- 代价是要自己维护约 1,600 行代码和一套测试。协议升级由 SDK 承担。

如果以后这四项不再需要，换成 TBXark/mcp-proxy 的迁移成本很低：配置里的 clients / connections / tools 能一一对应过去。

## 3. 架构

```
Agent ──HTTP(Streamable)──► /mcp
                             │ 1 身份      Bearer Token → client → principal（SDK 的鉴权中间件）
                             │ 2 路由      暴露名 → (connection, 上游工具名)
                             │ 3 策略      (principal, tool) → allow / approval_required / deny，默认 deny
                             │ 4 定义      工具必须在 lock 里，且与上游当前定义一致
                             │ 5 参数      按给 Agent 看的 schema 校验；pin 的参数由 Gateway 填入
                             │ 6 审批      approval_required → 询问 Approver（目前一律拒绝）
                             │ 7 上游调用  用该账号自己的凭据；超时、并发上限、结果大小上限
                             │ 8 脱敏      从结果里抹掉已知的密钥值
                             ▼
                    审计日志（每一步的拒绝/放行都记一行元数据）
```

每一步失败都是拒绝。第 2、3 步的拒绝对 Agent 表现为同一个 `Unknown tool`，无法探测别人有哪些工具。

数据模型只有五个概念，全部写在一个 YAML 里：

| 概念 | 含义 |
|---|---|
| principal | `person_a` / `person_b` / `household`，仅此而已，没有角色和组 |
| client | 一份发给某个 Agent 的 Token，绑定一个 principal |
| connection | 一个上游 MCP Server，绑定一个服务的一个账号，有一个 owner |
| tool | 上游工具在 Gateway 上的暴露名，可带 `pin` / `allow_values`；暴露名全局唯一 |
| rule | principals × connection × tools → effect；跨账号授权必须显式写 `cross_account: true` |

「principal + service + account + tool + resource」的映射方式：service 和 account 是 connection 的属性，
resource 用 `pin` / `allow_values` 表达（同一个上游工具可以用不同的暴露名、不同的 pin 暴露多次）。

刻意没有的东西：数据库、管理 API、热加载、Web UI、通配符、角色。改权限 = 在 Gateway 主机上改文件并重启。
Agent 无法通过网络改变 Gateway 的任何状态。

### 模块

| 文件 | 职责 |
|---|---|
| `config.py` | 配置模型和全部交叉校验；未知字段报错 |
| `auth.py` | Token 生成、哈希、常数时间比对；从请求里取调用者 |
| `policy.py` | 把规则预计算成 `(principal, tool) → effect` |
| `lock.py` | 工具定义的规范化、摘要和 lock 文件 |
| `credentials.py` | 加密密钥文件、结果脱敏 |
| `upstream.py` | 每个 connection 一条长连接：连接、校验定义、重连、错误归一化 |
| `server.py` | 两个 MCP handler（`tools/list`、`tools/call`）和 HTTP 应用 |
| `approval.py` | 审批接口和拒绝一切的默认实现 |
| `audit.py` | JSONL 审计日志，字段白名单 |
| `cli.py` | `agw serve / check / lock / token / secret` |

## 4. 复用与自研

| 部分 | 来源 |
|---|---|
| MCP 协议、Streamable HTTP 服务端、stdio / HTTP 客户端、协议版本协商 | 官方 [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) |
| Bearer 鉴权中间件、401 处理、Host/Origin 校验 | SDK（`BearerAuthBackend`、`RequireAuthMiddleware`、`TransportSecuritySettings`） |
| HTTP 服务 | uvicorn + Starlette（SDK 的依赖） |
| 密钥文件加密 | `cryptography` 的 Fernet（AES-128-CBC + HMAC-SHA256），没有自己写任何密码学 |
| 参数校验 | `jsonschema`，使用空 registry，禁止任何远程 `$ref` |
| 配置解析和校验 | pydantic + PyYAML |
| **自己写的** | Token → principal 的映射、策略求值、lock 文件、pin / allow_values 的 schema 改写、上游连接生命周期、错误归一化、脱敏、审计、CLI |
| Phase 2 的 IMAP / CalDAV / Gmail | 由 Connector 使用成熟库或现成 MCP Server，Gateway 不实现任何上游协议 |

## 5. 身份认证的关键风险

1. **共享主机上的 Token 证明不了是谁。** 三个 Agent 都在同一台 Mac mini 上，而 OpenClaw 以高权限运行
   （Full Disk Access）。任何存放在这台机器上的个人 Token，OpenClaw 都可能读到，进而以那个人的身份调用 Gateway。
   Gateway 只能验证「这是哪个 client 的 Token」，验证不了「Token 是不是被别的进程拿走了」。
   **因此：只要个人 Token 和 OpenClaw 在同一台它能读的机器上，两人之间的隔离对 OpenClaw 不成立。**
   可行的做法按强度排列：
   - OpenClaw 只发 `household` 的 client（示例配置就是这样）；
   - 个人 Token 只放在 OpenClaw 读不到的地方：另一台机器，或至少是 OpenClaw 无权访问的独立系统用户；
   - 个人工具保持只读，并接受上述残余风险。
2. **服务两个人的 Bot 由 Bot 自己决定用哪个 Token。** 这一步必须由 Bot 的代码根据已认证的聊天用户来选，
   不能由模型输出决定。Gateway 无法验证这一点；做不到就只给 `household`。
3. **Token 是静态的。** 没有过期时间，不绑定来源主机；泄露即可冒用，直到轮换。缓解手段是 Tailscale ACL
   限制谁能连到 Gateway 端口、审计日志里的 `client` 和 `remote` 字段、以及简单的轮换流程。
4. **没有按请求者的 OAuth。** OpenClaw 支持 `oauth.identity: "per-requester"`，这是让共享 Agent 也能携带
   可验证个人身份的正路，但需要 Gateway 充当 OAuth 授权服务器。Phase 1 没做，原因是复杂度和攻击面都明显增大。
5. **配置文件是信任根。** 能改 `gateway.yaml`、lock 文件或重启 Gateway 的人拥有全部权限。
6. **Gateway 本身不做 TLS。** Token 以明文 HTTP 头传输，必须跑在 Tailscale（WireGuard 加密）上或 TLS 终结之后。

已测试并成立的部分：身份不受工具参数、请求头、Cookie、会话 ID、`_meta` 影响；同一条 HTTP 连接上的不同请求各自鉴权；
无 Token / 错 Token 在进入 MCP 之前就被拒绝并记入审计。

## 6. 凭据隔离的关键风险

1. **主机管理员能拿到一切。** root、docker 组成员、能进入容器的人，都能读到密钥文件和解密后的凭据。
   密钥文件和密文在同一台机器上，加密只防「密文单独外泄」（备份、误提交、快照），不防主机被控制。
2. **stdio Connector 与 Gateway 同权。** 它是 Gateway 的子进程，同一个 UID，能读密钥文件，也就能解开所有账号的凭据。
   一个被投毒的 Connector 依赖 = 全部凭据泄露。Connector 代码必须审阅并锁定版本；
   不想给这种信任的第三方 Connector 应作为独立容器跑、用 HTTP 接入，这样它只持有自己那一份凭据。
3. **只读不是凭据属性。** iCloud 的 App 专用密码没有只读版本，也不区分邮件、日历、通讯录。Gateway 只暴露读工具，
   但 Connector 手里的凭据能写、能删。只有 Gmail 的 `gmail.readonly` 是真正在凭据层只读的。
4. **脱敏只是最后一道网。** 它按已知密钥值做精确匹配（长度 ≥ 6）。经过 base64、分段或换编码的密钥不会被发现。
   正确的防线是 Connector 不把凭据放进结果。
5. **会轮换的凭据需要 Connector 自己保存状态。** Gateway 注入的是静态值。Gmail 的 refresh token 如果被轮换，
   Connector 需要自己的可写存储，这部分存储同样要按凭据对待。
6. **环境变量。** stdio Connector 通过环境变量拿到凭据，同 UID 的进程和 root 能从 `/proc` 读到。
   Gateway 自己的环境变量不会传给 Connector，Connector 之间也互相看不到对方的值。

已测试并成立的部分：Connector 只拿到自己账号的密钥；`tools/list`、401 响应、错误信息、审计日志里没有密钥、Token、
启动命令或参数值；上游起不来时返回固定文案；Connector 把环境变量整个吐出来时，密钥值被替换为 `[REDACTED]`。

## 7. Connector 接口（为 Phase 2 准备）

Connector 不是新的抽象，就是一个普通的 MCP Server，外加四条约定：

1. 一个进程（或一个 URL）只服务一个账号。两个人各用自己的账号 = 两条 connection、两个进程。
2. 凭据由 Gateway 给：stdio 用 `secret_env`，HTTP 用 `bearer_secret` / `secret_headers`。
3. 工具不接受账号、用户或凭据参数。
4. 工具结果里不出现凭据。

[examples/demo_connector.py](../examples/demo_connector.py) 是模板（其中 `debug_dump`、`crash` 等是故意做坏的测试工具，不要照抄）。
接入步骤：加 connection → `agw secret set` → `agw lock` 审阅定义 → 写 policy → 重启。

配置大致是这样（**工具名是占位**，以 `agw lock` 实际列出的为准）：

```yaml
- id: icloud-mail-a
  service: icloud-mail
  account: person_a
  owner: person_a
  transport: stdio
  command: ["icloud-mcp"]
  env: { ICLOUD_USERNAME: "person_a@icloud.com" }
  secret_env: { ICLOUD_APP_PASSWORD: icloud_app_password_a }
  tools:
    - { upstream: search_messages, name: a_mail_search }
    - { upstream: search_messages, name: a_mail_search_family, pin: { mailbox: "Family" } }
```

各服务的已知问题，实现前需要确认：

| 服务 | 路线 | 必须说明的限制 |
|---|---|---|
| iCloud Mail | IMAPS + App 专用密码，每人各自的 Apple ID，不改变现有账号结构 | 密码不是只读的，也不限于邮件；只读只存在于 Gateway 的白名单层 |
| Apple Calendar | CalDAV + App 专用密码 | 同上；建议邮件和日历各用一个 App 专用密码，便于单独吊销（权限范围相同） |
| Apple Reminders | 升级后的 iCloud 提醒事项不走 CalDAV，只能通过登录了该 Apple ID 的 Mac 上的 EventKit | EventKit 对提醒事项只有完全访问；而且需要一台登录个人账号的 Mac，这与「Gateway 主机不受 Agent 控制」冲突。Phase 2 需要先决定这台 Mac 是谁 |
| Gmail | Gmail API + OAuth，`gmail.readonly` | 凭据层真只读。`gmail.readonly` 是受限 scope；OAuth 应用处于 Testing 状态时 refresh token 7 天过期 |

现成的 iCloud MCP Server 里，[eodozzy/icloud-mcp](https://github.com/eodozzy/icloud-mcp)（MIT，体量小，
从环境变量读 App 专用密码，写操作需显式开启）最接近上述约定；它只有一位维护者，用之前要通读代码并锁定版本。
不能因为某个项目「只提供只读工具」就认为它的运行时权限是只读的。

没有可靠个人 API 的平台（Amazon 消费者订单等）不在计划内：不使用逆向接口，不保存浏览器会话。

## 8. 审批（Phase 3 的接口）

现在有的：

- `policy` 的 `approval_required`；
- `ApprovalRequest`：principal、client、tool、connection、account、上游工具名、**最终上游参数的 SHA-256**、请求 ID、创建时间、TTL；
- `Approver` 协议，在参数校验之后、上游调用之前被调用；
- 默认实现 `DenyAllApprover`，一律拒绝；
- 没有任何配置项能换掉它或关闭审批，测试覆盖了这一点。

Gateway 自己不缓存任何批准结果，每次调用都重新询问 Approver，所以单次使用、过期、防重放由 Approver 实现负责。
用测试替身验证过：批准的是 A 参数就只执行 A 参数，改一个字符即拒绝，重放即拒绝。

还没有的（Phase 3 要做的）：待审批请求的存储、带外的人工通道（计划沿用 compose-cd-engine 的 Passkey 方式）、
向用户展示可读的操作摘要、过期和单次使用的真实实现。**在这些完成之前，不存在任何能返回「批准」的代码路径。**

## 9. 尚未实现或无法保证

| 项 | 状态 |
|---|---|
| 防御已取得 Gateway 主机管理员权限的 Agent | **做不到**，只能靠部署约束 |
| 区分共享 Agent 背后是哪个人 | **做不到**，共享连接只给 household |
| 人工审批 | **未实现**，只有接口；`approval_required` = 不执行 |
| 上游凭据层的只读 | 取决于上游；iCloud 做不到，Gmail 可以 |
| 防内容中的 Prompt Injection | **不防**。只保证被误导的模型仍受其 Token 的权限约束 |
| 第三方模型的数据留存 / 匿名性 | **无法保证**。工具结果交给 Agent 之后的去向不在 Gateway 控制内 |
| 结果内容的最小化 | 不做。Connector 返回什么就是什么（仅有大小上限和密钥脱敏） |
| Resources / Prompts / Sampling / Elicitation | 不代理 |
| 嵌套参数、查询字符串内部的资源限制 | 不支持。`pin` / `allow_values` 只作用于顶层参数；上游工具必须把资源做成独立参数 |
| TLS、限流、登录失败锁定 | 没有。Token 是 256 位随机数，暴力猜测不可行；传输加密靠 Tailscale |
| OS Keychain / 外部 Secret Manager | 没有，只有加密文件。`SecretStore` 是一个四个方法的协议，以后可以替换 |
| 主密钥轮换命令 | 没有。重新 `secret init` 并重新录入凭据 |
| 热加载、管理 API | 刻意没有 |

## 10. 安全测试对照

| 要求 | 测试 | 说明 |
|---|---|---|
| 跨用户访问账号 | `test_isolation.py` | 列不出、调不了，拒绝与「不存在」不可区分 |
| 未授权工具调用 | `test_isolation.py`、`test_tools.py` | 未在白名单的上游工具对 Agent 不存在 |
| 通过参数伪造身份 | `test_identity.py` | 参数、请求头、Cookie、会话 ID、`_meta` 都无效 |
| 凭据泄露 | `test_credentials.py` | 结果、列表、错误、审计日志、Connector 环境 |
| 工具名冲突 | `test_tools.py` | 暴露名全局唯一，配置期报错 |
| 上游工具动态变更 | `test_tools.py` | 启动时和运行中的变更都会下线该工具；投毒描述不会到达 Agent |
| SSRF / 任意 URL | `test_upstream.py`、`test_tools.py` | URL 只来自配置；跨源重定向不跟随；schema 远程 `$ref` 被拒 |
| 审批重放 | `test_approval.py` | 仅验证了挂载点的语义，**不是**对一个真实审批系统的测试 |
| Agent 绕过 Gateway | `test_surface.py` | 只验证了暴露面和 Connector 约定；其余是部署约束 |
| 不可信内容中的 Prompt Injection | `test_surface.py` | 只验证了权限不变；Gateway 不过滤内容 |
