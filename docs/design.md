# 设计说明

本文回答五件事：为什么不直接用现成的开源 Gateway、架构是什么、哪些是复用的哪些是自己写的、
身份与凭据隔离的关键风险在哪、以及哪些能力**没有实现或无法保证**。部署约束见
[deployment.md](deployment.md)。

## 1. 结论

- 自己实现家庭账号隔离、审批、可选网页管理和连接器封装。
  协议、传输、鉴权中间件、加密、WebAuthn、IMAP、CalDAV 全部复用成熟库。
- 身份只来自客户端出示的 Bearer Token：一个 Token 对应一个 client，一个 client 对应一个 principal。
- 每个 `(service, account)` 是一条独立的上游连接，只拿到自己账号的凭据。
- 默认拒绝；工具必须同时出现在连接的 `tools` 和某条 `policy` 规则里才存在。
- 上游工具定义经人工审阅后写入 lock 文件；上游改了定义，该工具自动下线，直到重新审阅。
- 自带四个只读 Connector：iCloud Mail（IMAP）、iCloud 日历（CalDAV）、Gmail（REST + OAuth）、
  Apple 提醒事项（EventKit，实验性）。**只有 Gmail 的只读是凭据层的**，见 7.3。
- 写操作走 Passkey 审批：每一次调用都要账号所有者对**那一次调用的确切内容**做一次 Passkey 验证，批准只能用一次。
  没有配置审批页面时，`approval_required` 的工具永远不会执行。目前没有任何自带的写工具。
- 真正的安全边界是 **Gateway 运行在哪台机器上**，代码管不了这件事。
- **Connector 和审批都只对本地的替身服务测试过**（见第 10 节），没有连过真实的 iCloud、Google 账号，
  真实 Chromium 加虚拟认证器已覆盖注册、管理和审批；实体认证器尚未实测。真实账号的检查清单见 [deployment.md](deployment.md)。

## 2. 现成开源方案评估（2026-11）

| 项目 | 形态 | 能直接满足的 | 缺口 |
|---|---|---|---|
| [TBXark/mcp-proxy](https://github.com/TBXark/mcp-proxy) | Go 单二进制，MIT | 每个上游一个路径，各自的 `authTokens`；`toolFilter` 白名单 | 没有「principal」概念（按路径+Token 拼出来）；无定义锁定、无参数固定、无结构化审计、无密钥存储、调用路径上没有审批挂载点 |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust，Apache-2.0 | JWT 鉴权 + CEL 规则按 `jwt.sub` / `mcp.tool.name` 授权，会过滤 `tools/list` | 需要自己签发 JWT；功能面大（A2A、LLM 路由、xDS）；同样没有定义锁定、参数固定和凭据存储 |
| [MCPHub](https://github.com/samanhappy/mcphub) | TypeScript，Apache-2.0 | 用户、分组、Dashboard | 仍需验证账号隔离、工具定义锁定与精确调用审批的语义 |
| [docker/mcp-gateway](https://github.com/docker/mcp-gateway) | Go，MIT | 容器化运行上游、按 profile 的工具白名单 | 围绕 Docker Desktop MCP Toolkit 和 catalog 设计；没有按调用者的身份隔离 |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | Python，Apache-2.0 | 几乎什么都有 | 企业级体量：RBAC、多租户、插件、Redis/数据库 |
| [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | Python，MIT | stdio ↔ HTTP 传输桥 | 只是桥，没有身份和策略 |

结论：

- 如果只需要「鉴权 + 工具白名单 + 多上游聚合」，**TBXark/mcp-proxy 零代码就够用**，agentgateway 是更重但更完整的选择。这是实话，不必为了用自研而用自研。
- 自研的理由是下面四项在以上项目里都没有，而它们正是本项目的安全要求：
  1. **工具定义锁定**：防上游动态变更（rug pull / 描述投毒），也是「未审阅的工具不会自己出现」的实现方式。
  2. **参数固定与取值限制**：资源级限制（只看家庭日历、只看某个邮箱文件夹）不靠模型自觉。
  3. **只含元数据的审计**：不落邮件正文、不落参数值。
  4. **调用路径上的审批**：批准必须绑定最终发往上游的参数，这只能在 Gateway 内部做。
- 代价是要自己维护这些代码和一套测试。协议升级由 SDK 承担。

如果以后这四项不再需要，换成 TBXark/mcp-proxy 的迁移成本很低：配置里的 clients / connections / tools 能一一对应过去。

## 3. 架构

```
Agent ──HTTP(Streamable)──► /mcp
                             │ 1 身份      Bearer Token → client → principal（SDK 的鉴权中间件）
                             │ 2 路由      暴露名 → (connection, 上游工具名)
                             │ 3 策略      (principal, tool) → allow / approval_required / deny，默认 deny
                             │ 4 定义      工具必须在 lock 里，且与上游当前定义一致
                             │ 5 参数      按给 Agent 看的 schema 校验；pin 的参数由 Gateway 填入
                             │ 6 审批      approval_required → 这一次调用有没有一份未用过的批准（第 8 节）
                             │ 7 上游调用  用该账号自己的凭据；超时、并发上限、结果大小上限
                             │ 8 脱敏      从结果里抹掉已知的密钥值
                             ▼
                    审计日志（每一步的拒绝/放行都记一行元数据）

人（浏览器）──HTTPS──► /approvals/…   只在配置了 approvals 时存在；用 Passkey 决定，不用 Token
```

每一步失败都是拒绝。第 2、3 步的拒绝对 Agent 表现为同一个 `Unknown tool`，无法探测别人有哪些工具。

网页管理使用家庭模型：`households` 是家庭，`members` 是有姓名和家庭归属的个人，`clients` 是有家庭归属的 Agent。
连接的 owner 是成员或家庭。`policy.clients × connection × tools` 决定 Agent 的权限；家庭不是被授权主体，成员关系没有权限继承。
个人连接由 owner 审批，家庭共享连接由该家庭的成员审批。一个 Agent 的授权适用于其全部调用，Token 不证明当前聊天人的身份。
成员的 `name` 是唯一对外姓名，内部 `id` 仅用来维持凭据和关联关系。

以下是保留兼容的旧版 YAML 模型；启用网页后会按每个现有 Agent 的实际权限转换，不向新 Agent 继承这些规则：

| 概念 | 含义 |
|---|---|
| principal | `person_a` / `person_b` / `household`，仅此而已，没有角色和组 |
| client | 一份发给某个 Agent 的 Token，绑定一个 principal |
| connection | 一个上游 MCP Server，绑定一个服务的一个账号，有一个 owner |
| tool | 上游工具在 Gateway 上的暴露名，可带 `pin` / `allow_values`；暴露名全局唯一 |
| rule | principals × connection × tools → effect；跨账号授权必须显式写 `cross_account: true` |

「principal + service + account + tool + resource」的映射方式：service 和 account 是 connection 的属性，
resource 用 `pin` / `allow_values` 表达（同一个上游工具可以用不同的暴露名、不同的 pin 暴露多次）。

默认仍是 YAML + 重启。显式配置 `admin` 后，`/admin/` 提供 Passkey 管理员会话和受保护的管理 API。
管理员由主机配置的 `admin.owner` 指定，普通家庭成员、MCP Token、Tailscale 可达性都不授予管理角色。
SQLite 保存审批、公钥和管理员会话；`admin.enc` 加密保存网页修改的配置、凭据和工具锁。
Agent 通过 MCP 能改变的管理状态仍只有发起待审批请求（每个 client 同时最多 5 个）。

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
| `approval.py` | 审批接口（`ApprovalRequest`、`Approver`）和拒绝一切的默认实现 |
| `passkey.py`、`static/` | Passkey 审批：请求的存储、WebAuthn 验证、审批页面 |
| `audit.py` | JSONL 审计日志，字段白名单 |
| `cli.py` | `agw serve / check / lock / token / secret / approval` |
| `admin*.py`、`static/admin.*` | 一次性初始化、Passkey 管理会话、成员和 Token、连接器目录、Google 网页授权、权限编辑 |
| `runtime.py` | 等待在途 MCP 请求结束，原子切换有效配置；Token 鉴权在相同读取租约内 |
| `connectors/` | 自带的 Connector，每个是一个独立进程；Gateway 核心不引用它们 |

## 4. 复用与自研

| 部分 | 来源 |
|---|---|
| MCP 协议、Streamable HTTP 服务端、stdio / HTTP 客户端、协议版本协商 | 官方 [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) |
| Bearer 鉴权中间件、401 处理、Host/Origin 校验 | SDK（`BearerAuthBackend`、`RequireAuthMiddleware`、`TransportSecuritySettings`） |
| HTTP 服务 | uvicorn + Starlette（SDK 的依赖） |
| 密钥文件加密 | `cryptography` 的 Fernet（AES-128-CBC + HMAC-SHA256），没有自己写任何密码学 |
| 参数校验 | `jsonschema`，使用空 registry，禁止任何远程 `$ref` |
| 配置解析和校验 | pydantic + PyYAML |
| WebAuthn（挑战、签名、origin 校验） | Yubico 的 [`fido2`](https://github.com/Yubico/python-fido2) |
| IMAP 协议、TLS | [`IMAPClient`](https://github.com/mjs/imapclient) + 标准库 `ssl` |
| 邮件解析（MIME、编码、附件） | 标准库 `email` |
| CalDAV 协议、重复事件展开 | [`caldav`](https://github.com/python-caldav/caldav)（及其依赖 `icalendar`、`recurring-ical-events`） |
| Gmail | Gmail REST API，经 SDK 自带的 HTTP 客户端 `httpx2`；授权流程用 Google 的 `google-auth-oauthlib`（只在取 Token 的那一次） |
| 提醒事项 | macOS EventKit，经 `pyobjc` |
| **自己写的** | Token → principal 的映射、策略求值、lock 文件、pin / allow_values 的 schema 改写、上游连接生命周期、错误归一化、脱敏、审计、CLI；审批请求的状态机和页面；四个 Connector 里「把库的调用包成几个只读工具」的那一层 |

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
   可验证个人身份的正路，但需要 Gateway 充当 OAuth 授权服务器。没有做，原因是复杂度和攻击面都明显增大。
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
   自带的 Connector 也在这条规则之内：`caldav` 这一个库带进来大约 18 个间接依赖（见 `requirements.txt`），
   它们都以 Gateway 的权限运行。版本和哈希是锁定的，但没有逐个审阅过。
3. **只读不是凭据属性。** 见 7.3。
4. **脱敏只是最后一道网。** 它按已知密钥值做精确匹配（长度 ≥ 6）。经过 base64、分段或换编码的密钥不会被发现。
   正确的防线是 Connector 不把凭据放进结果。
5. **Gateway 注入的是静态值。** Gmail Connector 用存好的 refresh token 换取短期 access token，access token 只在内存里，
   不落盘。按 Google 的文档，这类 refresh token 在刷新时不会被更换，所以 Connector 不需要可写存储；如果 Google 改为轮换，
   这个设计就不够了（Connector 会报授权失效，需要人重新授权）。
6. **环境变量。** stdio Connector 通过环境变量拿到凭据，同 UID 的进程和 root 能从 `/proc` 读到。
   Gateway 自己的环境变量不会传给 Connector，Connector 之间也互相看不到对方的值。

已测试并成立的部分：Connector 只拿到自己账号的密钥；`tools/list`、401 响应、错误信息、审计日志里没有密钥、Token、
启动命令或参数值；上游起不来时返回固定文案；Connector 把环境变量整个吐出来时，密钥值被替换为 `[REDACTED]`。

## 7. Connector

### 7.1 约定

Connector 不是新的抽象，就是一个普通的 MCP Server，外加四条约定：

1. 一个进程（或一个 URL）只服务一个账号。两个人各用自己的账号 = 两条 connection、两个进程。
2. 凭据由 Gateway 给：stdio 用 `secret_env`，HTTP 用 `bearer_secret` / `secret_headers`。
3. 工具不接受账号、用户或凭据参数。
4. 工具结果里不出现凭据。

[examples/demo_connector.py](../examples/demo_connector.py) 是模板（其中 `debug_dump`、`crash` 等是故意做坏的测试工具，不要照抄）。
接入步骤：加 connection → `agw secret set` → `agw lock` 审阅定义 → 写 policy → 重启。

### 7.2 自带的 Connector

以 `python -m agent_gateway.connectors.<模块>` 启动，完整的两人配置见
[deploy/gateway.household.example.yaml](../deploy/gateway.household.example.yaml)。

| 模块 | 服务 | 工具 | 凭据 | 只读成立在哪一层 |
|---|---|---|---|---|
| `imap_mail` | iCloud Mail（任何 IMAP 服务器） | `list_mailboxes`、`search_messages`、`get_message`、`get_attachment` | App 专用密码 | 只在 Connector 发出的命令这一层 |
| `caldav_calendar` | iCloud 日历（任何 CalDAV 服务器） | `list_calendars`、`list_events`、`get_event`、`check_conflicts` | App 专用密码 | 只在 Connector 发出的请求这一层 |
| `gmail` | Gmail | `search_messages`、`get_message`、`get_attachment` | OAuth refresh token，scope 只有 `gmail.readonly` | **凭据层**，由 Google 强制 |
| `reminders_eventkit` | Apple 提醒事项（实验性，见 7.6） | `list_lists`、`list_reminders`、`get_reminder` | 没有凭据；macOS 对「提醒事项」的完全访问授权 | 只在 Connector 的代码这一层 |

对任务书各项要求的实现方式：

- **不做全量邮箱索引。** 每次调用都是对服务器的一次搜索或读取，本地不存任何邮件。搜索由服务器执行（IMAP `SEARCH`、Gmail 的查询语法）。
- **完整正文。** `get_message` 返回纯文本正文（只有 HTML 的邮件会转成文本，也可以要原始 HTML），长邮件用
  `offset` / `max_chars` 分段读完。HTML 转文本只是为了可读，**不是**内容过滤。
- **附件。** `get_message` 列出附件，`get_attachment` 按序号取：文本类直接返回文本，常见图片格式作为图片内容返回，
  其余以 base64 返回。单个附件默认上限 5 MB，另受 Gateway 的 `max_result_bytes` 限制（两人示例里调到了 8 MB）。
- **Hide My Email / Sign in with Apple 的转发邮件。** 这类邮件就在 iCloud 收件箱里，区别只在收件地址是中继地址。
  `search_messages` 的 `to` 可以按中继地址搜，结果里带 `to` 和 `delivered_to` 头。
- **两人各自的账号。** 两条 connection、两个进程、两份凭据；Connector 没有「切换账号」的参数。
- **凭据被拒绝。** 服务器拒绝密码（或 Google 拒绝 refresh token）后，Connector 在一段时间内不再出示这份凭据
  （IMAP / CalDAV 60 秒，Gmail 5 分钟），避免反复失败导致账号被锁；返回给 Agent 的是固定文案，说明需要人来处理。
- **连接中断。** IMAP 连接断了会重连一次再重试；仍然不通则返回「无法连接」。Gmail 的 access token 过期会自动刷新，
  收到 401 时强制刷新一次。Gateway 这一侧，Connector 进程死掉会被重新拉起。
- **TLS。** IMAP 和 CalDAV 一律 TLS 并校验证书，没有关闭校验的选项；CalDAV 不做基于 DNS 的服务发现，密码只发往配置的那个地址。
- **日历的事件查找只用时间范围查询。** `get_event` 不按 UID 查，而是用 `list_events` 给出的日历、UID 和开始时间
  在那一天里找。原因：iCloud 对带 UID 条件的查询返回 412，而库的绕行办法是请求一个由 UID 拼出来的地址。
  时间范围查询是 `list_events` 已经在用的同一种请求。

### 7.3 只读的真实含义

「只读」在四个 Connector 里是三种不同强度的东西，不能混为一谈：

| | 凭据本身能做什么 | Connector 实际发出什么 | 结论 |
|---|---|---|---|
| Gmail | 只能读邮件。Token 的 scope 是 `gmail.readonly`，用它发写请求会被 Google 拒绝 | 对 `gmail.googleapis.com` 的 GET，和对 `oauth2.googleapis.com` 的 Token 刷新 | **凭据层只读。** Connector 每次刷新都检查 Google 报告的 scope，只要不是恰好这一个就拒绝工作 |
| iCloud Mail | App 专用密码**能收发邮件、删除邮件，也能访问日历和通讯录**。Apple 不提供只读的、或只限某一项服务的密码 | 邮箱用 `EXAMINE` 打开（协议层面的只读打开，读信不会标记已读），正文用 `BODY.PEEK` 取；不发任何修改命令 | **只是这段代码不写。** 拿到这份密码的人、或被改过的 Connector 进程，不受工具列表限制 |
| iCloud 日历 | 同上，是同一种密码 | 只有 PROPFIND 和 REPORT | 同上 |
| 提醒事项 | macOS 对提醒事项只有「完全访问」一种授权，没有只读；授权是给**应用**的，同一个应用名下启动的任何程序都有 | 只调用读取接口 | 同上，而且见 7.6 |

因此：

- 对 iCloud，Gateway 提供的保护是「Agent 拿不到密码，只能通过这几个读工具间接使用它」，而不是「密码只能读」。
  这依赖于 Connector 进程和 Gateway 主机没有被攻破。
- 邮件和日历各用一个 App 专用密码（示例配置就是这样）。权限范围并不因此变小，好处只是可以单独吊销，
  以及从 Apple 的登录记录里能看出是哪一个在用。
- 这些 Connector 的测试里有一项是「服务器只收到了读请求」（IMAP 邮箱内容和标记前后不变；CalDAV 只出现 PROPFIND / REPORT）。
  它证明的是这份代码的行为，不是凭据的权限。

### 7.4 现成 iCloud MCP 项目的评估（2026-11，依据它们的 README 和仓库信息）

任务书要求优先评估这两个项目：

| | [epinethrone/icloud-mcp](https://github.com/epinethrone/icloud-mcp) | [eodozzy/icloud-mcp](https://github.com/eodozzy/icloud-mcp) |
|---|---|---|
| 形态 | Python，MIT；邮件 25 个工具、日历 12、通讯录 11、提醒事项 10、备忘录 9，另有 Drive、地图、信息、健康；自带 OAuth 服务器、Dashboard、菜单栏应用和 Mac 助手 | Python，MIT，体量小；stdio |
| 账号模型 | 明确声明单用户：一个部署服务一个 iCloud 账号，不是多租户，「替别人保存 App 专用密码」被明确排除在范围之外 | 一个进程一个账号，密码先查系统钥匙串，再读环境变量 |
| 只读 | 有 `READ_ONLY=true` 开关和工具选择 | 默认只读（只读方式打开邮箱、`BODY.PEEK`）；发信、回复、转发和日历/通讯录的增删改需要环境变量开关加一次确认 |
| 底层库 | MCP Python SDK、IMAPClient、caldav、icalendar | README 没有写明 |
| 维护 | 个人项目，本月仍有提交 | 个人项目，最近一次提交在 2026-06 |

没有直接采用的原因：

1. **写操作的代码在进程里。** 两个项目的只读都是开关，发信和删改的代码路径在同一个进程里，由配置或环境变量挡住。
   任务书说的「不能因为项目提供只读工具就假定其运行时权限完全只读」在这里是字面意义上成立的。
   自带的 Connector 里没有任何写操作的代码，要让它写必须改代码。
2. **体量。** stdio Connector 以 Gateway 的权限运行（第 6 节第 2 条），它的全部代码和依赖都和 Gateway 一样被信任。
   epinethrone 的功能面远大于这里需要的四个工具，并且自带一套身份系统；eodozzy 小得多，但仍包含不需要的写路径和通讯录。
3. **需要的部分很小。** epinethrone 用的同样是 IMAPClient 和 caldav。在这两个库上写几个只读工具，每个 Connector 约 240 行，
   比审阅、锁定并持续跟踪一个第三方项目的更新更省事，也更容易保证第 7.1 节的四条约定。

从 epinethrone 的 README 里得到、并已反映在实现里的经验（它们来自对 Apple 真实服务器的使用，本项目自己没有验证过）：

- iCloud 的 CalDAV 拒绝带 UID 条件的查询（412）→ `get_event` 改为时间范围查询（7.2）。
- 有些账号在 IMAP 和 CalDAV 上需要不同的登录名 → 两个 Connector 的用户名是各自独立配置的。
- iCloud 的日历请求较慢（秒级）→ 示例配置里 connection 的超时是 60 秒。

如果以后想换用其中之一：作为**独立容器**用 HTTP 接入（它就只持有自己那份凭据），在 Gateway 里只列出读工具并锁定定义。
这样 Gateway 的保证不变，只读仍然只是白名单层面的。

### 7.5 Gmail

- 使用你自己的 Google Cloud 项目里的 OAuth 客户端（类型「桌面应用」），scope 只申请 `gmail.readonly`。
- 授权由人在自己的电脑上做一次：`python -m agent_gateway.connectors.gmail_auth client_secret.json`，
  它打开浏览器走 Google 的授权页（Google 官方库实现），成功后把 refresh token 打印到标准输出，直接用管道交给
  `agw secret set`，不经过剪贴板和文件。Google 返回的 scope 不是恰好 `gmail.readonly` 时不输出任何东西。
- 两个人各自授权一次，得到两份 Token，存成两个 secret，对应两条 connection。OAuth 客户端可以共用。
- **OAuth 应用处于「Testing」发布状态时，refresh token 7 天后失效**，需要重新授权。要长期使用，把应用发布为
  「In production」；`gmail.readonly` 是受限 scope，未经验证的应用在授权页会显示警告，对自用的两个账号这是可以接受的。
  这一点来自 Google 的文档，本项目没有实测过。

### 7.6 提醒事项（实验性）

升级后的 iCloud 提醒事项不再通过 CalDAV 提供，能读到它的只有登录了该 Apple ID 的 Apple 设备上的 EventKit。
由此带来三个代码解决不了的约束：

1. **数据跟着 macOS 登录会话走。** Connector 必须运行在那个人自己的 macOS 用户会话里。同一台 Mac 上的另一个用户、
   或 Linux 上的 Gateway 容器，都读不到。两个人 = 两个 macOS 用户（或两台 Mac）各跑一个。不需要改变现有的 iCloud 账号结构。
2. **授权是完全访问，而且是给应用的。** macOS 把授权记在「负责的应用」名下（从终端启动就是终端应用）。
   同一个应用名下启动的任何程序都获得同样的完全访问，包括在那个终端里运行的 Agent。
3. **如果 Agent 以同一个 macOS 用户运行，或者有完全磁盘访问权限，Gateway 对提醒事项不提供任何隔离**：
   Agent 可以不经过 Gateway 直接读写。这种情况下接入提醒事项只是提供了便利，不是安全边界。

接入方式（部署步骤见 [deployment.md](deployment.md) 的「提醒事项」一节）：那个人的 Mac 上跑第二个原生的 `agw`，
只暴露这一个 Connector 给一个 client，也就是主 Gateway；主 Gateway 把它当作一个 HTTP 上游，用 `bearer_secret` 连接。
没有为此写新的传输或代理代码。

**状态：** 数据转换和排序用模拟 EventKit 对象的替身测试过；「未授权时不读也不弹窗」在这台 Mac 上测试过；
真实 Reminders Connector 已在独立进程中通过 EventKit 替身执行，并覆盖两个个人 helper 串联主 Gateway 的账号隔离。
模拟验收覆盖全部只读工具。**没有**对真实提醒事项数据运行过，**没有**走过 macOS 的授权弹窗；
以后台服务（launchd）方式运行时能否获得授权仍需要在实际部署时确认。

### 7.7 不接入的平台

没有可靠个人 API 的平台（Amazon 消费者订单等）不在计划内：不使用逆向接口，不窃取 Cookie，不保存浏览器会话；
Amazon 的 SP-API 是卖家接口，不是消费者订单接口。

## 8. 审批

### 8.1 一次调用的经过

1. Agent 调用一个 `approval_required` 的工具。Gateway 先完成策略和参数校验（pin 已填入），然后查这一次调用有没有批准。
   没有：把请求存为「待审批」，告诉 Agent 请求在哪个地址等待，**不执行**。
2. 账号的所有者在浏览器里打开那个地址，看到将要执行的内容：哪个 client、哪个账号、哪个工具、**完整的参数**。
   用 Passkey 批准或拒绝。
3. Agent 用完全相同的参数再调用一次。Gateway 找到批准，在同一个数据库事务里把它标记为「已使用」，然后执行。
   再调用一次就找不到批准了，从第 1 步重新开始。

通知这一步没有单独的通道：等待地址由 Agent 转告给人。这是安全的，因为 Passkey 由浏览器绑定到配置的域名，
别的页面拿不到有效的签名；但人必须读审批页面上显示的内容，而不是 Agent 的转述。

### 8.2 批准绑定什么

- **请求的身份**（`ApprovalRequest.binding`）：发起的 client 和 principal、connection、service、account、上游工具名、
  以及**最终发往上游的参数**的 SHA-256。改任何一个参数、换一个 client、换一个账号，都是另一次调用，需要另一次批准。
- **Passkey 签的是什么**：每个决定是一次独立的 WebAuthn 断言（要求用户验证，即指纹、面容或 PIN），挑战值是
  「一次性随机数 + 决定（批准/拒绝/撤回）+ 数据库里这条请求的全部字段」的哈希。答复回来时按数据库里的请求重新计算，
  不一致即作废。所以一次签名只对「当时显示的那一条请求的那一个决定」有效，不能挪到别的请求上，也不能重放。
- **没有登录会话。** 批准不是「登录后点按钮」：没有 Cookie，没有可以复用的会话，每个决定都要重新验证 Passkey。
- **谁能决定**：账号的 owner；共享账号（`shared` 里的 principal 所拥有的）则每个人都可以。请求者自己的身份不起作用。

### 8.3 期限、次数和上限

| 项 | 值 |
|---|---|
| 待审批请求的有效期 | `request_ttl_seconds`，默认 10 分钟 |
| 批准后可以使用的期限 | `grant_ttl_seconds`，默认 10 分钟；用一次即失效 |
| 被拒绝后 | 拒绝后的 `request_ttl_seconds` 内，同一次调用直接回答「已被拒绝」，不产生新的请求 |
| 撤回 | 已批准未使用的请求可以在页面上用 Passkey 撤回，或由管理员 `agw approval cancel` |
| 每个 client 同时等待的请求 | 5 个 |
| 每人的 Passkey | 8 个 |
| 参数的保存 | 只保存到请求不再可能被决定或使用为止，之后清除；审计日志里从不出现参数值 |

批准在联系上游**之前**就被用掉。如果上游随后失败，批准不会退回：Gateway 无法知道写操作是否已经发生，所以不会自己重试写操作。

### 8.4 不能靠改配置绕过

- 没有 `approvals:` 配置时，`approval_required` = 永不执行。
- `approvals:` 里只有地址、存储位置和两个期限，没有任何能让请求自动通过的选项；也没有选择「别的审批器」的配置项。
- 测试覆盖了：各种看起来像开关的配置项都被当作未知字段拒绝。
- 这句话的边界见 8.5 第 1 条。

### 8.5 限制

1. **能控制 Gateway 主机的人可以绕过审批**：改策略把 `approval_required` 换成 `allow`、直接改 SQLite 文件、
   或运行 `agw approval enroll` 给自己登记一个 Passkey。「不允许通过修改配置绕过」只对不能修改主机的人成立。
2. **审批服务和 Gateway 在同一个进程里。** `Approver` 是一个两个方法的接口，接一个运行在别的主机上的审批服务
   （比如 compose-cd-engine 的那一套）只需要实现它；这个适配没有写，因为目前没有需要对接的独立服务，
   也没有任何真实的写工具。同机实现的代价是：攻破 Gateway 进程 = 攻破审批。
3. **没有用实体认证器验证过。** 服务端用软件 Passkey（真实的 P-256 密钥和签名）测试；
   Chromium 浏览器用虚拟 WebAuthn 认证器执行真实页面脚本，覆盖中英文、注册、批准、拒绝、撤回、
   原参数执行、单次使用和上游失败的显示。Touch ID、安全密钥及手机跨设备流程没有实测。
4. **页面显示的是原始参数（JSON）**，不是自然语言摘要。人需要自己读懂参数的含义。
5. **审批页面没有访问控制**，知道请求地址（192 位随机数）的人就能看到内容，但没有 Passkey 就不能决定。
   地址会出现在 Agent 的对话里，所以应把请求内容视为「Agent 及其模型提供商已经知道的东西」。
6. **不涉及支付、转账等高风险动作。** 这套机制目前没有接任何真实的写工具。

## 9. 尚未实现或无法保证

| 项 | 状态 |
|---|---|
| 防御已取得 Gateway 主机管理员权限的 Agent | **做不到**，只能靠部署约束 |
| 区分共享 Agent 背后是哪个人 | **做不到**，共享连接只给 household |
| 对真实 iCloud Mail / iCloud 日历 / Gmail 的验证 | **没有做过。** 只对本地的 IMAP、CalDAV 服务器和模拟的 Google 接口测试过 |
| 审批浏览器验证 | Chromium + 虚拟认证器已覆盖；实体认证器尚未实测（8.5） |
| 提醒事项 | **实验性，未在真实数据上运行**（7.6） |
| 上游凭据层的只读 | 只有 Gmail 成立；iCloud 和提醒事项做不到（7.3） |
| 审批不被主机上的人绕过 | **做不到**（8.5） |
| 独立主机上的审批服务 | 没有；只有接口 |
| 自带的写工具（发信、建日程等） | 没有 |
| 防内容中的 Prompt Injection | **不防**。只保证被误导的模型仍受其 Token 的权限约束；邮件正文、日历标题等原样返回（工具描述里提示了它们是数据） |
| 第三方模型的数据留存 / 匿名性 | **无法保证**。工具结果交给 Agent 之后的去向不在 Gateway 控制内 |
| 结果内容的最小化 | 不做。Connector 返回什么就是什么（仅有大小上限和密钥脱敏） |
| Resources / Prompts / Sampling / Elicitation | 不代理 |
| 嵌套参数、查询字符串内部的资源限制 | 不支持。`pin` / `allow_values` 只作用于顶层参数；上游工具必须把资源做成独立参数。例如 Gmail 的查询是一个字符串，无法限制到某个标签 |
| TLS、限流、登录失败锁定 | 没有。Token 是 256 位随机数，暴力猜测不可行；传输加密靠 Tailscale |
| OS Keychain / 外部 Secret Manager | 没有，只有加密文件。`SecretStore` 是一个四个方法的协议，以后可以替换 |
| 主密钥轮换命令 | 没有。重新 `secret init` 并重新录入凭据 |
| 审批的主动通知（推送、消息） | 没有。等待地址由 Agent 转告 |
| 网页配置、管理 API | 显式启用 `admin` 后可用；主机路径、管理员身份、域名和任意进程命令不开放给网页 |

## 10. 安全测试对照

测试使用真实的 Gateway 和 Connector 进程，对面是本地替身服务；所有账号、邮件、日程和提醒事项均为测试数据。
完整入口是 `python scripts/acceptance.py --docker`，报告保存在 `run/acceptance/`。

| 要求 | 测试 | 说明 |
|---|---|---|
| 跨用户访问账号 | `test_isolation.py`、各 `test_connector_*.py` | 列不出、调不了，拒绝与「不存在」不可区分；另一个人的邮箱、日历名字也无法指过去 |
| 未授权工具调用 | `test_isolation.py`、`test_tools.py` | 未在白名单的上游工具对 Agent 不存在 |
| 通过参数伪造身份 | `test_identity.py` | 参数、请求头、Cookie、会话 ID、`_meta` 都无效 |
| 凭据泄露 | `test_credentials.py`、各 `test_connector_*.py` | 结果、列表、错误、审计日志、Connector 环境 |
| 工具名冲突 | `test_tools.py` | 暴露名全局唯一，配置期报错 |
| 上游工具动态变更 | `test_tools.py` | 启动时和运行中的变更都会下线该工具；投毒描述不会到达 Agent |
| SSRF / 任意 URL | `test_upstream.py`、`test_tools.py` | URL 只来自配置；跨源重定向不跟随；schema 远程 `$ref` 被拒 |
| 审批绕过与重放 | `test_approval.py`、`test_passkey.py` | 参数改一个字符即需重新批准；批准只能用一次；并发的两次调用只有一次成功；签名不能挪到别的请求；显示之后请求变了则决定作废；过期；非所有者不能决定；没有用户验证的断言被拒；没有配置就没有页面 |
| Agent 绕过 Gateway | `test_surface.py` | 只验证了暴露面和 Connector 约定；其余是部署约束 |
| 不可信内容中的 Prompt Injection | `test_surface.py` | 只验证了权限不变；Gateway 不过滤内容 |
| 邮件的搜索、正文、附件、中继地址 | `test_connector_mail.py` | 对面是 [pymap](https://github.com/icgood/pymap)（一个真实的 IMAP 服务器实现）加 TLS；包括连接中断后重连、密码被拒、证书不可信 |
| 日历的事件、重复事件、冲突检查 | `test_connector_calendar.py` | 对面是 [Radicale](https://radicale.org)（真实的 CalDAV 服务器）；包括家庭日历的 pin |
| Gmail 的搜索、正文、附件、Token 刷新和失效、scope 检查 | `test_connector_gmail.py` | 对面是一个模拟 Google 接口的本地服务；授权助手用 Google 的真实客户端库走完整流程 |
| Connector 不写 | 以上三个文件 | 邮箱前后不变；CalDAV 只出现 PROPFIND / REPORT；Gmail 只出现 GET 和 Token 请求 |
| 浏览器审批页面 | `test_passkey_browser.py` | 真实 Chromium、真实页面脚本、虚拟 WebAuthn 认证器；中英文手机布局和参数安全显示 |
| 提醒事项经两层网关 | `test_reminders_gateway.py` | 两个独立 EventKit 替身进程；真实 HTTP 网关串联；列表、详情、完成状态、账号隔离、审计脱敏 |
| 容器部署 | `test_deployment.py` | 实际镜像、独立临时卷；非 root、只读挂载、无 capabilities、审批跨重启保留、Connector 恢复 |
| 示例配置可用 | `test_config.py` | 两份示例填好后能加载；household 示例引用的工具名和 pin 参数在 Connector 里真实存在 |
| 网页初始化和管理权限 | `test_admin.py` | 一次性初始化、域名和 UV 校验、会话撤销、CSRF、成员不能成为管理员、写盘失败、在途调用与 Token 撤销 |
| 网页 Google 授权 | `test_admin_oauth.py` | 仿 Google；state 和 PKCE、会话绑定、只读 scope、令牌不回浏览器、撤销和过期 |
| 网页完整操作 | `test_admin_browser.py` | 英文桌面、中文手机；注册、成员、Token、连接器审阅和验证、跨账号授权、参数限制、退出再登录 |

### 网页管理的额外边界

首次设置链接由主机生成，24 小时有效，保存在权限 `0600` 的 `admin-setup-link` 文件里；公共页面不返回此链接。
注册码和会话 Cookie 在数据库中只保存哈希。管理员身份固定在 YAML 中，家庭成员邀请只注册该成员的审批 Passkey。
HTTPS 管理会话使用 `__Host-`、Secure、HttpOnly、SameSite=Strict Cookie，最多一小时；每个 POST 需要精确 Origin、JSON，
已登录操作还需要会话专属 CSRF Token。MCP Bearer Token 不被管理入口接受。

网页只提供固定 Connector 目录，不能上传脚本或任意设置命令。新增或编辑连接器先生成绑定当前会话和配置版本的临时预览，
用户确认工具定义后才持久化。预览和 OAuth 中间凭据仅在内存保留，10 分钟过期并定期清理；Google Token 留在服务端。
工具进程可启动不代表真实账号登录成功，所以「工具已连接」与实际只读验证分别显示。

新配置先经完整模型和工具 schema 校验，再等待在途请求结束（最多 30 秒），原子写入加密状态并切换运行实例。
等待超时或写盘失败不会发布新配置。鉴权在请求租约内，所以撤销的 Token 不能在新配置里继续使用旧鉴权结果。
网页配置版本参与审批绑定；每次更新会取消未使用审批，即使在状态写入后发生崩溃，旧审批也不能用于新配置。
姓名存放在成员记录的 `name` 字段，家庭也有自己的 `name`。姓名唯一（忽略大小写），可编辑并支持中文和空格。
内部 ID 和 WebAuthn user handle 不随改名变化；页面只显示姓名。改名不改变授权版本，不重启连接器或取消审批。
应用旧连接器预览时合并最新姓名，删除成员时删除整个成员记录。旧 `display_names` 仅作为升级输入读取，保存后不再保留。
旧网页配置迁移时，将 principal 规则的最终效果逐个展开为现有 client 的规则（默认拒绝无需保存），保留 Token hash、
审计 subject、连接 owner 和审批版本。尚无 Agent 的旧身份授权不会赋予未来创建的 Agent。
新增连接和新增 Agent 都没有默认授权，撤销 Agent 时同时移除其全部规则，复用名称不会复活旧权限。
管理会话意味着能修改权限、登记成员公钥及录入凭据，应只在可信的人用的浏览器中登录。它不属于 Agent 的接入配置。

替身服务和真实服务的差别是这些测试证明不了的部分：Apple 和 Google 的服务器对边界情况的处理（非 ASCII 搜索、
超大邮箱、限流、特殊的登录名形式）只能在真实账号上发现。
