# 设计说明

本文描述当前实现、执行路径与安全边界。产品定位和能力要求见 [产品需求](requirements.md)，
配置方法与验证步骤见 [部署说明](deployment.md)。

## 1. 实现概况

- 提供账号隔离、审批、网页管理和连接器封装。
  协议、传输、鉴权中间件、加密、WebAuthn、IMAP、CalDAV 全部复用成熟库。
- 一个 Bearer Token 对应一个 Agent。Agent 属于一个群组，工具权限逐 Agent 配置。
- 每个 `(service, account)` 是一条独立的上游连接，只拿到自己账号的凭据。
- 默认拒绝；工具必须同时出现在连接的 `tools` 和某条 `policy` 规则里才存在。
- 远程/自定义上游定义经人工审阅写入 lock；定义变化会停用工具。标准内置连接器随安装包同步能力，新工具默认拒绝。
- 自带统一 IMAP/SMTP 邮件连接、Gmail（REST + OAuth），以及只读 iCloud 日历（CalDAV）和
  Apple 提醒事项（EventKit，实验性）。**Gmail 选择只读时，由 Google 在凭据层强制执行**，见 7.3。
- 读取和写入分别可选直接允许或逐次 Passkey 审批。需要审批时，由配置的成员或群组内任意成员核对
  **那一次调用的确切内容**，批准只能用一次。内置邮件连接的发信权限单独配置，默认逐次审批。
  没有配置审批页面时，`approval_required` 的工具永远不会执行。
- 部署必须阻止 Agent 读取凭据或控制 Gateway 主机及运行时。
- **自动验收使用模拟账号与替身服务**（见第 10 节）。真实 Chromium 加虚拟认证器覆盖注册、管理和审批；
  实际提供方和认证器组合的兼容性需单独验证。检查步骤见 [deployment.md](deployment.md)。

## 2. 接口与信任边界

客户端通过 Streamable HTTP 访问 `/mcp`。上游支持 stdio 和 Streamable HTTP；
连接使用预配置的地址、账号和凭据，不接受 Agent 提供的目标 URL 或进程命令。

Gateway 主机、配置管理员和同用户运行的 stdio 上游属于信任边界。
第三方上游需要进程与凭据隔离时，应独立部署并通过 HTTP 接入。
MCP 协议、认证中间件和密码学由现有库承担，服务适配器负责具体接口操作。

## 3. 架构

Gateway 以 MCP Proxy 为主：统一入口、工具元数据发现、连接路由、凭据和授权边界。
Agent 负责结果处理、聚合和 reasoning；上游 MCP 或薄 Connector 提供服务操作。
Gateway 不设计跨服务订单/财务等业务模型，不解析购物邮件生成订单库、不编排业务查询、不调用 LLM。
schema 校验、参数固定、MIME/协议适配、大小限制和密钥脱敏属于接口与安全处理。

```
Agent ──HTTP(Streamable)──► /mcp
                             │ 1 身份      Bearer Token → Agent（SDK 的鉴权中间件）
                             │ 2 路由      共享工具名 + connection → 内部授权绑定 → 上游工具名
                             │ 3 策略      (Agent, tool) → allow / approval_required / deny，默认 deny
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

从 0.6 起，默认 MCP 清单固定为 `gateway_search_tools`、`gateway_search_connections`、`gateway_call_tool`。
搜索按调用者的当前权限过滤；同类连接共用工具名，执行时显式选择 connection，并重新验证原有的每一道检查。
搜索返回每个连接的精确参数 schema；同一连接存在多个受限绑定时，用 variant 指定其中一个。
这里搜索的是工具与 connection 元数据，不索引邮件、订单或其他业务内容；共享工具名也不统一业务结果模型。
内部工具别名继续承载权限和审批绑定，旧客户端直接调用这些名字仍受相同检查；默认不再把它们全部加入 MCP 清单。

标准内置连接器在启动时从当前安装包同步能力和锁定义，新工具默认 deny。更新保留连接配置及已有授权；
读变写或被移除的能力撤销旧授权。与参数限制冲突的更新保留原限制并在网页显示原因。
远程连接器和自定义启动命令仍需显式审阅。安装包升级因此也是内置能力定义的信任边界，不能把远程动态定义自动当作已审阅。

群组包含成员和 Agent，可作为共享连接的所有者。YAML 沿用 `households` 声明群组，`members` 和 `clients` 的 `household` 字段指定所属群组。
连接的 owner 是成员或群组。`policy.clients × connection × tools` 决定每个 Agent 的权限，加入群组不会自动获得工具权限。
连接的 `approver` 可选同群组的一位成员或整个群组；不填时默认 owner。选群组时，其中任意一位成员批准即可。
owner 表示账号归属，approver 表示审批权，两者独立。一个 Agent 的授权适用于其全部调用，Token 不证明当前聊天人的身份。
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
管理员由主机配置的 `admin.owner` 指定，普通群组成员、MCP Token、Tailscale 可达性都不授予管理角色。
SQLite 保存审批、公钥和管理员会话；`admin.enc` 加密保存网页修改的配置、凭据和工具锁。
Agent 可通过 MCP 发起操作审批。成员的通行密钥注册链接由管理员在后台签发。

### 模块

| 文件 | 职责 |
|---|---|
| `config.py` | 配置模型和全部交叉校验；未知字段报错 |
| `auth.py` | Token 生成、哈希、常数时间比对；从请求里取调用者 |
| `policy.py` | 把规则预计算成 `(principal, tool) → effect` |
| `lock.py` | 工具定义的规范化、摘要和 lock 文件 |
| `catalog_sync.py` | 从安装包同步标准内置连接器能力；新工具默认拒绝，保留已有限制 |
| `discovery.py` | 固定发现入口、共享工具名、权限过滤后的连接与参数 schema |
| `credentials.py` | 加密密钥文件、结果脱敏 |
| `upstream.py` | 每个 connection 一条长连接：连接、校验定义、重连、错误归一化 |
| `server.py` | 两个 MCP handler（`tools/list`、`tools/call`）和 HTTP 应用 |
| `approval.py` | 审批接口（`ApprovalRequest`、`Approver`）和拒绝一切的默认实现 |
| `passkey.py`、`static/` | Passkey 审批：请求的存储、WebAuthn 验证、审批页面 |
| `audit.py` | JSONL 审计日志，字段白名单 |
| `cli.py` | `agw serve / check / lock / token / secret / approval` |
| `admin*.py`、`static/admin.*` | 一次性初始化、Passkey 管理会话、成员和 Token、连接器目录、Google 网页授权、权限编辑 |
| `runtime.py` | 等待在途 MCP 请求结束，原子切换有效配置；Token 鉴权在相同读取租约内 |
| `connectors/` | 自带的 Connector，每个账号使用独立进程；目录同步只读取纯 schema 工厂，不访问账号 |

## 4. 复用与自研

| 部分 | 来源 |
|---|---|
| MCP 协议、Streamable HTTP 服务端、stdio / HTTP 客户端、协议版本协商 | 官方 [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) |
| Bearer 鉴权中间件、401 处理、Host/Origin 校验 | SDK（`BearerAuthBackend`、`RequireAuthMiddleware`、`TransportSecuritySettings`） |
| HTTP 服务 | uvicorn + Starlette（SDK 的依赖） |
| 密钥文件加密 | `cryptography` 的 Fernet（AES-128-CBC + HMAC-SHA256） |
| 参数校验 | `jsonschema`，使用空 registry，禁止任何远程 `$ref` |
| 配置解析和校验 | pydantic + PyYAML |
| WebAuthn（挑战、签名、origin 校验） | Yubico 的 [`fido2`](https://github.com/Yubico/python-fido2) |
| IMAP 协议、TLS | [`IMAPClient`](https://github.com/mjs/imapclient) + 标准库 `ssl` |
| 邮件解析（MIME、编码、附件） | 标准库 `email` |
| CalDAV 协议、重复事件展开 | [`caldav`](https://github.com/python-caldav/caldav)（及其依赖 `icalendar`、`recurring-ical-events`） |
| Gmail | Gmail REST API，经 SDK 自带的 HTTP 客户端 `httpx2`；授权流程用 Google 的 `google-auth-oauthlib`（只在取 Token 的那一次） |
| 提醒事项 | macOS EventKit，经 `pyobjc` |
| 网关代码 | Token → principal 的映射、策略求值、lock 文件、pin / allow_values 的 schema 改写、上游连接生命周期、错误归一化、脱敏、审计、CLI；审批请求的状态机和页面；Connector 中将库的服务操作包装为工具的那一层 |

## 5. 身份认证的关键风险

1. **Token 可被同机高权限进程窃取。** Gateway 只能验证客户端凭据，无法判断凭据由哪个进程取得。
   客户端 Token 应位于其他 Agent 无权读取的环境中；共享凭据的权限必须适合其全部使用者。
2. **Token 不代表最终聊天用户。** 如客户端需要按用户选择不同凭据，选择逻辑必须基于可信认证，
   不能由模型输出决定。当前网关不提供最终用户身份透传认证。
3. **Token 是静态的。** 没有过期时间，不绑定来源主机；泄露即可冒用，直到轮换。缓解手段是 Tailscale ACL
   限制谁能连到 Gateway 端口、审计日志里的 `client` 和 `remote` 字段、以及简单的轮换流程。
4. **没有网关客户端 OAuth。** 当前使用静态 Bearer Token。Gmail 的授权流程只用于上游账号，
   通用 MCP 上游也支持 OAuth；两者均不提供客户端 OAuth。
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

1. 一个进程（或一个 URL）只服务一个账号。不同账号使用独立 connection 和进程。
2. 凭据由 Gateway 给：stdio 用 `secret_env`，HTTP 用 `bearer_secret` / `secret_headers`，或网页管理的 OAuth 授权。
3. 工具不接受账号、用户或凭据参数。
4. 工具结果里不出现凭据。

[examples/demo_connector.py](../examples/demo_connector.py) 是模板（其中 `debug_dump`、`crash` 等是故意做坏的测试工具，不要照抄）。
接入步骤：加 connection → `agw secret set` → `agw lock` 审阅定义 → 写 policy → 重启。

### 7.2 自带的 Connector

以 `python -m agent_gateway.connectors.<模块>` 启动，多账号配置示例见
[deploy/gateway.household.example.yaml](../deploy/gateway.household.example.yaml)。

| 模块 | 服务 | 工具 | 凭据 | 只读成立在哪一层 |
|---|---|---|---|---|
| `imap_mail` | iCloud Mail / IMAP + SMTP，同一账号一条连接 | `list_mailboxes`、`search_messages`、`get_message`、`get_attachment`、`list_messages`、`get_messages`、`set_message_state`、`move_messages`、`archive_messages`、`trash_messages`、`send_message` | 同一 App 专用密码 | 读工具使用 `EXAMINE` / `BODY.PEEK`；写工具由 Agent 权限及审批控制 |
| `caldav_calendar` | iCloud 日历（任何 CalDAV 服务器） | `list_calendars`、`list_events`、`get_event`、`check_conflicts` | App 专用密码 | 只在 Connector 发出的请求这一层 |
| `gmail` | Gmail | `search_messages`、`get_message`、`get_attachment` | OAuth refresh token，scope 只有 `gmail.readonly` | **凭据层**，由 Google 强制 |
| `reminders_eventkit` | Apple 提醒事项（实验性，见 7.6） | `list_lists`、`list_reminders`、`get_reminder` | 没有凭据；macOS 对「提醒事项」的完全访问授权 | 只在 Connector 的代码这一层 |

接口行为：

- **不做全量邮箱索引。** 每次调用都是对服务器的一次搜索或读取，本地不存任何邮件。搜索由服务器执行（IMAP `SEARCH`、Gmail 的查询语法）。
- **完整正文。** `get_message` 返回纯文本正文（只有 HTML 的邮件会转成文本，也可以要原始 HTML），长邮件用
  `offset` / `max_chars` 分段读完。HTML 转文本只是为了可读，**不是**内容过滤。
- **附件。** `get_message` 列出附件，`get_attachment` 按序号取：文本类直接返回文本，常见图片格式作为图片内容返回，
  其余以 base64 返回。单个附件默认上限 5 MB，另受 Gateway 的 `max_result_bytes` 限制（多账号示例配置为 8 MB）。
- **Hide My Email / Sign in with Apple 的转发邮件。** 应连接实际接收转发邮件的邮箱。
  `search_messages` 的 `to` 可以按中继地址搜，结果里带 `to` 和 `delivered_to` 头；Gateway 不维护商家身份映射或订单数据。
- **账号隔离。** 独立 connection、进程和凭据；Connector 没有「切换账号」的参数。
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
| Gmail | 默认只读；整理和发送由配置单独控制 | Gmail API 搜索、读取、标签和废纸篓操作；仅在开启发送时调用 `messages.send` | 每次刷新都校验 Google 报告的 scope 与配置完全一致 |
| iCloud Mail | App 专用密码**能收发邮件、删除邮件，也能访问日历和通讯录**。Apple 不提供只读的、或只限某一项服务的密码 | 读取工具用 `EXAMINE` 和 `BODY.PEEK`；0.5 起同一连接另有状态修改、移动及 SMTP 发信工具，由 Gateway 的 write 权限控制 | **工具白名单层只读。** write 可逐次审批或明确免审批；拿到密码或控制进程的人不受工具列表限制 |
| iCloud 日历 | 同上，是同一种密码 | 只有 PROPFIND 和 REPORT | 同上 |
| 提醒事项 | macOS 对提醒事项只有「完全访问」一种授权，没有只读；授权是给**应用**的，同一个应用名下启动的任何程序都有 | 只调用读取接口 | 同上，而且见 7.6 |

因此：

- 对 iCloud，Gateway 提供的保护是「Agent 拿不到密码，只能通过这几个读工具间接使用它」，而不是「密码只能读」。
  这依赖于 Connector 进程和 Gateway 主机没有被攻破。
- 邮件和日历各用一个 App 专用密码（示例配置就是这样）。权限范围并不因此变小，好处只是可以单独吊销，
  以及从 Apple 的登录记录里能看出是哪一个在用。
- 读取工具的测试验证「服务器只收到了读请求」（IMAP 邮箱内容和标记前后不变；CalDAV 只出现 PROPFIND / REPORT）。
  它证明的是这份代码的行为，不是凭据的权限。

### 7.4 连接器接入与验证

现有上游 MCP 可通过配置接入，工具定义需要显式审阅。只读分类由受信任的目录或管理员提供，
不能直接信任上游 `readOnlyHint`。工具清单限制的是 Agent 的可调用能力，不缩小上游凭据本身的权限。

服务连接器应保留原生服务语义。内置连接器使用 IMAPClient、CalDAV、Gmail API 和 EventKit，
各连接拥有独立的账号上下文。工具发现成功只证明 MCP 服务可用，业务账号登录需要独立验证。

### 7.5 Gmail

- 使用你自己的 Google Cloud 项目里的 OAuth 客户端（类型「桌面应用」），scope 只申请 `gmail.readonly`。
- 授权由人在自己的电脑上做一次：`python -m agent_gateway.connectors.gmail_auth client_secret.json`，
  它打开浏览器走 Google 的授权页（Google 官方库实现），成功后把 refresh token 打印到标准输出，直接用管道交给
  `agw secret set`，不经过剪贴板和文件。Google 返回的 scope 不是恰好 `gmail.readonly` 时不输出任何东西。
- 每个账号独立授权，Token 存为各自的 secret，对应独立 connection。OAuth 客户端可以共用。
- **OAuth 应用处于「Testing」发布状态时，refresh token 7 天后失效**，需要重新授权。要长期使用，把应用发布为
  「In production」；`gmail.readonly` 是受限 scope，未经验证的应用在授权页会显示警告，应按实际应用状态核对授权限制。
  这一点来自 Google 的文档，本项目没有实测过。

### 7.6 提醒事项（实验性）

升级后的 iCloud 提醒事项不再通过 CalDAV 提供，能读到它的只有登录了该 Apple ID 的 Apple 设备上的 EventKit。
由此带来三个代码解决不了的约束：

1. **数据跟着 macOS 登录会话走。** Connector 必须运行在那个人自己的 macOS 用户会话里。同一台 Mac 上的另一个用户、
   或 Linux 上的 Gateway 容器，都读不到。多个账号需要各自的 macOS 会话或设备授权，不能通过切换工具参数访问另一账号。
2. **授权是完全访问，而且是给应用的。** macOS 把授权记在「负责的应用」名下（从终端启动就是终端应用）。
   同一个应用名下启动的任何程序都获得同样的完全访问，包括在那个终端里运行的 Agent。
3. **如果 Agent 以同一个 macOS 用户运行，或者有完全磁盘访问权限，Gateway 对提醒事项不提供任何隔离**：
   Agent 可以不经过 Gateway 直接读写。这种情况下接入提醒事项只是提供了便利，不是安全边界。

接入方式（部署步骤见 [deployment.md](deployment.md) 的「提醒事项」一节）：那个人的 Mac 上跑第二个原生的 `agw`，
只暴露这一个 Connector 给一个 client，也就是主 Gateway；主 Gateway 把它当作一个 HTTP 上游，用 `bearer_secret` 连接。
没有为此写新的传输或代理代码。

**状态：** 模拟测试覆盖数据转换、排序以及「未授权时不读也不弹窗」；
真实 Reminders Connector 已在独立进程中通过 EventKit 替身执行，并覆盖两个个人 helper 串联主 Gateway 的账号隔离。
模拟验收覆盖全部只读工具。**没有**对真实提醒事项数据运行过，**没有**走过 macOS 的授权弹窗；
以后台服务（launchd）方式运行时能否获得授权仍需要在实际部署时确认。

### 7.7 后续平台接入范围

扩展范围包括电商、财务、设备、基础设施、媒体、通信和专业数据服务，状态见 [产品需求](requirements.md)。
优先复用现成 MCP，再考虑针对明确 API 的薄适配器。邮件读取不等于购物平台已接入，
业务理解与跨来源聚合由 Agent 或上游服务负责。

远程 Streamable HTTP MCP 可在网页配置 URL、认证和工具；自定义 stdio 命令由主机配置。
通用上游 OAuth 使用官方 MCP SDK 处理发现、PKCE 和授权，Gmail 使用独立授权流程，校验所选 scope。整理使用 `gmail.modify`，其 Google 权限也可发送，网关仍按所选功能暴露工具。

### 7.8 新邮件通知

Gateway 本身不轮询。主机配置里的 `mail_events` 为某条自带 Gmail 或 IMAP 连接打开后，这条连接的 Connector 进程里
多一个后台线程，每 30 秒问一次服务器「上次之后有什么新的」，有就向配置的 webhook 发一个签名请求。
Agent 收到后再用这条连接的读取工具读信，所以凭据仍然只在 Gateway 里。

- **只发标识。** 请求体为 `{"type": <配置的类型>, "occurredAt": ..., "data": {"mailbox": <连接 ID>, "message_ids": [...]}}`；
  IMAP 为 `"uidvalidity": N, "uids": [...]`。不含发件人、主题、正文或附件，也不读取它们：Gmail 只调
  `users.getProfile`、`users.history.list`，补报时另调 `users.messages.list`（`gmail.readonly` 即可）；IMAP 用 `EXAMINE`
  打开 INBOX 后只做 `UID SEARCH`，补报时另取 `INTERNALDATE`，不改动已读状态。
- **什么算新。** 第一次检查只记下当前位置，之前的邮件不算。之后：Gmail 历史里新增到 INBOX 的邮件（`messageAdded`），
  以及后来被加上 INBOX 标签的（移回收件箱、稍后提醒到期）；IMAP 是 INBOX 里 UID 大于上次最大值的邮件，移进 INBOX 的邮件也会得到新 UID。
- **先落盘再发送。** 新标识、推进后的游标和待发事件一起原子写入 `<连接状态目录>/mail-events.json`，然后才发送。
  每个事件生成时就有固定的 delivery ID，接收方按它去重，所以重试（包括进程重启后）不会变成第二个事件。
  2xx 算送达；400、413 说明请求体本身被拒，丢弃该事件，避免挡住后面的；其余（401、404、429、5xx、网络错误）保留重试。
- **退避。** 一轮里检查或发送失败，下一轮间隔依次为 30 秒、1、2、4 分钟，之后每 5 分钟（与 Gmail 凭据被拒后的暂停相同），
  一轮全部成功即恢复 30 秒。接收方离线时每一轮仍先检查，新邮件照样记进待发队列。
- **游标失效时补报。** Gmail 历史通常保留约一周，有时只有几小时；过期时（404）改为列出「上次成功检查前 60 秒之后」到达 INBOX 的邮件。
  IMAP 的 UIDVALIDITY 变了时同理，按 INTERNALDATE 筛选。可能重复报告少量邮件。补报按邮件到达时间找，
  所以**这段时间里被移回 INBOX 的旧邮件不会通知**（归档后又移回、稍后提醒到期；IMAP 移动保留原来的 INTERNALDATE）；
  游标有效时它们照常通知（IMAP 移进 INBOX 的邮件得到新 UID）。这是有意的取舍：完整补报要每轮列出整个 INBOX 并保存全部 ID
  （IMAP 编号重排后还要比对 Message-ID），配额和状态随收件箱大小增长。需要不漏的部署应另有定期的全量巡检。
- **有界。** 每个事件最多 200 个标识；接收方长期不可用时待发队列最多保留 1000 个事件，最旧的先丢。
- **一个连接一个监听。** 网页管理修改配置时，新 Connector 进程会在旧进程退出前启动；状态文件用文件锁保护，同一时刻只有一个进程在检查。
  `agw lock`、网页「预览工具」等只为读取工具定义而启动的 Connector 不拿状态目录，不会监听。
- **配置放在主机文件。** 启用网页管理后，连接存在网页管理的加密状态里（第一次在网页上修改就把整个连接列表存进去），
  之后 YAML 里对连接的改动不再生效；网页表单只有固定字段，没有地方填 webhook 地址和签名密钥，新建连接的 `env` 只来自表单。
  所以通知不放在连接里，而是放在两种管理方式都读、网页改不到的 `mail_events`。签名密钥存在 secret store，
  以环境变量交给 Connector，不写进状态文件。
- **改名、换邮箱都从当时开始。** `mail_events` 按连接 ID 绑定，网页改不了 gateway.yaml，所以网页拒绝给
  `mail_events` 写着的连接改名，免得通知悄悄停掉：先在 gateway.yaml 写上新名称、重启 Gateway，再在网页改名。
  状态按连接 ID 存放，改名不搬状态：新名称像刚打开通知一样从改名时开始，重启到改名之间到达的邮件、旧名称下还没发出的
  通知都不再发，由全量巡检兜底。这是有意的取舍：改名很少，而搬状态的代码在保存出错时会让状态和配置错位。
  状态里记着邮箱地址（Gmail 的 `emailAddress`，IMAP 的 `用户名@服务器`）：同一个连接换成另一个邮箱时，旧邮箱的游标和待发通知作废
  （这条连接已读不到旧邮箱的邮件），新邮箱也从当时开始；同一个邮箱重新授权不受影响。
- **请求格式**是 OpenBot 的签名 webhook：`x-openbot-timestamp`、`x-openbot-delivery-id`、
  `x-openbot-signature: sha256=<HMAC-SHA256("<timestamp>.<delivery id>.<请求体>")>`。

没有用 Gmail 的 `users.watch` + Pub/Sub：它需要另建 Pub/Sub 主题、订阅和一份 Pub/Sub 凭据（Gmail Token 的 scope 必须恰好是
所配置的那些，不能顺带加 Pub/Sub），而 Google 说明通知可能延迟或丢失，仍要靠 `history.list` 兜底。也没有用 IMAP IDLE：
30 秒的间隔已满足及时性，IDLE 还要处理续期和断线。两者都可以以后在同一个游标和发送队列上加。

## 8. 审批

### 8.1 一次调用的经过

1. Agent 调用需要审批的工具。Gateway 校验身份、权限和参数后保存原请求。
2. 审批人在浏览器查看账号、工具和完整参数，用 Passkey 批准或拒绝。邮件的状态修改、移动、归档、删除等操作
   还会列出所涉邮件的发件人、标题和日期（见下文）。
3. Gateway 领取已批准的请求，重新核对现有权限、凭据和工具定义，在联系上游前原子标记为「已使用」，然后执行一次。
4. 支持 MCP Tasks 和 URL elicitation 的客户端通过原调用跟踪任务。Agent 也可调用
   `gateway_call_tool`，只传最初提交的 `idempotency_key` 查询状态。只有网页上的 Passkey 能批准执行。

每次提交由 Agent 生成独立的 key。Gateway 在同一个事务中保存 key、参数指纹和请求；相同 key 与参数会复用，
不同参数会被拒绝。只有发起请求的 Agent Token 能查询。状态持久化，原始结果短期保存在内存。
若进程在领取后、记录结果前中断，结果标记为未知，不重放。免审批的后台调用也用同一个 key 查询。

**邮件预览。** 内置 IMAP 和 Gmail 连接上按邮件 ID 修改邮件的工具，新建请求时 Gateway 会查出这些邮件的发件人、
标题和日期，与请求一起保存，审批页面据此列出。正文不读取，IMAP 用 `EXAMINE` 和 `BODY.PEEK`，不会把邮件标为已读。
因为审批页面没有访问控制（8.5），**只有当发起请求的 Agent 自己就能直接读到这些邮件时才查**：
同一连接上至少有一个读工具对它是 `allow`（不是逐次审批），固定参数与所涉文件夹一致，文件夹或标签范围也照常生效；
否则页面只说明「无读取权限，不显示预览」。查询最多等 8 秒，失败或超时只影响预览，不影响请求本身；
重复提交复用已有请求，不会再查。预览和参数一样参与 Passkey 签名，请求不再可能被决定或使用时一并清除，
审计日志只记录是否显示（`approval_preview`），不记录内容。查询走连接器的内部工具 `preview_messages`，
它不在工具目录里，Agent 无法调用。发件人和标题由发信人填写，页面也提示这一点。

### 8.2 批准绑定什么

- **请求的身份**（`ApprovalRequest.binding`）：发起的 client、Token 指纹和 principal、connection、service、account、上游工具名、
  以及**最终发往上游的参数**的 SHA-256。改任何一个参数、换一个 client、换一个账号，都是另一次调用，需要另一次批准。
- **Passkey 签的是什么**：每个决定是一次独立的 WebAuthn 断言（要求用户验证，即指纹、面容或 PIN），挑战值是
  「一次性随机数 + 决定（批准/拒绝/撤回）+ 数据库里这条请求的全部字段」的哈希。答复回来时按数据库里的请求重新计算，
  不一致即作废。所以一次签名只对「当时显示的那一条请求的那一个决定」有效，不能挪到别的请求上，也不能重放。
- **没有登录会话。** 批准不是「登录后点按钮」：没有 Cookie，没有可以复用的会话，每个决定都要重新验证 Passkey。
- **谁能决定**：connection 的 `approver` 指定同群组的一位成员或群组内任意成员；未设置时默认 owner。
  owner 是账号归属，approver 是审批权；请求者不能通过参数选择或冒充审批人。旧 YAML 的 shared 规则保留兼容。

### 8.3 期限、次数和上限

| 项 | 值 |
|---|---|
| 待审批请求的有效期 | `request_ttl_seconds`，默认 1 小时；按创建时的设置记录到期时间，修改后只影响新请求 |
| 批准后开始执行的期限 | `grant_ttl_seconds`，默认 10 分钟；领取一次即失效 |
| 被拒绝后 | 拒绝后的 `request_ttl_seconds` 内，同一次调用直接回答「已被拒绝」，不产生新的请求 |
| 撤回 | 已批准未使用的请求可以在页面上用 Passkey 撤回，或由管理员 `agw approval cancel` |
| 每个 client 同时等待的请求 | 5 个 |
| 每人的 Passkey | 8 个 |
| 参数和邮件预览的保存 | 只保存到请求不再可能被决定或使用为止，之后清除；审计日志里从不出现参数值或预览内容 |

批准在联系上游**之前**就被用掉。如果上游随后失败，批准不会退回：Gateway 无法知道写操作是否已经发生，所以不会自己重试写操作。

### 8.4 修改权限和审批设置

没有 `approvals:` 时，`approval_required` 永不执行。MCP Token 不能修改策略。
网页管理员需要用 Passkey 再确认权限增授、审批人或参数限制变更、Token 签发或轮换、
Passkey 邀请或撤销，以及会引入或改变连接凭据和工具的操作。
确认绑定本次操作、请求内容、当前配置版本和登录会话，最多两分钟，只能使用一次。
单纯撤销访问可以立即执行。

### 8.5 限制

1. **能控制 Gateway 主机的人可以绕过审批**：改策略把 `approval_required` 换成 `allow`、直接改 SQLite 文件、
   或运行 `agw approval enroll` 给自己登记一个 Passkey。受信任的网页管理员在重新验证后也能调整策略；
   已经签发的审批不能用来批准不同的操作。
2. **审批服务和 Gateway 在同一个进程里。** `Approver` 是一个两个方法的接口，接一个运行在别的主机上的审批服务
   需要实现并验收独立 adapter；当前仅提供同进程实现。同机实现的代价是：攻破 Gateway 进程 = 攻破审批。
3. **认证器兼容性。** 服务端用软件 Passkey（真实的 P-256 密钥和签名）测试；
   Chromium 浏览器用虚拟 WebAuthn 认证器执行真实页面脚本，覆盖中英文、注册、批准、拒绝、撤回、
   原参数执行、单次使用和上游失败的显示。测试未覆盖所有实体认证器、跨设备和浏览器组合。
4. **页面显示的是原始参数（JSON）**，不是自然语言摘要。人需要自己读懂参数的含义。
   邮件操作另列出所涉邮件的发件人、标题和日期，但 Agent 没有直接读取权限时没有这份预览，只能看邮件 ID。
5. **审批页面没有访问控制**，知道请求地址（192 位随机数）的人就能看到内容，但没有 Passkey 就不能决定。
   地址会出现在 Agent 的对话里，所以应把请求内容视为「Agent 及其模型提供商已经知道的东西」。
6. **不涉及支付、转账等高风险动作。** 当前自带写工具限于邮件操作和模拟笔记，是否需要审批由显式策略决定。

## 9. 尚未实现或无法保证

| 项 | 状态 |
|---|---|
| 防御已取得 Gateway 主机管理员权限的 Agent | **做不到**，只能靠部署约束 |
| 区分共享 Agent 背后是哪个人 | 当前 Token 只识别 Agent；权限必须适合所有共用该 Token 的人 |
| 对真实 iCloud Mail / iCloud 日历 / Gmail 的完整验证 | 未完成；自动验收使用本地 IMAP、CalDAV 和模拟 Google；单次连接成功不替代完整验证 |
| 审批浏览器验证 | Chromium + 虚拟认证器已覆盖；实体设备和浏览器兼容性需单独验证（8.5） |
| 提醒事项 | **实验性，未在真实数据上运行**（7.6） |
| 新邮件通知 | 只用模拟 Google、pymap 和本地签名接收方验证过（7.8）；真实 Gmail 历史、iCloud 和 OpenBot 接收需部署后核对 |
| 上游凭据层的只读 | 只有 Gmail 成立；iCloud 和提醒事项做不到（7.3） |
| 审批不被主机上的人绕过 | **做不到**（8.5） |
| 独立主机上的审批服务 | 没有；只有接口 |
| 自带的写工具 | IMAP 状态/移动/归档/废纸篓、SMTP 发信已实现；Gmail 可选择整理和发送；Calendar / Reminders 仍只读 |
| 扩展服务 connector | 尚未接入；通用 Proxy 的可用性不代表具体平台集成已完成 |
| 通用远程 MCP 网页管理 / 上游 OAuth | 已实现；网页配置 HTTP 连接、工具选择与分类、OAuth 发现和刷新、Bearer / API Key |
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
| 审批绕过与重放 | `test_approval.py`、`test_passkey.py` | 参数改一个字符即需重新批准；批准只能用一次；并发查询不会重复执行；签名不能挪到别的请求；显示之后请求变了则决定作废；过期；非指定审批人不能决定；没有用户验证的断言被拒；没有配置就没有页面 |
| 审批页面的邮件预览 | `test_approval_mail_preview.py`、`test_connector_gmail.py`、`test_imap_operations.py` | 能直接读这些邮件的 Agent 才有预览；读工具固定在别的文件夹、按 Agent 禁读时没有；只含发件人、标题、日期，不读正文、不标已读；范围外的 Gmail 邮件显示为不可见；决定后清除；审计日志不含内容 |
| Agent 绕过 Gateway | `test_surface.py` | 只验证了暴露面和 Connector 约定；其余是部署约束 |
| 不可信内容中的 Prompt Injection | `test_surface.py` | 只验证了权限不变；Gateway 不过滤内容 |
| 邮件的搜索、正文、附件、中继地址 | `test_connector_mail.py` | 对面是 [pymap](https://github.com/icgood/pymap)（一个真实的 IMAP 服务器实现）加 TLS；包括连接中断后重连、密码被拒、证书不可信 |
| 日历的事件、重复事件、冲突检查 | `test_connector_calendar.py` | 对面是 [Radicale](https://radicale.org)（真实的 CalDAV 服务器）；包括家庭日历的 pin |
| Gmail 的搜索、正文、附件、Token 刷新和失效、scope 检查 | `test_connector_gmail.py` | 对面是一个模拟 Google 接口的本地服务；授权助手用 Google 的真实客户端库走完整流程 |
| 读取操作不写 | 以上三个文件 | IMAP 读取前后邮箱和标记不变；CalDAV 只出现 PROPFIND / REPORT；只读 Gmail 只出现 GET 和 Token 请求；邮件写工具单独验收 |
| 浏览器审批页面 | `test_passkey_browser.py` | 真实 Chromium、真实页面脚本、虚拟 WebAuthn 认证器；中英文手机布局和参数安全显示 |
| 提醒事项经两层网关 | `test_reminders_gateway.py` | 两个独立 EventKit 替身进程；真实 HTTP 网关串联；列表、详情、完成状态、账号隔离、审计脱敏 |
| 容器部署 | `test_deployment.py` | 实际镜像、独立临时卷；非 root、只读挂载、无 capabilities、审批跨重启保留、Connector 恢复 |
| 示例配置可用 | `test_config.py` | 两份示例填好后能加载；household 示例引用的工具名和 pin 参数在 Connector 里真实存在 |
| 网页初始化和管理权限 | `test_admin.py` | 一次性初始化、域名和 UV 校验、会话撤销、CSRF、成员不能成为管理员、写盘失败、在途调用与 Token 撤销 |
| 网页 Google 授权 | `test_admin_oauth.py` | 仿 Google；state 和 PKCE、会话绑定、只读 scope、令牌不回浏览器、撤销和过期 |
| 网页完整操作 | `test_admin_browser.py` | 英文桌面、中文手机；注册、成员、Token、连接器审阅和验证、跨账号授权、参数限制、退出再登录 |

### 网页管理的额外边界

首次设置链接由主机生成，24 小时有效，保存在权限 `0600` 的 `admin-setup-link` 文件里；公共页面不返回此链接。
注册码和会话 Cookie 在数据库中只保存哈希。管理员身份固定在 YAML 中，群组成员邀请只注册该成员的审批 Passkey。
HTTPS 管理会话使用 `__Host-`、Secure、HttpOnly、SameSite=Strict Cookie，最多一小时；每个 POST 需要精确 Origin、JSON，
已登录操作还需要会话专属 CSRF Token。MCP Bearer Token 不被管理入口接受。
在 Agent 无法控制的设备或浏览器中打开 `/admin/`。

网页提供内置 Connector 和远程 HTTPS MCP 配置，不能上传脚本或任意设置命令。新增或编辑连接器先生成绑定当前会话和配置版本的临时预览，
用户确认工具定义后才持久化。预览和 OAuth 中间凭据仅在内存保留，10 分钟过期并定期清理；Token 留在服务端。
Gmail 与通用 MCP 共用登录会话校验。MCP 授权还绑定资源和 issuer，后台请求不会自动扩大 scope 或启动新授权。
通用 OAuth 使用独立加密文件保存 Token、客户端信息、元数据和绝对到期时间；每个授权共用刷新锁，轮换后立即持久化。
刷新不获取管理写锁、不更改权限版本。移除连接后，迟到的刷新不能重新创建该授权。
工具进程可启动不代表真实账号登录成功，所以「工具已连接」与实际只读验证分别显示。

新配置先经完整模型和工具 schema 校验，再等待在途请求结束（最多 30 秒），原子写入加密状态并切换运行实例。
等待超时或写盘失败不会发布新配置。鉴权在请求租约内，所以撤销的 Token 不能在新配置里继续使用旧鉴权结果。
网页配置版本参与审批绑定；每次更新会取消未使用审批，即使在状态写入后发生崩溃，旧审批也不能用于新配置。
姓名存放在成员记录的 `name` 字段，群组也有自己的 `name`。姓名唯一（忽略大小写），可编辑并支持中文和空格。
内部 ID 和 WebAuthn user handle 不随改名变化；页面只显示姓名。改名不改变授权版本，不重启连接器或取消审批。
应用旧连接器预览时合并最新姓名，删除成员时删除整个成员记录。旧 `display_names` 仅作为升级输入读取，保存后不再保留。
旧网页配置迁移时，将 principal 规则的最终效果逐个展开为现有 client 的规则（默认拒绝无需保存），保留 Token hash、
审计 subject、连接 owner 和审批版本。尚无 Agent 的旧身份授权不会赋予未来创建的 Agent。
新增连接和新增 Agent 都没有默认授权，撤销 Agent 时同时移除其全部规则，复用名称不会复活旧权限。
连接权限按当前已审阅工具展开为规则，仅替换选定 Agent 在该连接上的授权。访问范围与审批独立：禁止访问全部 deny；
只读拒绝 write，read 可选 allow 或 approval_required；读写则分别为 read 和 write 选择 allow 或 approval_required，支持全部组合。
内置目录的已知读取工具或主机显式标记 `tools[].access: read` 的工具可进入只读集合；
其他工具按写入处理，不信任上游的 `readOnlyHint` 自动授予读取权。未知工具不会因名字看起来像 get/list 就被放行。
逐工具规则仍可审阅和调整。升级保留原有自定义授权，网页显示为自定义，不静默改写现有权限。
连接的 approver 限于账号所属群组，改变审批人会撤销未使用的网页审批；即使直接修改主机 YAML，消费批准时也核对当前审批人集合。
编辑连接器凭据保留已有 approver。Agent 改名同步更新全部 policy.clients 引用，Token 哈希不变；改名属于配置变更，旧审批不再可用。
管理会话意味着能修改权限、登记成员公钥及录入凭据，应只在可信的人用的浏览器中登录。它不属于 Agent 的接入配置。

替身服务和真实服务的差别是这些测试证明不了的部分：Apple 和 Google 的服务器对边界情况的处理（非 ASCII 搜索、
超大邮箱、限流、特殊的登录名形式）只能在真实账号上发现。
