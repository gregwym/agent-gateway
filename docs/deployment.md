# 部署

本指南使用示例账号和占位地址。自动验收使用模拟服务；接入真实服务后，按第 8 节核对实际提供方的行为。

## 1. 部署安全边界

Gateway 的全部安全性建立在一条前提上：**Agent 不能读、不能改、不能重启 Gateway 所在的环境。**
部署应满足以下条件：

- Agent 在 Gateway 主机上没有 shell、SSH、root，也不在 `docker` 组；
- Agent 不能通过任何部署通道修改 Gateway 的配置、镜像、Compose 文件或环境变量；
- Agent 读不到 Gateway 的数据目录（`config/`、`secrets/`、`key/`、`state/`），也读不到它们的备份；
- Agent 只能通过网络访问 Gateway 的端口，访问不到上游 Connector 和上游凭据；
- 个人 Token 不存放在其他 Agent 能读到的地方（见 [design.md](design.md) 第 5 节）；
- 审批用的 Passkey 所在的设备（手机、你自己的电脑）不受 Agent 控制，登记 Passkey 的链接不经过 Agent 能读到的渠道。

Docker 容器不是这里的安全边界。Compose 文件里的非 root、只读根文件系统、去掉 capabilities，
限制进程权限，不限制主机管理员。

能改 `gateway.yaml` 或 `state/approvals.sqlite` 的人可以绕过审批，能读 `key/` 和 `secrets/` 的人拿得到全部上游凭据。

## 2. 部署环境

| 位置 | 评价 |
|---|---|
| 独立主机或虚拟机 | Agent 无登录与管理权限，网络只开放网关入口 |
| 共享容器主机 | Agent 无主机、容器运行时或部署管理权限，不能读取数据卷与备份 |
| Agent 可管理的开发环境 | 仅用于模拟账号测试，不放置真实服务凭据 |

## 3. 安装（Docker Compose）

> 容器验收覆盖镜像构建、管理命令、健康检查、非 root 运行、只读挂载、缺失密钥拒绝启动、
> 审批状态跨重启保留和连接器恢复。具体平台结果以对应版本的验收报告为准。

在 Gateway 主机上，由人执行：

```sh
git clone https://github.com/gregwym/agent-gateway && cd agent-gateway/deploy

mkdir -p data/config data/secrets data/key data/state
cp gateway.example.yaml data/config/gateway.yaml              # demo；真实账号用 gateway.household.example.yaml，见第 5 节
sudo chown -R 10001:10001 data && sudo chmod -R go-rwx data   # Linux 主机；macOS 上的 Colima / Docker Desktop 不需要 chown

docker compose build
```

然后按顺序：

1. **编辑 `data/config/gateway.yaml`**：principals、connections、tools、policy。
2. **给每个 Agent 发一个 Token**：`docker compose run --rm admin token`，把哈希填进 `clients[].token_sha256`，
   Token 本身交给对应的 Agent。Gateway 不保存 Token，丢了就重新生成。
3. **创建主密钥**：`docker compose run --rm admin secret init`。立刻把 `data/key/master.key` 的内容抄进密码管理器。
4. **录入上游凭据**：`docker compose run --rm admin secret set <名字>`，值从提示符输入，不经过命令行参数。
5. **审阅工具定义**：`docker compose run --rm admin lock`。它会打印配置里引用的每个上游工具的完整定义。
   工具描述是会被 Agent 当作指令读的文本，要像审代码一样读一遍。确认后 `lock --write`。
6. **检查**：`docker compose run --rm admin check`，输出每个 principal 能调用什么。逐行核对。
7. **启动**：`AGW_BIND=<本机 Tailscale IP> docker compose up -d`（可以把 `AGW_BIND` 写进 `deploy/.env`）。

不用 Docker 时，在仓库目录里 `pip install '.[connectors]'` 后直接用 `agw` 命令，步骤相同；用一个专用的系统用户运行，
数据目录权限 `0700`。这个项目没有发布到 PyPI，不要按名字从 PyPI 安装。

## 4. 网络

- 端口只发布在 **一个地址** 上：本机的 Tailscale IP，或 `127.0.0.1` 再由 `tailscale serve` 提供 HTTPS。不要发布到 `0.0.0.0`。
- 用 Tailscale ACL 限制谁能连。只放行 Agent 所在节点到 Gateway 端口，不给任何到 Gateway 主机的 SSH：

  ```json
  { "grants": [ { "src": ["tag:agent"], "dst": ["tag:agent-gateway"], "ip": ["tcp:8080"] } ] }
  ```

- Gateway 以主机名被访问时，设置 `server.allowed_hosts`（如 `["agent-gateway.your-tailnet.ts.net:8080"]`），
  开启 `/mcp` 的 Host 头校验并拒绝带 `Origin` 的浏览器请求（防 DNS rebinding）。填的值必须和客户端实际发来的 Host 头一致，
  包括端口；填错的表现是所有 `/mcp` 请求都被拒绝。
- Gateway 不需要入站公网访问。出站只需要到各上游服务（`imap.mail.me.com:993`、`caldav.icloud.com` 及其跳转到的
  `*.icloud.com` 主机、`smtp.mail.me.com:587`、`gmail.googleapis.com`、`oauth2.googleapis.com`）。

**启用审批时需要 HTTPS。** 浏览器只在 HTTPS 页面（或 `http://localhost`）上允许使用 Passkey。Gateway 自己不做 TLS，
由 Tailscale 提供证书是最省事的办法：

```sh
AGW_BIND=127.0.0.1 docker compose up -d
tailscale serve --bg --https=443 http://127.0.0.1:8080     # 以你的 Tailscale 版本的 `tailscale serve --help` 为准
```

这样 Agent 和人都通过 `https://<主机名>.<tailnet>.ts.net` 访问（MCP 地址是 `https://…/mcp`），
`approvals.origin` 和 `server.allowed_hosts` 都填这个主机名（443 端口不带端口号）。需要在 Tailscale 管理后台开启
MagicDNS 和 HTTPS 证书；ACL 里放行的端口相应改成 `tcp:443`。经过 `tailscale serve` 之后，审计日志里的 `remote`
通常是本机地址；部署后应核对实际审计来源字段。

## 5. 接入真实账号

[gateway.household.example.yaml](../deploy/gateway.household.example.yaml) 是多个独立成员账号使用邮件、日历和 Gmail 的示例配置。复制成 `data/config/gateway.yaml`，把所有大写的占位值换掉。它引用 7 个 secret，下面逐个说明怎么得到。
全部录入后才能 `lock`：`lock` 会启动每个 Connector 列出工具，缺 secret 时启动不了。Connector 在第一次被调用时才登录上游，
所以凭据是否正确要到第一次调用才知道。

**只读的真实范围**（详见 [design.md](design.md) 7.3）：Gmail 选择只读时，Token 由 Google 强制只读。iCloud 的 App 专用密码
**没有只读版本**，它能收发邮件、改日历；只读靠 Gateway 仅开放已审阅的读取工具，读取工具使用 `EXAMINE` 和 `BODY.PEEK`，密码只存在 Gateway 主机上。

### 5.1 iCloud 邮件

1. 每个人登录 [account.apple.com](https://account.apple.com) →「登录与安全」→「App 专用密码」，生成一个，命名如
   `agent-gateway mail`。需要账号已开启双重认证。邮件和日历各生成一个，这样可以单独吊销。
2. 录入：`docker compose run --rm admin secret set icloud_mail_password_a`（B 同理）。
3. 配置里的 `IMAP_USERNAME` 填 iCloud 邮箱地址。Apple 的说明是用户名通常为地址中 `@` 之前的部分，
   必要时使用完整地址，以账号实际登录结果为准。登录被拒绝后 Connector 会暂停 60 秒再试，避免连续失败锁账号。

「隐藏邮件地址」和「通过 Apple 登录」转发的邮件应从实际接收邮箱读取，按收件地址搜索用 `to` 参数；
`get_message` 返回 `Delivered-To`、`To`、`Reply-To` 等头，可以看出是哪个中转地址收的。

从 0.5 起，**一个邮箱只有一个 connection**，同时包含 IMAP 收取／整理和 SMTP 发信，保存一次 App 专用密码。
网页服务名称为「Mail / 邮箱 (iCloud, IMAP + SMTP)」。iCloud 默认 IMAP 993，SMTP `smtp.mail.me.com:587` + STARTTLS；
SMTP 使用完整邮箱地址，IMAP 用户名只有本地部分时自动补 `@icloud.com`。可填写 SMTP 用户名覆盖值及发件邮箱。
其他邮件服务填写其 SMTP 服务器；留空可以关闭发信。支持 TLS 465 或 STARTTLS，不支持明文 SMTP。
「验证连接」只列出邮箱并验证已配置的 SMTP 登录，不发邮件。

已有连接升级：权限或连接器卡片会提示尚未登记的新工具，点击 **审阅新工具 → 应用连接器** 即可保留原服务器设置及凭据引用并补齐工具。
也可使用 **连接器 → 编辑并审阅 → 预览工具 → 应用连接器**。然后在 **权限** 为 Agent 保存连接权限。
原有工具名称、固定参数和权限保留；新增工具默认无权限，读写审批分别可选「每次审批」或「不审批」。
不需要重新输入已保存的密码，也不需要新增第二个 SMTP connection。

新增工具后缀及用法：

| 后缀 | 用法 |
|---|---|
| `_list` | `list_messages`，按邮箱及过滤条件建立 UID 快照；后续只传 `next_cursor`，直到为 null。每页最多 100 条，删除项也返回结果 |
| `_get_batch` | `get_messages`，传 `mailbox`、`uidvalidity` 和最多 50 个 `uids`；每封独立结果，正文分段用 `next_offset` |
| `_set_state` | `set_message_state`，`read: true/false` 标记已读／未读，`starred: true/false` 加星／取消加星；保留其他标志 |
| `_move` / `_archive` / `_trash` | 移动／归档／移入废纸篓，批量输入同上。归档和废纸篓优先用服务端特殊文件夹；无法唯一识别时明确填写 `destination` |
| `_send` | `send_message`，`to` 数组、`subject`、`text`，可选 `cc`、`bcc`、`html`；发件地址来自连接设置 |

`uidvalidity` 从 `_list` 获取；邮箱 UID 世代变化时拒绝操作，需重新列出。
分页快照有效期最多一小时，连接进程重启即失效；遍历起点之后的新邮件需重新列出。
最多 16 份活动快照、合计一百万 UID；超限会明确报错，可用互不重叠的 `since` / `before` 日期范围遍历。
批量读取最多取 40 MB 原始邮件，并限制响应大小；超限项明确提示缩小批次或正文片段，不会悄悄省略。
批量结果逐封为 `success`、`error`、`unknown` 或 `not_attempted`；时间预算耗尽时剩余项标为未执行。
服务器中途断线不会自动重放写入；`unknown` 先核对当前状态再决定重试。移动回退使用 UIDPLUS，绝不清除未选中的已删除邮件。
SMTP 返回每个收件人的 `accepted`／`rejected`／`unknown`，accepted 仅指服务器接收提交。
当前发信支持文本／HTML，无附件；不额外写入「已发送」，由邮件服务商决定是否自动保存。发信内容和收件人均绑定到一次审批。

### 5.2 iCloud 日历

1. 同样生成一个 App 专用密码，`secret set icloud_calendar_password_a`。
2. `CALDAV_USERNAME` 填 Apple ID（登录 Apple 账号用的邮箱，可能不是 `@icloud.com` 地址），
   `CALDAV_TIMEZONE` 填你们的 IANA 时区（如 `America/Los_Angeles`），不带时区的时间参数按它解释。
3. **家庭日历**：示例把 A 账号里的家庭日历单独暴露给共享 Agent 和 B，日历 id 是固定参数（`pin`），Agent 改不了。
   id 要启动后才能查到：先带着占位值启动，用 A 的 Token 调一次 `a_calendar_list`（命令见第 8 节），
   把家庭日历的 `id` 填进两处 `FAMILY_CALENDAR_ID`，`check` 后重启。在那之前这两个工具只会回答 `No such calendar.`。

不需要改变现有的 iCloud 账号结构：每个人用自己的 Apple ID 和自己的密码，Gateway 里是两条互不相通的连接。

### 5.3 Gmail

Google 的控制台界面经常改版，下面按要做的事写，不按菜单名写。

1. 在 [Google Cloud Console](https://console.cloud.google.com) 建一个项目，启用 **Gmail API**。
2. 配置 OAuth 同意屏幕：用户类型「外部」。**发布状态要改成「In production」**：停在「Testing」时 Google 会在 7 天后让
   refresh token 失效。`gmail.readonly` 是受限 scope，不提交验证的话授权页会显示「未经验证的应用」警告，对自用的两个账号可以接受。
   （应按当前提供方要求核对应用发布状态；如使用 Testing 模式，需要将授权账号列为测试用户并处理授权到期。）
3. 创建 OAuth 客户端，类型 **「桌面应用」**，下载 JSON（下面叫 `client_secret.json`）。
4. 把 client id 填进配置的 `GMAIL_CLIENT_ID`，把 client secret 存进 secret store：

   ```sh
   python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["installed"]["client_secret"])' client_secret.json \
     | docker compose run --rm -T admin secret set gmail_client_secret
   ```

5. 每个人在一台有浏览器的电脑上各做一次授权。在仓库目录里：

   ```sh
   python3 -m venv .venv && . .venv/bin/activate && pip install '.[gmail-auth]'
   python -m agent_gateway.connectors.gmail_auth client_secret.json \
     | docker compose -f deploy/docker-compose.yml run --rm -T admin secret set gmail_token_a
   ```

   浏览器会打开 Google 的授权页，用**那个人自己的** Google 账号登录并同意。Token 只走管道，不显示在屏幕上；
   Google 给的权限不是恰好 `gmail.readonly` 时不输出任何东西。Gateway 在另一台机器上时，把管道的后半段换成
   `ssh <Gateway 主机> 'cd agent-gateway/deploy && docker compose run --rm -T admin secret set gmail_token_a'`。
6. 用完后删掉 `client_secret.json`。

多个账号可以共用一个 OAuth 客户端，每个账号独立授权并保存 Token（`gmail_token_a`、`gmail_token_b`）。

### 5.4 收尾

```sh
docker compose run --rm admin lock          # 读一遍 24 个工具的定义
docker compose run --rm admin lock --write
docker compose run --rm admin check         # 核对：household 只有 family_calendar_* 两个工具
docker compose up -d
```

启动后按第 8 节验证账号访问。

## 6. 审批

自带邮件连接已经支持写入。读取和写入都可以配置为无需审批或每次审批；本节适用于所有 `approval_required` 工具。
可先用 demo 配置（[gateway.example.yaml](../deploy/gateway.example.yaml) 里的 `a_notes_add`）验证，不操作真实账号。
产品范围与接入状态见 [requirements.md](requirements.md)。

**启用**：配置里加

```yaml
approvals:
  origin: https://gateway.your-tailnet.ts.net   # 人在浏览器地址栏里看到的那个地址，必须是 https（本机试用可以是 http://localhost:8080）
  store: ../state/approvals.sqlite
```

`origin` 写错的表现是审批页能打开，但点批准时报 `wrong_origin`。Passkey 由浏览器绑定在这个主机名上，
**以后改主机名，所有人都要重新登记。**

**登记 Passkey**（每个人一次，可以登记多个设备，每人最多 8 个）：

已启用网页管理时，在「群组成员 → 注册通行密钥」生成本人注册链接即可。下面是主机侧 CLI 的等价入口：

```sh
docker compose run --rm admin approval enroll person_a
```

它打印一个 15 分钟内有效、只能用一次的链接。**谁先打开，谁就成为这个人账号的批准者**，所以把链接通过私下渠道
（AirDrop、当面、端到端加密的私聊）交给本人，不要贴进任何 Agent 读得到的对话。打开后按浏览器提示创建 Passkey
（需要生物识别或设备密码）。

**一次审批**：Agent 调用一个 `approval_required` 的工具时，调用不会执行，Agent 收到一段固定文字，里面有一个
`…/approvals/r/<id>` 链接。连接指定的审批人打开链接，页面显示是哪个 client、哪个账号、哪个工具、完整参数；用 Passkey 批准后，
Agent 在有效期内（默认 10 分钟）**用完全相同的参数**再调一次，才会执行，而且只执行一次。参数变了就是一个新的请求。
连接的 `approver` 可选同群组的一位成员或群组内任意成员；未设置时默认 owner。选择群组时，其中任意成员可批准，
无需全员批准；owner 本身不授予其他 Agent 工具权限。

**管理**：

| 命令（前面加 `docker compose run --rm admin`） | 作用 |
|---|---|
| `approval requests` | 列出近期请求及其状态、谁批的、执行结果 |
| `approval cancel -- <请求 id>` | 撤销一个已批准但还没用掉的请求；`--` 防止以连字符开头的 ID 被当作选项 |
| `approval passkeys` | 列出已登记的 Passkey |
| `approval forget <Passkey id>` | 删除一个 Passkey（设备丢了就做这个） |

没有 `approvals:` 一节，或者没有符合当前审批人设置的已登记 Passkey 时，`approval_required` 的调用不会执行。
待处理请求的参数明文存在 `approvals.sqlite` 里，请求结束（执行、拒绝、撤销、过期）时清除。

## 7. 提醒事项

**实验性，未在真实数据上验证。** 背景和限制见 [design.md](design.md) 7.6，要点三条：

- 提醒事项只能在登录了那个 Apple ID 的 Mac 上、在那个人自己的 macOS 登录会话里读到。所以要在**那个人的 Mac** 上
  跑第二个很小的 `agw`（下面叫 helper），主 Gateway 把它当作一个 HTTP 上游。那台 Mac 关机或睡眠时提醒事项不可用。
- macOS 的授权是「完全访问」，没有只读档，而且记在启动它的应用名下（从「终端」启动，就是「终端」获得授权，
  以后从「终端」里跑的任何程序都能读写提醒事项）。
- helper 不要放在 Agent 运行的那台机器上：以同一个 macOS 用户运行的 Agent 可以绕过 Gateway 直接读写提醒事项。

在那个人的 Mac 上，由本人操作：

```sh
git clone https://github.com/gregwym/agent-gateway && cd agent-gateway
python3 -m venv .venv && . .venv/bin/activate && pip install '.[macos]'

mkdir -p run/reminders && cp deploy/reminders-helper.example.yaml run/reminders/gateway.yaml
export AGW_CONFIG=run/reminders/gateway.yaml

python -m agent_gateway.connectors.reminders_eventkit --request-access   # macOS 弹窗，选允许
agw token                 # 哈希填进 run/reminders/gateway.yaml；Token 本身存进主 Gateway（见下）
agw lock --write && agw check
agw serve --host <这台 Mac 的 Tailscale IP>
```

在主 Gateway 上：`secret set reminders_helper_token_a`（值是上面那个 Token），取消
`gateway.household.example.yaml` 里 `reminders-a` 的 connection 和 policy 两段注释，`lock --write`、`check`、重启。
Tailscale ACL 只放行主 Gateway 主机到这台 Mac 的 `tcp:8090`。

模拟验证覆盖工具发现、两个 helper 串联主网关、列表、详情、完成状态和账号隔离。
系统授权弹窗、真实提醒事项读取和 launchd 运行权限需要在目标环境验证。
上例使用终端前台运行；配置 LaunchAgent 前应验证相同用户会话下的访问权限。

## 8. 验收

### 8.1 模拟验收（不需要真实账号）

在仓库的虚拟环境中运行：

```sh
pip install -e '.[dev,browser-tests]'
python -m playwright install chromium
python scripts/acceptance.py --docker
```

所有数据都是一次性的测试数据。邮件对接本地 pymap（TLS），日历对接 Radicale，Gmail 对接仿 Google 的
OAuth/API 服务；Reminders 用 EventKit 替身经过两层真实网关。审批页面在真实 Chromium 中通过虚拟认证器
完成注册、批准、拒绝、撤回及一次性执行。容器测试使用独立临时卷，验证权限隔离、重启后的审批状态和故障恢复，
结束时删除测试容器与卷，不操作现有部署。

`run/acceptance/report.json` 记录源码指纹、各项退出码和测试统计；同目录保存 JUnit、日志及浏览器截图。
没有 Docker 时去掉 `--docker`，报告会明确该次不包含容器验收。Linux 缺少原生 EventKit 时，原生权限守卫测试会跳过，
跨平台的 EventKit 替身端到端测试仍会执行。

### 8.2 真实服务的可选验收

下面是以后使用真实账号时的检查清单，不属于模拟验收的通过条件。

自动验收只对本地替身（pymap、Radicale、仿 Google 的本地服务、软件 Passkey）执行。
验证可以在最终主机上做；想先快速试一遍，也可以在你自己的电脑（不是 Agent 所在的机器）上不用 Docker 跑：
`pip install -e '.[connectors,gmail-auth]'`，配置放在 `run/config/`，命令去掉 `docker compose run --rm admin` 前缀换成 `agw`。
试完把 `run/` 整个删掉。

准备一个调用工具的函数（需要 `curl` 和 `jq`）：

```sh
export AGW_URL=http://127.0.0.1:8080/mcp      # 或 https://<主机名>/mcp
call() {  # call <token> <tool> '<JSON 参数>'
  curl -s "$AGW_URL" -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}" \
    | jq '.result // .error'
}
tools() { curl -s "$AGW_URL" -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq -r '.result.tools[].name'; }
```

`$A`、`$B`、`$H` 是 person_a、person_b、household 三个 client 的 Token。

0.6 默认只列出三个入口。先搜索工具，再选择有权限的连接，最后调用：

```sh
call "$A" gateway_search_tools '{"query":"mail"}'
call "$A" gateway_search_connections '{"tool":"mail_list_messages"}'
# connection 使用上一步实际返回的 ID；参数采用它的 inputSchema。
call "$A" gateway_call_tool '{"tool":"mail_list_messages","connection":"my_mail","arguments":{"limit":25}}'
```

工具搜索支持 connection 筛选，连接搜索支持 tool 筛选；两者都支持 query、offset、limit，跟随 next_offset 完整遍历。
两个邮箱连接会共用 `mail_list_messages` 等工具名，授权和审批仍按实际连接分别检查。
升级到 0.6 后，已有 Agent 会话需要刷新一次 MCP 清单（或新建会话）以获得这三个入口。
之后能力或授权变化通过搜索即可看到。未授权 Agent 也有三个入口，但搜索结果为空。
下面旧的前缀工具名调用仍兼容；如需复现旧的完整 tools/list 清单，在 YAML 中设置 `server.tool_discovery: all`。

标准内置连接器的能力随网关版本自动同步，无需修数据库或逐个更新连接。新能力默认未授权；
请在 Permissions 中选择 Agent 的连接权限，分别决定读取和写入是否逐次审批。
权限修改不会重启未改变的连接器；请求响应丢失时，网页会读取最新设置确认保存结果，不自动重复提交。

**Phase 2**

| # | 验收项 | 怎么验 | 预期 |
|---|---|---|---|
| 1 | 搜索和读取真实邮件 | `call $A a_mail_search '{"from":"<某个发件人>","since":"2026-10-01"}'`，再 `call $A a_mail_get '{"uid":<上一步的 uid>}'`；Gmail：`call $A a_gmail_search '{"query":"from:<某人> newer_than:30d"}'`，`call $A a_gmail_get '{"id":"<id>"}'` | 结果和你在邮件客户端里看到的一致；中文主题和正文不乱码 |
| 2 | 完整正文及附件 | 找一封很长的邮件，`a_mail_get` 返回的 `body_chars` 是正文总长度，`truncated` 为 `true` 时用 `{"uid":…,"offset":20000}` 取后续部分；找一封带 PDF 和图片附件的，`call $A a_mail_attachment '{"uid":…,"index":0}'` | 分段拼起来是完整正文；附件大小和原件一致（默认上限 5 MB） |
| 2b | 中转地址 | `call $A a_mail_search '{"to":"<你的某个隐藏邮件地址>"}'` | 搜得到，`Delivered-To` / `To` 显示中转地址 |
| 3 | 指定账号的日历 | `call $A a_calendar_list '{}'`；`call $A a_calendar_events '{"start":"2026-11-16","end":"2026-11-23"}'`；对一个重复日程用 `a_calendar_event`（`calendar`、`uid`、`start` 都取自上一步）；`call $A a_calendar_conflicts '{"start":"2026-11-18T09:00","end":"2026-11-18T10:00"}'` | 和「日历」App 一致：全天日程、重复日程的每一次、别人邀请的日程、时区。iCloud 的每次日历调用可能要几秒 |
| 3b | 提醒事项 | 按第 7 节搭好后 `call $A a_reminders_lists '{}'`、`call $A a_reminders_list '{}'` | 实验性；任何不一致都请记下来 |
| 4 | 账号隔离 | 用 B、H 分别调用 `gateway_search_connections`；尝试通过 `gateway_call_tool` 选择未授权连接；尝试传入固定参数 | 搜索仅返回已授权连接；越权调用得到和「工具不存在」一样的回答；固定参数不能被覆盖 |
| 5 | 没有全量索引 | 用一段时间后看 `data/state/` | 仅有审计和管理/审批所需状态（如 `admin.enc`、`approvals.sqlite`），没有邮箱或订单索引；审计行里没有邮件内容和参数值 |
| 6a | 授权失效 | 在 Apple 账号页吊销邮件的 App 专用密码，再 `call $A a_mail_search '{}'` | 回答 `The mail server rejected this account's credentials…`，不是崩溃，也不泄露密码；`secret set` 新密码并重启后恢复 |
| 6b | Gmail 授权失效 | 在 [myaccount.google.com/connections](https://myaccount.google.com/connections) 移除这个应用的访问权，再调用 | 回答 `Google no longer accepts this account's authorisation…`；重新跑 `gmail_auth` 并重启后恢复 |
| 6c | Token 更新 | Gmail 调用一次，隔一个多小时再调用一次 | 两次都成功（access token 一小时过期，Connector 自己换新的） |
| 6d | 连接中断 | 邮件调用一次，放置半小时以上（或断一下网）再调用 | 成功；Connector 发现连接断了会重连一次 |

**Phase 3**

用 demo 配置或在你的配置里临时加一个 `approval_required` 的工具，并按第 4、6 节启用 HTTPS 和 `approvals:`。

| # | 怎么验 | 预期 |
|---|---|---|
| 1 | `approval enroll person_a`，在手机或电脑上打开链接 | 浏览器要求创建 Passkey；同一个链接第二次打开无效 |
| 2 | `call $A a_notes_add '{"folder":"inbox","text":"hello"}'` | 没有执行；回答里有审批链接 |
| 3 | 打开链接，核对页面上的 client、账号、工具、参数，批准 | 要求生物识别或设备密码 |
| 4 | 原样重复第 2 步的调用，然后再重复一次 | 第一次执行成功；第二次又变成等待审批（一次批准只管一次） |
| 5 | 发起请求，批准后把参数改一个字再调用 | 不执行，生成新的请求 |
| 6 | 发起请求，在页面上拒绝；再原样调用 | 回答已被拒绝，不生成新请求（默认 10 分钟内） |
| 7 | 用 B 的设备打开 A 的请求链接 | 看得到内容，但 B 的 Passkey 批不了 A 账号的请求 |
| 8 | 批准后不调用，`approval cancel -- <id>`，再调用 | 不执行 |
| 9 | `jq -c 'select(.event \| startswith("approval"))' data/state/audit/audit.jsonl` | 每次请求、批准、拒绝、撤销各有一行，没有参数值 |

问题报告应包含失败步骤、时间和对应审计事件，避免附带凭据或业务内容。

## 网页 onboarding（可选）

使用 `deploy/gateway.web.example.yaml` 可以从空网关开始；也可以在已启用 `approvals` 和 `secrets` 的配置里加：

```yaml
admin:
  owner: person_a
  state: ../state/admin.enc
  session_seconds: 1800
```

`owner` 必须是现有的非共享身份，由部署者指定。`approvals.origin` 填最终 HTTPS 域名，`server.allowed_hosts`
填对应的主机名。以 Tailscale Services 发布时，两处都用 Service 的域名。主机端发布 Service 和控制台批准主机后，
还需要一条允许客户端访问 `svc:<服务名>` 的 `tcp:443` grant；主机批准不会自动授予客户端访问权限。

部署者初始化一次主密钥（`docker compose run --rm admin secret init`），启动后首次设置链接会写在
`data/state/admin-setup-link`。也可运行 `docker compose run --rm admin admin setup` 查看；链接丢失或过期用
`docker compose run --rm admin admin setup --rotate` 更新。链接 24 小时有效，只能成功初始化一次；注册后文件删除。
把此链接私下交给管理员。若该身份已有 Passkey，则直接打开 `/admin/` 登录，不再生成初始化链接。

管理员随后全部在网页操作：

1. 打开设置链接，用 Touch ID、设备密码或安全密钥创建 Passkey。
2. 在「群组成员」添加个人，选择所属群组；使用网页生成的 15 分钟邀请链接注册审批 Passkey。
3. 在「连接器」添加模拟笔记、IMAP、CalDAV、Gmail、HTTPS Reminders helper 或远程 MCP，审阅工具定义后应用。
4. 点「验证连接」执行一次真正的只读请求。只启动了工具进程不表示上游账号凭据有效。
5. 在「Agent 接入」创建独立 Token，选择所属群组，复制一次显示的值及 MCP 地址到客户端。新 Agent 默认没有工具。
6. 点击该 Agent 的「配置权限」，按连接选择「禁止访问」「只读」或「读写」。
   「读取审批」和「写入审批」可分别配置。内置邮件连接把「邮箱整理审批」和「发信审批」分开：
   发信可以禁止、逐次审批或明确允许免审批。升级后旧版的免审批发信规则按逐次审批执行。
   YAML 如需免审批发信，在仅包含内置发信工具的 `effect: allow` 规则中显式设置 `mail_send_direct: true`。
   需要审批时核对具体内容，通过 Passkey 批准一次。审批人可选某位成员或「群组内任意成员」，与 owner 独立。
   同一连接的审批人设置适用于所有 Agent。没有写入工具的连接器只显示只读选项；现有自定义工具规则不会自动改写。
   逐工具权限和参数限制收在「高级设置」；参数限制适用于该暴露工具的所有 Agent。加入群组不会自动获得工具权限。

「Agent 接入 → 改名」可修正名称中的拼写错误，同时更新该 Agent 的授权引用。原 Token、MCP 地址和群组归属不变，
客户端无需重新配置；未完成的审批需重新发起。重用旧名称不会继承权限，历史审计记录保留当时的名称。

点击右上角姓名，或「群组成员 → 修改名称」，可以直接修改名字，支持中文和空格，不再有另一个显示名称字段。
内部凭据绑定、权限、现有 Passkey、管理会话和待处理审批不变。
名称保存在加密的 `admin.enc` 中。连接器预览会显示加载状态；校验或网络错误直接显示在当前弹窗中，已填写内容会保留。
预览只读取工具定义。内置连接器的「验证连接」检查实际账号访问；通用远程 MCP 只验证初始化和工具定义，不执行上游业务工具。
验证失败会在连接器卡片上保留原因，区分用户名/密码被拒、TLS/DNS/网络失败、权限不足和工具定义变化。
其他表单错误保留在当前页面或弹窗；服务器故障提供错误编号，可在审计日志中关联定位，不显示密码或上游原始响应。
Google 回调失败也会显示管理页面。iCloud Mail 登录用户名通常是 `@icloud.com` 前的部分，也可尝试完整邮箱地址；
密码须为 [Apple App 专用密码](https://support.apple.com/en-us/102654)，设置参见 [Apple 的 IMAP 说明](https://support.apple.com/en-us/102525)。

在「连接器 → 添加连接器」选择 **Gmail (Google OAuth)**。首次 [在 Google Cloud](https://console.cloud.google.com/auth/clients)
启用 Gmail API，创建 **Web 应用** OAuth 客户端，登记网关显示的重定向 URI，再导入 Google 下载的客户端 JSON。
选好权限后点「通过 Google 授权」：
- 只读：`gmail.readonly`。
- 读取和发送：`gmail.readonly` + `gmail.send`。
- 读取和整理／读取、整理和发送：`gmail.modify`。Gmail 的此 scope 也允许发信，网关仅在所选档位包含发送时开放发送工具。

到「权限」为各 Agent 单独授权。取消某项能力会移除相应工具，也清除已有授权。
Gmail 的移动在一封邮件上添加目标标签、移除来源标签，并保留其他标签；归档只移除 `INBOX`。
刷新令牌由网关加密保存。手动录入和 Desktop OAuth CLI 仍可用于已有凭据。

无法使用 OAuth 时，可选择「邮箱 (IMAP + SMTP) → Gmail」，填写完整邮箱和 [Google App 专用密码](https://support.google.com/mail/answer/185833)。
Google 账号需要开启两步验证，部分账号不提供 App 专用密码。

<a id="remote-mcp"></a>

### 远程 MCP 与 OAuth

在「连接器 → 添加连接器」选择「远程 MCP」，填写 HTTPS MCP 地址。相同服务的不同账号使用相同服务标识，
各自创建独立连接。认证可选无需认证、Bearer Token、API Key Header 或 OAuth。
更换地址时必须重新提供凭据；原地址的凭据不会自动发送给新地址。

OAuth 会发现服务的授权服务器并打开授权页。服务商支持动态注册时，客户端字段可以留空；
否则填写已注册的 client ID、issuer 和客户端认证方式。保密客户端还需 client secret。
把 `https://<网关域名>/admin/oauth/mcp/callback` 登记为回调地址。
支持客户端元数据 URL 的服务商也可使用该方式，不能同时填写 client ID。
Scope 留空时使用 MCP 服务要求的范围，填写时用空格分隔；授权页和工具审阅页会显示范围。
授权服务器必须支持 PKCE S256。

授权完成后选择开放的工具，审阅 schema 并确认读写分类。网关按名称为 get、list、search、query 等操作建议读取，
含义不明确或可能修改数据的操作建议写入。保存后在「权限」为 Agent 授权；新增工具默认拒绝。
「审阅当前工具」重新发现工具和定义；未审阅的定义变化会阻止调用。
取消选择的工具，以及从读取改为写入的工具，会移除原有授权。

OAuth 的 access token、refresh token、客户端信息及发现的元数据保存在 `admin.enc.oauth`（与管理员状态文件相邻），
使用现有主密钥加密。刷新令牌轮换和绝对过期时间会持久化；刷新不修改权限版本。
未返回刷新令牌的服务在访问过期后需要重新授权，界面会提示。
「撤销授权」立即清除本地 Token，再尝试服务商的撤销接口；界面区分服务商已确认、未支持或未确认的结果。
删除连接会删除网关保存的授权；如需在服务商侧撤销，请先使用「撤销授权」或其账号管理页面。

网页新增凭据和配置保存在 `admin.enc`，主密钥、原有 YAML/lock/secret 挂载继续只读。备份需包含 `admin.enc`、存在时的 `admin.enc.oauth` 和
`approvals.sqlite`，主密钥单独保存。第一次网页保存后，五个账号配置段由加密状态覆盖 YAML；主机设置仍来自 YAML。
网页不支持任意命令/自定义连接器部署。停用 `admin` 会停用这些覆盖，迁回 YAML 前需由部署者整理出有效配置。

管理会话默认 30 分钟；请在 Agent 无法控制的设备或浏览器中登录。授予权限、更换审批人、签发或轮换 Token、
管理 Passkey 以及应用连接器设置时，需要再次用管理员 Passkey 确认本次操作。
接入或权限配置变更会等待正在执行的调用结束，最多 30 秒；这类修改会使旧审批失效。
最后一个管理员 Passkey 不能从网页删除；所有设备都丢失时，由主机管理员用 `agw approval enroll <admin.owner>`
生成恢复注册链接，再从网页撤销丢失的 Passkey。

## 9. 日常操作

启用网页管理时，优先使用 `/admin/` 完成成员、Token、连接器和权限操作；`agw check` 会显示包含网页覆盖的有效配置。
以下命令流程用于未启用网页管理的 YAML 模式。

**改权限**：改 `gateway.yaml` → `check` → `docker compose restart gateway`。

**上游工具定义变了**：Gateway 会自动下线该工具，并在审计日志里写一条 `tool_blocked`（`definition_changed` /
`missing_upstream`）。处理方式：`lock` 看 diff → 确认无害后 `lock --write` → 重启。升级 Connector 版本后必然要走一遍。

**轮换客户端 Token**：`token` 生成新的 → 替换配置里的哈希 → 重启 → 更新 Agent 侧配置。旧 Token 立即失效。
怀疑泄露时也是这个流程。

**轮换上游凭据**：先在服务方吊销旧的（Apple 账号页的 App 专用密码、Google 账号的第三方应用访问权）→ `secret set` 录入新的 → 重启。

**撤销一个 Agent**：删除它的 `clients` 条目 → 重启。

**Agent 说某个工具用不了**：Agent 收到的都是固定文字，对应关系如下。

| Agent 收到 | 原因 | 处理 |
|---|---|---|
| `…rejected this account's credentials…` | App 专用密码被吊销或录错；之后 60 秒内的调用直接得到同一句话 | 生成新密码 → `secret set` → 重启 |
| `Google no longer accepts this account's authorisation…` | refresh token 过期或被撤销（「Testing」状态下每 7 天一次） | 重新跑 `gmail_auth` → 重启 |
| `The stored Google token allows more than reading mail…` | 存进去的 Token 不是只读 scope | 用 `gmail_auth` 重新授权，不要用别处得到的 Token |
| `…could not be reached…` | 网络或上游服务故障 | 通常自己恢复 |
| `The upstream service is currently unavailable.` | Connector 进程没起来或刚被重启 | 看容器日志；Gateway 会自动重连 |
| `This tool is disabled until an administrator reviews its definition.` | 上游工具定义和锁文件不一致 | `lock` |
| `This action needs human approval and was not executed.`（没有链接） | 没有配置 `approvals:`，或当前指定审批人没有已登记 Passkey | 第 6 节 |

## 10. 备份与恢复

| 文件 | 内容 | 备份方式 |
|---|---|---|
| `key/master.key` | 解密 `secrets.enc` 的密钥 | **只**放密码管理器，不进入任何自动备份 |
| `secrets/secrets.enc` | 加密后的上游凭据 | 可以随常规备份；没有密钥时无法解开 |
| `state/admin.enc` | 网页管理的配置、Token 哈希、工具定义和加密凭据（启用网页时） | 与配置一起备份，主密钥仍单独保存 |
| `config/gateway.yaml`、`config/tools.lock.json` | 配置和已审阅的工具定义；只含 Token 的哈希 | 常规备份，或放私有仓库 |
| `state/approvals.sqlite` | 已登记 Passkey 的公钥、近期审批请求 | 可以备份，也可以不备份：丢了的后果是每个人重新登记一次。它不含私钥，但含待处理请求的参数 |
| `state/audit/` | 审计日志 | 按需 |

密钥和密文分开放，是这份加密唯一的意义：密文单独泄露不等于凭据泄露。把两者放进同一个备份就失去了这个意义。

**恢复**：把文件放回原位（密钥从密码管理器取回，权限 `0600`、属主 10001）→ `check` → 启动。
从备份恢复 `approvals.sqlite` 会把当时已登记的 Passkey 一起恢复，包括之后被你 `forget` 掉的；恢复后用 `approval passkeys` 核对一遍。

**密钥丢了**：`secrets.enc` 无法恢复。删掉它和旧密钥，重新 `secret init`，到各服务方重新生成凭据后逐个 `secret set`。
这些凭据都是可以重新签发的，所以丢密钥是麻烦，不是灾难。

**主机被入侵或怀疑被入侵**：按「全部凭据已泄露」处理：在各服务方吊销所有上游凭据，换新主机，
重新生成主密钥、所有上游凭据和所有客户端 Token，删掉 `approvals.sqlite` 让所有人重新登记 Passkey。

## 11. 审计日志

`state/audit/audit.jsonl`，每行一个 JSON，每个 UTC 日切一个文件，保留 `audit.retention_days` 个。

事件：`tool_call`、`auth_failed`、`tool_blocked`、`startup`，以及审批相关的 `approval_requested`、`approval_decided`、
`passkey_enrolled`、`passkey_removed`。

记录的字段：时间、事件、client、principal、tool、connection、service、account、上游工具名、decision、reason、
耗时、结果字节数、参数**名**、来源地址、审批请求 id、批准者。

不记录：参数值、结果内容（邮件、日程、提醒事项的任何文字）、Token、凭据、上游错误原文。

`remote` 是 Gateway 进程看到的对端地址。容器部署下它取决于 Docker 网络：从外部网卡进来的连接通常保留源地址，
经 Docker 本机转发或 `tailscale serve` 的连接会显示成网桥或本机地址。部署后先看一眼实际记录到的值，再决定能不能靠它判断调用来自哪台机器。

```sh
jq -c 'select(.decision != "allow")' data/state/audit/audit.jsonl      # 所有被拒绝和出错的调用
jq -c 'select(.event == "auth_failed")' data/state/audit/audit.jsonl   # 无效 Token 的尝试
jq -r 'select(.event == "tool_call") | [.principal, .tool] | @tsv' data/state/audit/audit.jsonl | sort | uniq -c
```

审计日志由 Gateway 自己写，能控制 Gateway 主机的人也能改它。它用于发现 Agent 的异常行为，不是防篡改的证据。

## 12. 升级

```sh
git pull
docker compose build
docker compose run --rm admin check
docker compose run --rm admin lock      # Connector 版本变了就会有 diff
docker compose up -d
```

依赖版本锁在 `requirements.txt`（带哈希）。升级依赖 = 重新生成该文件并跑完整测试，不要在镜像里放开版本。
