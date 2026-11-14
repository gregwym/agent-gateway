# 部署

## 1. 代码保证不了、必须由部署保证的事

Gateway 的全部安全性建立在一条前提上：**Agent 不能读、不能改、不能重启 Gateway 所在的环境。**
以下任何一条不成立，Gateway 的隔离就不成立，代码对此无能为力：

- Agent（尤其是有运维权限的 OpenClaw）在 Gateway 主机上没有 shell、SSH、root，也不在 `docker` 组；
- Agent 不能通过任何部署通道修改 Gateway 的配置、镜像、Compose 文件或环境变量；
- Agent 读不到 Gateway 的数据目录（`config/`、`secrets/`、`key/`），也读不到它们的备份；
- Agent 只能通过网络访问 Gateway 的 `/mcp` 端口，访问不到上游 Connector 和上游凭据；
- 个人 Token 不存放在其他 Agent 能读到的地方（见 [design.md](design.md) 第 5 节）。

Docker 容器不是这里的安全边界。Compose 文件里的非 root、只读根文件系统、去掉 capabilities，
限制的是「Gateway 自己出 bug 时能做什么」，不限制主机管理员。

## 2. 放在哪台机器

| 位置 | 评价 |
|---|---|
| 专用小主机（如 Raspberry Pi），只跑 Gateway，Agent 在上面没有任何账号 | **推荐。** 前提最容易成立，也最容易说清楚 |
| Synology NAS 上的一个 Compose 项目 | 可以，但有条件：通过 Compose Deployer **永远不要**给 Agent 这个项目的 `manage` 或 `elevated` 授权（那等于能读文件、改 compose、进容器）；Agent 没有 NAS 的 SSH / DSM 管理员。`read *` 授权能看到容器日志，Gateway 的日志里没有密钥、参数值和结果内容 |
| 和 OpenClaw 同一台 Mac mini | **不要放真实凭据。** OpenClaw 在那台机器上权限很高，Gateway 的文件和容器运行时都在它够得着的地方。只适合跑 demo |

## 3. 安装（Docker Compose）

> 已验证的环境：linux/arm64，Docker 29，Compose v5。验证内容：镜像构建、容器内的全部管理命令、启动与健康检查、
> 以 uid 10001 运行且无任何 capability、配置 / 密钥 / 密文只读挂载、缺少密钥文件时拒绝启动、Connector 进程被杀后自动重连。
> linux/amd64 没有实测，只确认了所有依赖都有带哈希的 wheel。

在 Gateway 主机上，由人执行：

```sh
git clone https://github.com/gregwym/agent-gateway && cd agent-gateway/deploy

mkdir -p data/config data/secrets data/key data/state
cp gateway.example.yaml data/config/gateway.yaml
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

不用 Docker 时，`pip install .` 后直接用 `agw` 命令，步骤相同；用一个专用的系统用户运行，数据目录权限 `0700`。

## 4. 网络

- 端口只发布在 **一个地址** 上：本机的 Tailscale IP，或 `127.0.0.1` 再由 `tailscale serve` 提供 HTTPS。不要发布到 `0.0.0.0`。
- 用 Tailscale ACL 限制谁能连。只放行 Agent 所在节点到 Gateway 端口，不给任何到 Gateway 主机的 SSH：

  ```json
  { "grants": [ { "src": ["tag:agent"], "dst": ["tag:agent-gateway"], "ip": ["tcp:8080"] } ] }
  ```

- Gateway 以主机名被访问时，设置 `server.allowed_hosts`（如 `["agent-gateway.your-tailnet.ts.net:8080"]`），
  开启 Host 头校验并拒绝带 `Origin` 的浏览器请求（防 DNS rebinding）。
- Gateway 不需要入站公网访问。出站只需要到各上游服务。

## 5. 日常操作

**改权限**：改 `gateway.yaml` → `check` → `docker compose restart gateway`。没有热加载，这是有意的。

**上游工具定义变了**：Gateway 会自动下线该工具，并在审计日志里写一条 `tool_blocked`（`definition_changed` /
`missing_upstream`）。处理方式：`lock` 看 diff → 确认无害后 `lock --write` → 重启。升级 Connector 版本后必然要走一遍。

**轮换客户端 Token**：`token` 生成新的 → 替换配置里的哈希 → 重启 → 更新 Agent 侧配置。旧 Token 立即失效。
怀疑泄露时也是这个流程。

**轮换上游凭据**：先在服务方吊销旧的（Apple ID 的 App 专用密码、Google 的应用授权）→ `secret set` 录入新的 → 重启。

**撤销一个 Agent**：删除它的 `clients` 条目 → 重启。

## 6. 备份与恢复

| 文件 | 内容 | 备份方式 |
|---|---|---|
| `key/master.key` | 解密 `secrets.enc` 的密钥 | **只**放密码管理器，不进入任何自动备份 |
| `secrets/secrets.enc` | 加密后的上游凭据 | 可以随常规备份；没有密钥时无法解开 |
| `config/gateway.yaml`、`config/tools.lock.json` | 配置和已审阅的工具定义；只含 Token 的哈希 | 常规备份，或放私有仓库 |
| `state/audit/` | 审计日志 | 按需 |

密钥和密文分开放，是这份加密唯一的意义：密文单独泄露不等于凭据泄露。把两者放进同一个备份就失去了这个意义。

**恢复**：把四类文件放回原位（密钥从密码管理器取回，权限 `0600`、属主 10001）→ `check` → 启动。

**密钥丢了**：`secrets.enc` 无法恢复。删掉它和旧密钥，重新 `secret init`，到各服务方重新生成凭据后逐个 `secret set`。
这些凭据都是可以重新签发的，所以丢密钥是麻烦，不是灾难。

**主机被入侵或怀疑被入侵**：按「全部凭据已泄露」处理：在各服务方吊销所有上游凭据，换新主机，
重新生成主密钥、所有上游凭据和所有客户端 Token。

## 7. 审计日志

`state/audit/audit.jsonl`，每行一个 JSON，每个 UTC 日切一个文件，保留 `audit.retention_days` 个。

记录的字段：时间、事件（`tool_call` / `auth_failed` / `tool_blocked` / `startup`）、client、principal、tool、
connection、service、account、上游工具名、decision、reason、耗时、结果字节数、参数**名**、来源地址。

不记录：参数值、结果内容、Token、凭据、上游错误原文。

`remote` 是 Gateway 进程看到的对端地址。容器部署下它取决于 Docker 网络：从外部网卡进来的连接通常保留源地址，
经 Docker 本机转发的连接会显示成网桥地址（如 `172.18.0.1`）。部署后先看一眼实际记录到的值，再决定能不能靠它判断调用来自哪台机器。

```sh
jq -c 'select(.decision != "allow")' data/state/audit/audit.jsonl      # 所有被拒绝和出错的调用
jq -c 'select(.event == "auth_failed")' data/state/audit/audit.jsonl   # 无效 Token 的尝试
jq -r 'select(.event == "tool_call") | [.principal, .tool] | @tsv' data/state/audit/audit.jsonl | sort | uniq -c
```

审计日志由 Gateway 自己写，能控制 Gateway 主机的人也能改它。它用于发现 Agent 的异常行为，不是防篡改的证据。

## 8. 升级

```sh
git pull
docker compose build
docker compose run --rm admin check
docker compose run --rm admin lock      # Connector 版本变了就会有 diff
docker compose up -d
```

依赖版本锁在 `requirements.txt`（带哈希）。升级依赖 = 重新生成该文件并跑完整测试，不要在镜像里放开版本。
