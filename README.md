# agent-gateway

A small, self-hosted MCP gateway for a household. Personal AI agents connect to
one MCP endpoint; the gateway decides **who is calling** from the credential the
agent presents, shows that caller **only the tools they were given**, and makes
the upstream calls with **credentials the agent never sees**.

```
 OpenClaw (shared) ── token H ──┐                      ┌─ stdio ── connector: person_a's account   (credential A)
 MausBot for A ────── token A ──┤   Streamable HTTP    │
 MausBot for B ────── token B ──┼──►  agent-gateway  ──┼─ stdio ── connector: person_b's account   (credential B)
 Codex / Claude ──────  ...  ───┘                      │
                                 identity → policy →   └─ https ── MCP server: household account   (credential H)
                                 locked definition →
                                 arguments → audit
```

The gateway is about 2,250 lines of Python (comments included) on top of the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk); the bundled
read-only connectors are about 1,400 more. There is no admin API and no dashboard:
one YAML file, one lock file, one encrypted secret file, one audit log and, when
approvals are enabled, one SQLite file and one web page.

**Status.** The gateway core, passkey approval and read-only connectors for iCloud
Mail, iCloud Calendar and Gmail are implemented and tested against local stand-ins
(a real IMAP server, a real CalDAV server, a fake Google, and software passkeys).
The approval page also runs in real Chromium with a virtual WebAuthn authenticator;
Reminders is exercised through two gateway helpers with an EventKit substitute.
**Nothing here has been run against a real iCloud or Google account or a real
authenticator yet.** The Reminders connector is experimental. See
[what it does not do](#what-it-does-not-do), and the checklist of what to verify
yourself in [docs/deployment.md](docs/deployment.md) (中文).

## What it does

- **Identity from the token, nothing else.** Each client has its own bearer token,
  bound to exactly one principal (`person_a`, `person_b`, `household`). Tool
  arguments, headers, cookies and session ids cannot change who the caller is.
- **Default deny, explicit allowlist.** A tool exists for a principal only if a rule
  names that principal and that tool. Everything else is not listed and not callable,
  and "not yours" is indistinguishable from "does not exist". No wildcards.
- **One connection per account.** Each upstream MCP server process is bound to one
  account and receives only that account's credential. Reaching into another
  principal's account needs an explicit `cross_account: true` in the rule.
- **Argument restrictions.** A tool can be exposed with arguments fixed (`pin`) or
  limited to listed values (`allow_values`), e.g. "the family calendar only".
  Arguments that are not in the reviewed schema are rejected.
- **Locked tool definitions.** Names, descriptions and schemas are reviewed once and
  stored in `tools.lock.json`. Agents are served the locked text. If an upstream
  changes a definition, that tool is withdrawn until a human re-reviews it; new
  upstream tools never appear on their own.
- **Credentials stay behind.** Upstream secrets live in an encrypted file, are handed
  only to their own connector, and known secret values are scrubbed from results.
  Errors shown to agents are fixed strings.
- **Audit without content.** One JSON line per call and per failed login: who, which
  tool, which account, outcome, sizes, argument *names*. No argument values, no results.
- **Approval by passkey.** A rule can say `approval_required`. Such a call waits until
  the account's owner approves that exact call (same client, account, tool and
  arguments) with a passkey, runs once, and needs a new approval the next time.
  Without an `approvals:` section such a tool is visible and **never runs**.
- **Read-only connectors included.** iCloud Mail (IMAP), iCloud Calendar (CalDAV) and
  Gmail, one process per account, searching and reading on demand: no mailbox is
  synchronised or indexed. See [bundled connectors](#bundled-connectors).

## What it does not do

Read this list before trusting it with real accounts. Details and reasons are in
[docs/design.md](docs/design.md) (中文).

- **It cannot protect secrets from someone who controls its host.** Root, the Docker
  group, or code running as the gateway's user can read everything. Where it runs is
  the real boundary: see [docs/deployment.md](docs/deployment.md) (中文).
- **It cannot tell which person is talking to a shared agent.** A token proves which
  *client* is calling. A token stored where another agent can read it proves nothing.
  Agents that serve both people must be given a `household` client.
- **Physical passkeys have not been tested.** The approval tests cover the real
  Chromium page and WebAuthn API with a virtual authenticator, plus server-side
  signature checks. Whoever can edit the config or approval store can bypass it.
- **It has not been verified against the real services.** The connectors were tested
  against pymap, Radicale and a stand-in for Google's API. iCloud and Gmail will
  differ somewhere.
- **"Read-only" is a credential property only for Gmail.** The Gmail token is limited
  to `gmail.readonly` by Google. An iCloud app-specific password can send mail and
  change calendars; there, read-only means the connector sends only read requests.
  macOS grants Reminders access as full access. A buggy or malicious connector can
  do whatever its credential allows.
- **No defence against prompt injection in content.** Mail bodies and other tool
  results are returned as they are. The gateway bounds what a misled model can
  *do* (its tools, its accounts); it does not stop the model from being misled.
- **Only MCP tools.** Resources, prompts, sampling and elicitation are not proxied.
- **No TLS, no rate limiting, no hot reload, no OS-keychain backend, no OAuth for
  clients.** Put it on a tailnet or behind a TLS terminator.
- **No generic HTTP, shell or SSH tools, by design.**

## Quick start (demo, no Docker)

Python 3.11+.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

mkdir -p run/config && cp deploy/gateway.example.yaml run/config/gateway.yaml
export AGW_CONFIG=run/config/gateway.yaml

agw token           # run three times; put each hash in place of one PASTE_HASH_FROM_agw_token
agw secret init     # creates run/key/master.key
agw secret set notes_key_a       # asks for the value; anything works for the demo
agw secret set notes_key_b
agw secret set notes_key_house

agw lock            # prints every tool definition the config refers to. Read them.
agw lock --write    # accept them into run/config/tools.lock.json
agw check           # prints who can call what
agw serve           # http://127.0.0.1:8080/mcp
```

Then, with one of the tokens:

```sh
curl -s http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Each token lists a different set of tools. `a_notes_add` is listed for person_a and
does not run: it answers "This action needs human approval and was not executed."
To try the approval flow, run `agw approval enroll person_a` and open the link it
prints in a browser on the same machine (the example config uses
`http://localhost:8080`) to create a passkey. Call `a_notes_add` again: the answer
now names a page where the request waits. Open it, approve, and repeat the same call.

## Docker Compose

```sh
cd deploy
mkdir -p data/config data/secrets data/key data/state
cp gateway.example.yaml data/config/gateway.yaml      # then edit it
sudo chown -R 10001:10001 data                        # the container runs as uid 10001

docker compose build
docker compose run --rm admin token                    # per client; paste the hashes into gateway.yaml
docker compose run --rm admin secret init
docker compose run --rm admin secret set notes_key_a   # and the others
docker compose run --rm admin lock --write
docker compose run --rm admin check

AGW_BIND=100.x.y.z docker compose up -d                # this host's Tailscale IP
```

The container runs as a non-root user with a read-only root filesystem, no
capabilities, and config, key and secrets mounted read-only. That limits what a bug
in the gateway can do. It is not isolation from the host's administrators.
Verified on linux/arm64 (Docker 29, Compose v5); on macOS with Colima or Docker
Desktop the `chown` is not needed.
Deployment constraints, real accounts, approvals, backup and rotation:
[docs/deployment.md](docs/deployment.md).

## Configuration

One file, read at startup. [deploy/gateway.example.yaml](deploy/gateway.example.yaml)
is a complete, commented demo;
[deploy/gateway.household.example.yaml](deploy/gateway.household.example.yaml) is two
people with iCloud Mail, iCloud Calendar and Gmail each.

| Key | Meaning |
|---|---|
| `server` | `host`, `port`, `allowed_hosts` (Host header check), `max_result_bytes` |
| `audit` | `path`, `retention_days` (one file per UTC day) |
| `secrets` | `path` of the encrypted store, `key_file` |
| `lock_file` | reviewed tool definitions, default `tools.lock.json` |
| `approvals` | `origin` (the https address people open to approve), `store` (SQLite file), `request_ttl_seconds`, `grant_ttl_seconds` |
| `principals` | the identities that exist |
| `shared` | principals whose accounts are meant to be shared (e.g. `household`) |
| `clients[]` | `id`, `principal`, `token_sha256`: one per credential handed out |
| `connections[]` | one upstream MCP server for one `(service, account)`, its `owner`, how to start or reach it, which secrets it gets, and its `tools[]` |
| `connections[].tools[]` | `upstream` name, exposed `name` (unique across the gateway), optional `description`, `pin`, `allow_values` |
| `policy[]` | `principals`, `connection`, `tools`, `effect` (`allow` / `approval_required` / `deny`), `cross_account` |

Unknown keys are errors. If several rules match, the strictest wins. Paths are
relative to the config file.

## Commands

| Command | Does |
|---|---|
| `agw serve [--host H] [--port P]` | run the gateway |
| `agw check` | validate the config; print each principal's access; exit 1 if a tool cannot be served |
| `agw lock [--write] [--connection ID]` | diff upstream tool definitions against the lock file; `--write` accepts them |
| `agw token` | mint a client token and print its hash (the token is not stored) |
| `agw secret init \| set NAME \| rm NAME \| list` | manage upstream credentials (values are read from a prompt or stdin, never from argv) |
| `agw approval enroll PERSON \| passkeys \| forget ID \| requests \| cancel ID` | register a person's passkey (prints a one-time link), list or remove passkeys, list recent requests, revoke an unused approval |

All take `-c FILE` or `$AGW_CONFIG`. They are run by a person on the gateway host;
none of this is reachable over the network.

## Connecting an agent

Every client needs three things: the URL (`http://<gateway>:8080/mcp`), the
Streamable HTTP transport, and the header `Authorization: Bearer <its own token>`.
The legacy SSE transport and OAuth are not offered.

**OpenClaw** (`openclaw.json`). OpenClaw on a shared machine cannot prove which
person is asking, so it gets the `household` client:

```json5
{
  mcp: {
    servers: {
      family: {
        url: "http://agent-gateway.your-tailnet.ts.net:8080/mcp",
        transport: "streamable-http",
        headers: { Authorization: "Bearer ${AGW_TOKEN_HOUSEHOLD}" },  // from the environment, not a literal
        requestTimeoutMs: 60000,
      },
    },
  },
}
```

**Claude Code** (`.mcp.json`) and other clients that use the `mcpServers` shape:

```json
{
  "mcpServers": {
    "family": {
      "type": "http",
      "url": "http://agent-gateway.your-tailnet.ts.net:8080/mcp",
      "headers": { "Authorization": "Bearer ${AGW_TOKEN}" }
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.family]
url = "http://agent-gateway.your-tailnet.ts.net:8080/mcp"
bearer_token_env_var = "AGW_TOKEN"
```

**MausBot and anything else.** Give it the same three values in whatever form its
MCP client configuration takes. Use one gateway client per person the bot serves,
and select the token in the bot's code from the authenticated chat user, never from
anything the model writes. If it cannot do that, give it one `household` client.

A client-side tool filter (such as OpenClaw's `toolFilter`) is a convenience. The
allowlist that counts is the gateway's.

## Bundled connectors

Each is a small stdio MCP server, started by the gateway as
`python -m agent_gateway.connectors.<module>` with one account's credential.

| Module | Service | Tools | Credential | Read-only is enforced by |
|---|---|---|---|---|
| `imap_mail` | iCloud Mail (any IMAP over TLS) | `list_mailboxes`, `search_messages`, `get_message`, `get_attachment` | app-specific password | the connector only (`EXAMINE`, `BODY.PEEK`); the password itself can write |
| `caldav_calendar` | iCloud Calendar (any CalDAV) | `list_calendars`, `list_events`, `get_event`, `check_conflicts` | app-specific password | the connector only (`PROPFIND`, `REPORT`); the password itself can write |
| `gmail` | Gmail REST API | `search_messages`, `get_message`, `get_attachment` | OAuth refresh token | Google (scope `gmail.readonly`); the connector refuses to use a token with any other scope |
| `reminders_eventkit` | Apple Reminders, macOS only, **experimental** | `list_lists`, `list_reminders`, `get_reminder` | none (a macOS permission) | the connector only; macOS grants full access |

Messages are searched on the server and fetched one at a time; long bodies are
returned in pages and attachments up to a size limit. A refused credential produces a
fixed message telling the agent that a person has to act, and the connector stops
presenting that credential for a while. `gmail_auth` is the one-time consent helper
that produces the Gmail token. Setup for each service, and what the Reminders
connector needs (a helper on that person's own Mac), is in
[docs/deployment.md](docs/deployment.md).

## Adding another service

A connector is an ordinary MCP server that follows four rules
([examples/demo_connector.py](examples/demo_connector.py) is the template):

1. One process (or one URL) serves exactly one account.
2. Its credential comes from the gateway: an environment variable for stdio, a header for HTTP.
3. No tool takes an account, user or credential argument.
4. Tool results never contain the credential.

Then: add a `connection`, store its secret with `agw secret set`, review its tools
with `agw lock`, add `policy` rules, restart. A stdio connector runs with the
gateway's own privileges, so its code is as trusted as the gateway's: review it and
pin its version. A tool that changes something should get `effect: approval_required`.
Why the bundled connectors were written rather than taken from existing iCloud MCP
projects is in [docs/design.md](docs/design.md).

## Development

```sh
pip install -e '.[dev]'
pytest
```

The tests start a real gateway on a local port in front of real connector
processes and cover: cross-user access, calls outside the allowlist, identity
spoofing through arguments and headers, credential leakage, tool-name collisions,
upstream definition changes, SSRF through URLs, redirects and schema references,
approval bypass and replay, the exposed HTTP surface, and upstream failure.
The connector tests run the mail connector against [pymap](https://github.com/icgood/pymap)
behind TLS, the calendar connector against [Radicale](https://radicale.org), and the
Gmail connector against a local stand-in for Google's token and API endpoints.

For the full simulated acceptance suite (no real accounts or credentials):

```sh
pip install -e '.[dev,browser-tests]'
python -m playwright install chromium
python scripts/acceptance.py --docker
```

The command runs all tests, including the actual approval page in Chromium and
Reminders through two simulated Mac helpers. With `--docker`, it also builds the
image and checks non-root execution, read-only mounts, account isolation, approvals
surviving restart, and connector recovery. It creates only disposable test volumes
and removes them afterwards. Omit `--docker` when no Docker daemon is available.
Reports (`report.json`, JUnit XML, logs and browser screenshots) are saved under
`run/acceptance/`. The JSON report identifies the tested source snapshot.
[GitHub Actions](.github/workflows/acceptance.yml) runs this on Linux and macOS;
the Linux Python 3.12 job includes Docker. These simulations do not certify real
Apple/Google accounts, physical authenticators or macOS permission prompts.

The project is not published on PyPI; install it from a clone.
`requirements.txt` pins the versions the tests ran against, with hashes, and is what
the image installs. Regenerate it with
`pip-compile --generate-hashes --strip-extras --extra connectors -o requirements.txt pyproject.toml`.

## License

[MIT](LICENSE)
