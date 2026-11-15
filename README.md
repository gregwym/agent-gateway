# agent-gateway

A self-hosted MCP proxy that gives agents access to approved tools while keeping
upstream credentials on the gateway. Connect multiple agents to one endpoint,
grant access per connection, and require human approval for selected operations.

[Product requirements](docs/requirements.md) · [Design](docs/design.md) ·
[Deployment](docs/deployment.md) · [MIT license](LICENSE)

## Why use it

| Need | What the gateway provides |
|---|---|
| Connect several agents to several services | One MCP endpoint with named upstream connections |
| Keep service credentials out of agent environments | Separate gateway tokens; upstream secrets stay in an encrypted store |
| Control which accounts and operations an agent can use | Default-deny grants per agent, connection and tool, with argument restrictions |
| Require a person to authorize an operation | One-use Passkey approval bound to the exact account, tool and arguments |
| Keep large tool catalogs out of the agent's initial context | Searchable tool and connection metadata, filtered by current permissions |
| Diagnose access and execution failures | Actionable administration errors and metadata-only audit logs |

```text
MCP clients                 agent-gateway                 Upstream MCP servers
  Agent A ── token A ──┐     authenticate                  account / credential A
  Agent B ── token B ──┼──►  authorize + approve  ──────►  account / credential B
  Agent C ── token C ──┘     route + audit                 shared service account
                            /mcp                          stdio or Streamable HTTP
```

Agents interpret and combine results. Upstream servers provide service operations.
The gateway handles access and execution; it does not build a business database,
aggregate service data, or call an LLM. It uses the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

## Capabilities

- **Explicit access.** New agents, connections and newly introduced tools start
  without grants. Account ownership and group membership do not grant tool access.
- **Independent read and write policies.** Each can be denied, allowed directly,
  or require approval for every call. A connection's approver can be a member or
  any member of its group, independently of its owner.
- **Account-bound routing.** Each connection uses one service account and its
  credentials. Each agent token identifies a client, not the person chatting with it.
- **Reviewed tools.** Names, descriptions and schemas are locked. Changes to remote
  definitions disable affected tools until reviewed. Bundled connector definitions
  reconcile on upgrade; new tools stay denied and existing restrictions are preserved.
- **Argument restrictions.** Fixed parameters and allowed values constrain resources
  such as a mailbox or calendar. Callers cannot override fixed parameters.
- **Web administration.** Passkey onboarding, members, agent tokens, connector setup,
  permission editing and connection checks. Changes apply atomically after active
  calls finish. The current member-group configuration uses the name `household`.
- **Audit.** Records include client, connection, tool, outcome and timing. They omit
  argument values, message bodies and tool results.

## Discover and call tools

The default MCP tool list contains three entry points:

| Tool | Purpose |
|---|---|
| `gateway_search_tools` | Find permitted tools and their parameter schemas |
| `gateway_search_connections` | Find permitted connections, restrictions and approval requirements |
| `gateway_call_tool` | Call a tool on a selected connection |

Example `tools/call` parameters using the demo configuration:

```json
{"name":"gateway_search_tools","arguments":{"query":"notes"}}
{"name":"gateway_search_connections","arguments":{"tool":"notes_add_note"}}
{"name":"gateway_call_tool","arguments":{"tool":"notes_add_note","connection":"notes-a","arguments":{"folder":"inbox","text":"Example note"}}}
```

Searches operate on metadata, not account contents. Both support `query`, `offset`
and `limit` (1–25). Use the returned `next_offset` to continue. Tool search can
filter by `connection`; connection search can filter by `tool` and returns the
exact schema for each permitted binding. Supply `variant` when a connection has
multiple restricted bindings for the same tool.

For IMAP and Gmail, connection search also matches known mailbox addresses. In
the IMAP connector's **Mailbox addresses** settings, add one alias per line.
The primary address and aliases point to the same connection. Gmail addresses
are recorded when the account is authorized through the web UI.

Use **Rename** on a connector to change its connection ID. Credentials and
permissions carry over. Update workflows that pass the old connection ID and
request unfinished approvals again.

Every call rechecks permissions, parameters and approval requirements. A call
requiring approval returns a link without executing. After approval, the agent
repeats the same call; the grant is consumed once. A failed upstream write is not
automatically retried.

Clients upgrading from the full tool listing must refresh it once. Subsequent
permission changes are visible through search. Legacy tool names remain callable
under the same checks; `server.tool_discovery: all` restores the full listing.

## Current status

The core proxy, web administration, Passkey approval and bundled connectors are
implemented. Automated acceptance uses isolated simulated accounts, local service
implementations and virtual WebAuthn authenticators. This does not establish full
compatibility with every provider or physical authenticator.

| Connector | Available operations | Limits |
|---|---|---|
| IMAP + SMTP | Search, paginated listing, message and attachment reads, batch reads, read/star flags, move/archive/trash, send | One connection per account; SMTP sending has no attachment support |
| CalDAV | List calendars and events, read events, check conflicts | Read-only; event listing has a result limit and no continuation cursor |
| Gmail | Search, message and attachment reads; browser OAuth with `gmail.readonly` | No search continuation, batch reading or writes |
| Apple Reminders | List reminder lists and reminders, read details | Experimental, read-only; requires a macOS helper and local authorization |

IMAP reads use `EXAMINE` and `BODY.PEEK`, so reading does not mark mail as seen.
Pagination uses an in-memory UID snapshot; new arrivals need a new listing, and
restart invalidates cursors. Batch operations report a result for each requested
message, including unknown or unattempted outcomes. SMTP acceptance does not prove
delivery. See [deployment and connector behavior](docs/deployment.md) for limits.

Built-in connectors save directly using the tools shipped with Gateway. Use
**Edit settings** to change a connection's settings while keeping its tool grants.

For a remote Streamable HTTP MCP server, select **Remote MCP** and search the
[MCP Registry](https://registry.modelcontextprotocol.io/) to find a published
HTTPS endpoint. Review the tools when adding or changing an endpoint. Choose
which tools to expose and classify them before granting Agent access. Remote
connections support OAuth, Bearer or API-key headers, and unauthenticated
endpoints. OAuth tokens stay encrypted and refresh automatically.

Custom stdio commands remain host-configured. Gateway-client OAuth and an external
approval-service adapter are not implemented. See the [product requirements](docs/requirements.md)
and [remote connection setup](docs/deployment.md#remote-mcp).

## Quick start

Python 3.11+. Run from a checkout of this repository; installation is from local
source, not a package with the same name on PyPI.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[connectors]'

mkdir -p run/config
cp deploy/gateway.example.yaml run/config/gateway.yaml
export AGW_CONFIG=run/config/gateway.yaml

agw token            # run for each demo client; put the hashes in gateway.yaml
agw secret init
agw secret set notes_key_a
agw secret set notes_key_b
agw secret set notes_key_house

agw lock             # inspect the tool definitions before accepting them
agw lock --write
agw check
agw serve
```

The demo secrets can contain arbitrary test values. The configuration deliberately
refuses to start until its token hashes and secrets have been supplied. It includes
multiple clients and accounts for testing isolation without external services.

Configure a client with:

- Endpoint: `http://127.0.0.1:8080/mcp` for a local demo; an HTTPS endpoint for remote use.
- Transport: Streamable HTTP.
- Header: `Authorization: Bearer <gateway-client-token>`.

For browser administration, use
[gateway.web.example.yaml](deploy/gateway.web.example.yaml). The host creates a
private, one-time setup link; complete Passkey registration, then use `/admin/`
to connect accounts and grant agent access. Agent tokens cannot access the console.
See [deployment instructions](docs/deployment.md) for setup, Docker Compose,
HTTPS, connector credentials, approvals and backups.

## Security boundaries

- The gateway host, administrator and local stdio connectors are trusted. Anyone
  who controls that host or runtime can access credentials and change policy.
- A shared agent token provides one permission set for everyone using it. Tool
  arguments and prompts cannot establish an end-user identity.
- Gmail's read-only scope is enforced by the provider. IMAP app passwords and
  EventKit permissions can permit writes even when the gateway grants only reads.
- Tool results can contain prompt injection. The gateway enforces access boundaries
  but does not interpret content or control the agent's downstream data handling.
- TLS is provided by a reverse proxy or encrypted private network. General rate
  limiting and OAuth authentication for gateway clients are not implemented.
- Only MCP tools are proxied. Resources, prompts, sampling and elicitation are not.
  The gateway exposes no unrestricted HTTP, shell or SSH tool.

## Development and acceptance

```sh
pip install -e '.[dev,browser-tests]'
python -m playwright install chromium
python scripts/acceptance.py --docker
```

The suite covers account isolation, permissions, secret handling, tool definition
changes, approval replay, connector operations, browser flows and container
recovery. It uses temporary fixtures rather than production accounts. Reports,
logs and screenshots are written to `run/acceptance/`. Provider-specific checks
are documented separately in [deployment.md](docs/deployment.md).
