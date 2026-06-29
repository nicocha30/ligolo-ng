# MCP Server (`relaymcp`)

`relaymcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes the Ligolo-ng Relay control plane to MCP clients such as Claude
Code, Claude Desktop, or any MCP-compatible agent. It is the MCP counterpart of
[`relayctl`](RELAY_API.md#relayctl): it authenticates to the proxy REST API and
maps each relay/tunnel/chain operation to an MCP tool, so an AI agent can list
agents, inspect relay-chain health, preview and apply route repairs, fail over
relayed agents, and manage relays, tunnels, listeners, interfaces, and routes.

It does **not** touch the tunneling data path — it is a thin client over the
same authenticated `/api/v1` REST API the Web UI and `relayctl` already use.

There are two ways to run it: the standalone `relaymcp` binary (this is the
client-side bridge, covered first below), or **embedded in the proxy itself**
(`proxy -mcp` / `-mcp-api`, see [Embedded mode](#embedded-mode-in-the-proxy)) —
same tools, no separate process.

## Prerequisites

Run the proxy with the API enabled and credentials set (same as `relayctl`):

```
proxy -daemon -selfcert -api -no-web-ui \
  -api-laddr 127.0.0.1:8080 \
  -web-user relay -web-password 'change-me'
```

`relaymcp` reads the same configuration as `relayctl`:

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-api` | `LIGOLO_API` | `http://127.0.0.1:8080` | proxy API base URL |
| `-user` | `LIGOLO_USER` | | API username |
| `-password` | `LIGOLO_PASSWORD` | | API password |
| `-token` | `LIGOLO_TOKEN` | | API bearer token (instead of user/password) |

The server obtains a JWT on first use and **refreshes it automatically** when it
expires (the proxy's tokens have a ~1h TTL), so it can run for a long session
without restarts.

## Transports

### stdio (default — local clients)

With no `-http` flag, `relaymcp` speaks MCP over stdin/stdout. This is the mode
used by Claude Code / Claude Desktop, which spawn the binary as a subprocess.
All logging goes to stderr; stdout carries only the MCP stream.

For a **remote** proxy, point `LIGOLO_API` at a local port forwarded to it:

```
ssh -L 8080:127.0.0.1:8080 user@proxy-host
# then LIGOLO_API=http://127.0.0.1:8080
```

### streamable HTTP (remote clients)

```
relaymcp -http 127.0.0.1:9090
```

This serves the MCP streamable-HTTP endpoint, letting a remote agent connect
over the network. Because this is a control plane for offensive tooling, the
HTTP transport is locked down:

- Binding a **non-loopback** address (e.g. `0.0.0.0:9090`) **requires** a bearer
  token via `-http-token` / `LIGOLO_MCP_HTTP_TOKEN`; `relaymcp` refuses to start
  otherwise.
- Provide TLS with `-tls-cert` and `-tls-key`, or front it with a TLS-terminating
  reverse proxy.

```
relaymcp -http 0.0.0.0:9090 \
  -http-token "$(openssl rand -hex 32)" \
  -tls-cert server.pem -tls-key server-key.pem
```

Clients send the token as `Authorization: Bearer <token>`.

## Configuring Claude Code

```
claude mcp add ligolo-relay \
  --env LIGOLO_API=http://127.0.0.1:8080 \
  --env LIGOLO_USER=relay \
  --env LIGOLO_PASSWORD=change-me \
  -- relaymcp
```

Or add it to a project `.mcp.json`:

```json
{
  "mcpServers": {
    "ligolo-relay": {
      "command": "relaymcp",
      "env": {
        "LIGOLO_API": "http://127.0.0.1:8080",
        "LIGOLO_USER": "relay",
        "LIGOLO_PASSWORD": "change-me"
      }
    }
  }
}
```

## Configuring Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ligolo-relay": {
      "command": "/usr/local/bin/relaymcp",
      "env": {
        "LIGOLO_API": "http://127.0.0.1:8080",
        "LIGOLO_USER": "relay",
        "LIGOLO_PASSWORD": "change-me"
      }
    }
  }
}
```

## Embedded mode (in the proxy)

Instead of the standalone `relaymcp` bridge talking to the REST API, the proxy
can serve the same MCP tools itself — no separate binary and no REST hop. The
tool set and behavior are identical (both use the same in-process backend
interface).

### stdio

```
proxy -mcp -selfcert -laddr 0.0.0.0:11601
```

The proxy keeps listening for agents in the background and serves MCP over stdio
(headless — no interactive CLI, logs on stderr, no banner). No `-api` needed.
Point Claude Code straight at it:

```
claude mcp add ligolo-relay -- proxy -mcp -selfcert -laddr 0.0.0.0:11601
```

Add `-mcp-read-only` to expose only the diagnostic tools.

### streamable HTTP on the API

```
proxy -api -mcp-api -web-user relay -web-password 'change-me'
```

mounts the MCP server at `/mcp` on the API server, behind the same JWT auth as
`/api/v1`. Clients authenticate via `POST /api/auth` and send the JWT as
`Authorization: Bearer <jwt>` — reusing the existing authenticated port, with no
second network surface.

### Which mode?

| | Standalone `relaymcp` | Embedded `proxy -mcp` / `-mcp-api` |
|---|---|---|
| Separate process | yes (client-side) | no |
| Needs proxy `-api` | yes | no (stdio) / yes (`-mcp-api`) |
| Reaches a remote proxy | yes — point `LIGOLO_API` at it | runs where the proxy runs |
| Best for | operator workstation, CI | single-host / all-in-one deploys |

## Safety: read-write vs read-only

By default every tool is exposed, including mutating ones. Mutating tools are
annotated with the MCP `destructiveHint` / `readOnlyHint` hints so the client
prompts for confirmation before disruptive actions (stopping tunnels/relays,
revoking tokens, applying repairs/failovers, deleting routes/interfaces).

To expose **only** read-only diagnostic tools (a pure observability surface),
start with `-read-only` or `LIGOLO_MCP_READ_ONLY=1`. The mutating tools are then
not registered at all.

## Tool catalog

### Read-only (always available)

| Tool | Description |
|------|-------------|
| `ping` | Health-check the proxy API. |
| `list_agents` | List connected agents (IDs, interfaces, tunnel/relay state, parent). |
| `get_chains` | Relay chain topology (direct vs. relayed, hop depth, parents). |
| `relay_doctor` | Relay health: status, token expiry, events, route warnings. |
| `relay_ops` | Full relay operations report (best overall snapshot). |
| `autoheal_status` | Auto-heal reconciler config, enabled state, run history. |
| `list_chain_routes` | Route candidates across the chain with conflict warnings. |
| `chain_route_plan` | Dry-run smart route plan (apply/skip decisions). |
| `chain_repair_plan` | Dry-run repair plan. |
| `chain_failover_plan` | Dry-run parent failover recommendations. |
| `list_listeners` | Active listeners/redirectors across agents. |
| `list_interfaces` | Configured TUN interfaces and their routes/state. |

### Mutating (omitted in `-read-only` mode)

| Tool | Description | Hint |
|------|-------------|------|
| `autoheal_run` | Run one auto-heal reconciliation (`apply` to execute). | additive |
| `chain_autoroute` | Apply the smart route plan across the chain. | additive |
| `chain_repair_apply` | Apply the repair plan. | destructive |
| `chain_failover_apply` | Re-parent relayed agents onto healthier relays. | destructive |
| `relay_start` | Enable relay mode on an agent. | additive |
| `relay_stop` | Stop relay mode (disconnects downstream agents). | destructive |
| `relay_token_rotate` | Rotate an agent's relay auth token. | additive |
| `relay_token_revoke` | Revoke the token and stop relay. | destructive |
| `tunnel_start` | Start an agent's TUN tunnel. | additive |
| `tunnel_stop` | Stop an agent's TUN tunnel. | destructive |
| `create_listener` / `delete_listener` | Manage listeners/redirectors. | additive / destructive |
| `create_interface` / `delete_interface` | Manage TUN interfaces. | additive / destructive |
| `add_route` / `delete_route` | Manage interface routes. | additive / destructive |

## Smoke test with the MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) lists and
calls tools without wiring the server into a chat client:

```
LIGOLO_API=http://127.0.0.1:8080 LIGOLO_USER=relay LIGOLO_PASSWORD=change-me \
  npx @modelcontextprotocol/inspector relaymcp
```

Then list tools and call `list_agents` or `relay_ops`. For the HTTP transport,
start `relaymcp -http 127.0.0.1:9090` and point the Inspector at the URL.

## Notes

- `relaymcp -version` prints the build stamp.
- The server is stateless: every tool takes explicit parameters (e.g. `agent_id`
  from `list_agents`), so there is no "current session" selection to manage.
