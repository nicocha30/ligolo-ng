# Relay API and Automation

Enable the API without interactive config prompts:

```
proxy -daemon -selfcert -api -no-web-ui \
  -api-laddr 127.0.0.1:8080 \
  -web-user relay -web-password 'change-me'
```

Authenticate:

```
TOKEN="$(curl -fsS http://127.0.0.1:8080/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"Username":"relay","Password":"change-me"}' | jq -r .token)"
```

Start relay mode on agent `1`:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/1 \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ListenAddr":"<agent-interface-ip>:11602","TokenTTLSeconds":28800}'
```

The proxy generates a relay auth token when `AuthToken` is omitted. The response
includes that token, its expiry, and a fingerprint-pinned downstream connect
command. Add `"OneTimeToken": true` to allow a token to authenticate one
downstream agent only.

```json
{
  "message": "relay started",
  "fingerprint": "ABCD...",
  "auth_token": "relay-token...",
  "token_expires_at": "2026-06-16T20:00:00Z",
  "one_time_token": false,
  "connect_command": "./agent -connect <relay-agent-reachable-ip>:11602 -accept-fingerprint ABCD... -relay-token relay-token..."
}
```

Rotate the active token. Rotation restarts the relay listener and disconnects
downstream descendants so they must reconnect with the new token:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/1/token \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"TokenTTLSeconds":1800}'
```

Revoke the active token and stop relay mode:

```
curl -fsS -X DELETE http://127.0.0.1:8080/api/v1/relay/1/token \
  -H "Authorization: $TOKEN"
```

Inspect chain health:

```
curl -fsS http://127.0.0.1:8080/api/v1/chains \
  -H "Authorization: $TOKEN" | jq
```

The chain response keeps the human topology string and adds structured nodes:

```json
{
  "topology": "Chain topology:\n  Proxy\n  ...",
  "max_depth": 5,
  "agents": [
    {
      "agent_id": 1,
      "session_id": "agent-a",
      "state": "online",
      "path_rtt_ms": 4,
      "relay_active": true,
      "relay_listen_addr": "<agent-interface-ip>:11602",
      "relay_fingerprint": "ABCD...",
      "relay_token_expires_at": "2026-06-16T20:00:00Z",
      "relay_token_expired": false,
      "relay_one_time_token": false,
      "children": []
    }
  ]
}
```

`path_rtt_ms` is proxy-to-agent round-trip time over the full active path, not an
isolated single-hop measurement. It is cached briefly, probed in parallel for
stale entries, and omitted when a node is offline or does not answer before the
probe timeout.

`max_depth` is the maximum number of agents in a single branch, including the
direct root agent. With the default `5`, the deepest allowed branch is
`Proxy -> A -> B -> C -> D -> E`; a downstream agent below `E` is rejected.

The CLI exposes the same data with:

```
chain_list
chain_list --json
```

Run relay diagnostics:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/relay/doctor?with_ipv6=false&interface_prefix=ligolo' \
  -H "Authorization: $TOKEN" | jq
```

The doctor response includes the chain snapshot, route candidates, duplicate
route warnings, active relay metadata, token expiry state, and recent relay
events such as downstream auth rejection, pending connection overload, depth
rejection, or relay control-channel closure.

Inspect the operator-grade relay operations report:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/relay/ops?with_ipv6=false&interface_prefix=ligolo' \
  -H "Authorization: $TOKEN" | jq
```

The ops response wraps the doctor data with a summary and action queue suitable
for dashboards and CI gates. It also embeds mesh health and the current smart
route, repair, and failover plans:

```json
{
  "status": "warning",
  "summary": {
    "agents_total": 2,
    "agents_online": 2,
    "direct_agents": 1,
    "relayed_agents": 1,
    "active_relays": 1,
    "downstream_agents": 1,
    "expired_tokens": 0,
    "route_conflicts": 2,
    "route_plan_apply": 1,
    "route_plan_skipped": 1,
    "mesh_healthy": 1,
    "mesh_degraded": 1,
    "mesh_offline": 0,
    "mesh_repairable": 1,
    "repair_actions": 2,
    "repair_automated": 1,
    "repair_manual": 1,
    "failover_recommendations": 1,
    "failover_at_risk": 0,
    "failover_command_ready": 1,
    "failover_apply_supported": 1,
    "warnings": 1,
    "max_depth": 5
  },
  "actions": [
    {
      "severity": "warning",
      "agent_id": 1,
      "title": "Resolve duplicate route candidate",
      "detail": "route 10.20.30.0/24 is advertised by multiple agents"
    }
  ],
  "chain": {},
  "routes": [],
  "relays": [],
  "route_plan": {
    "status": "warning",
    "summary": {
      "candidates": 2,
      "apply": 1,
      "skipped": 1,
      "conflict_groups": 1,
      "already_configured": 0,
      "start_tunnels": 0
    },
    "decisions": []
  },
  "mesh_health": [],
  "repair_plan": {
    "status": "warning",
    "summary": {
      "actions": 2,
      "apply_supported": 1,
      "applied": 0,
      "failed": 0,
      "route_ensures": 1,
      "tunnel_starts": 0,
      "prunes": 0,
      "manual": 1
    },
    "actions": []
  },
  "failover_plan": {
    "status": "warning",
    "summary": {
      "relayed_agents": 1,
      "at_risk": 0,
      "recommendations": 1,
      "command_ready": 1,
      "apply_supported": 1,
      "applied": 0,
      "failed": 0,
      "no_alternative": 0
    },
    "recommendations": []
  },
  "auto_heal": {
    "running": false,
    "policy": {
      "enabled": false,
      "apply": false,
      "interval_seconds": 30,
      "interface_prefix": "ligolo",
      "repair": true,
      "failover": true,
      "max_repair_actions": 10,
      "max_failovers": 1
    }
  }
}
```

Use `status` as the top-level automation result. `summary` gives stable counters
for dashboards, and `actions` contains remediation-oriented items derived from
offline agents, expired relay tokens, relay errors, route conflicts, and parent
failover recommendations.

Inspect route candidates across all online agents:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/chain_routes?with_ipv6=false&interface_prefix=ligolo' \
  -H "Authorization: $TOKEN" | jq
```

Dry-run the smart route plan:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/chain_route_plan?with_ipv6=false&interface_prefix=ligolo&start=true' \
  -H "Authorization: $TOKEN" | jq
```

The plan selects one candidate per CIDR. Duplicate candidates are ranked by
online state, hop depth, cached path RTT, tunnel state, and agent ID; skipped
candidates include the preferred agent and reason.

Dry-run the repair plan:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/chain_repair_plan?with_ipv6=false&interface_prefix=ligolo&start=true&prune_conflicts=false' \
  -H "Authorization: $TOKEN" | jq
```

Apply supported repair actions:

```
curl -fsS http://127.0.0.1:8080/api/v1/chain_repair \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"InterfacePrefix":"ligolo","WithIPv6":false,"Start":true,"PruneConflicts":false}'
```

Supported apply actions are route config ensures and tunnel starts. Set
`PruneConflicts` to `true` only when lower-ranked duplicate route entries should
be removed from config and active TUN interfaces. Manual actions such as token
rotation remain visible in the plan but are not applied automatically.

Dry-run relay parent failover recommendations:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/chain_failover_plan?include_commands=false' \
  -H "Authorization: $TOKEN" | jq
```

The plan evaluates relayed agents and ranks alternate parents by online state,
relay readiness, token state, hop depth, cached path RTT, and downstream fanout.
It recommends a parent switch when the current parent is at risk or a valid
alternate has a lower failover cost. Set `include_commands=true` only for
trusted output; when a proxy-held relay token is available, recommendations can
include downstream `agent -connect ... -relay-token ...` commands.

Apply selected relay parent failover recommendations:

```
curl -fsS http://127.0.0.1:8080/api/v1/chain_failover \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"SessionIDs":["agent-c"],"IncludeCommands":true}'
```

Apply requires `All`, `SessionIDs`, or `AgentIDs` in the request body. Supported
apply actions send a reconnect target update to the selected downstream agent,
then close its old session so its normal reconnect loop joins through the
recommended relay parent. This requires reconnect to be enabled on the agent
process, which is the default.

Inspect relay auto-heal status:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/autoheal \
  -H "Authorization: $TOKEN" | jq
```

Run one monitor-only reconciliation pass:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/autoheal/run \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"Apply":false,"Repair":true,"Failover":true,"MaxRepairActions":10,"MaxFailovers":1}' | jq
```

Run one bounded apply pass:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/autoheal/run \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"Apply":true,"Repair":true,"Failover":true,"StartTunnels":false,"PruneConflicts":false,"MaxRepairActions":10,"MaxFailovers":1}' | jq
```

The background reconciler is disabled by default. Enable monitor mode with
`relay.autoheal.enabled: true` or `-relay-autoheal`. Set
`relay.autoheal.apply: true` or use `-relay-autoheal-apply` only when supported
repair and failover actions should be applied automatically.

Configure selected per-agent route/interface entries across the chain:

```
curl -fsS http://127.0.0.1:8080/api/v1/chain_autoroute \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"InterfacePrefix":"ligolo","WithIPv6":false,"Start":false}'
```

## relayctl

The `relayctl` helper wraps the same REST calls for scripts:

```
relayctl -api http://127.0.0.1:8080 -user relay -password change-me chains
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" doctor
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" ops --fail-on-warning
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-start --agent 1 --listen <agent-interface-ip>:11602 --token-ttl 8h
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-token-rotate --agent 1 --token-ttl 30m
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-token-revoke --agent 1
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-routes
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-plan --interface-prefix ligolo --start
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-repair --interface-prefix ligolo --start
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-repair --interface-prefix ligolo --start --apply
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-failover
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-failover --include-commands
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-failover --apply --sessions agent-c
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-failover --apply --all
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" autoheal
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" autoheal --run
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" autoheal --run --apply --max-failovers 1
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-autoroute --interface-prefix ligolo
```

`relayctl ops --fail-on-warning` prints the full JSON report and exits non-zero
when the report status is not `ok`, making it suitable for smoke tests before a
relay chain is handed to operators or automation.

## MCP server

`relaymcp` exposes the same REST control plane to AI agents (e.g. Claude) as
Model Context Protocol tools, over stdio or streamable HTTP. It authenticates
with the identical `LIGOLO_API` / `LIGOLO_USER` / `LIGOLO_PASSWORD` /
`LIGOLO_TOKEN` settings used by `relayctl`. See [MCP.md](MCP.md) for the tool
catalog and client configuration.

## Web UI

The Web UI includes a **Relay** page at `/relay`. It polls the same
`/api/v1/relay/ops` report and exposes summary metrics, topology, mesh health,
smart route-plan decisions, repair actions, failover recommendations, suggested
actions, auto-heal status, relay start, and relay token rotation or revocation
controls.

Environment variable equivalents are supported:

- `LIGOLO_API`
- `LIGOLO_USER`
- `LIGOLO_PASSWORD`
- `LIGOLO_TOKEN`
- `LIGOLO_RELAY_TOKEN`
