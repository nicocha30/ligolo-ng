# Ligolo-ng Relay Enhancements

Ligolo-ng Relay is a maintained fork of
[upstream Ligolo-ng](https://github.com/nicocha30/ligolo-ng). It adds multi-hop agent
chaining (relay mode) and ICMP Port Unreachable responses on top of upstream
upstream Ligolo-ng. Core setup, tunneling, and listeners still follow upstream behavior,
while this fork adds relay-focused automation and a Web UI operations dashboard.
The [upstream Ligolo-ng documentation](https://docs.ligolo.ng/) still applies for
upstream features.

Operational docs:

- [FORK-DELTA.md](FORK-DELTA.md) tracks the fork's upstream base and exact delta.
- [doc/QUICKSTART_RELAY.md](doc/QUICKSTART_RELAY.md) gives a first-run relay
  workflow from direct Agent A to downstream Agent B.
- [doc/RELAY_API.md](doc/RELAY_API.md) documents relay automation and structured
  chain status, including the `relayctl` helper.
- [doc/DEPLOYMENT.md](doc/DEPLOYMENT.md) covers Docker Compose, systemd, Helm,
  and production smoke gates.
- [test/relay/README.md](test/relay/README.md) explains the Docker relay lab.
- [doc/UDP_SCAN_BENCHMARK.md](doc/UDP_SCAN_BENCHMARK.md) covers scan speed and
  classification benchmarks.
- [doc/RESTRICTIVE_EGRESS.md](doc/RESTRICTIVE_EGRESS.md) documents WebSocket,
  HTTP proxy, SOCKS, and relay-chain usage for constrained networks.
- [doc/PERFORMANCE.md](doc/PERFORMANCE.md) gives repeatable relay-chain path RTT
  and throughput checks.

---

## Multi-Hop Agent Chaining (Relay Mode)

Agents can act as lightweight TLS relays for downstream agents. This lets you pivot
through segmented networks where some hosts cannot reach the proxy directly:

```
Proxy <---> Agent A (relay) <---> Agent B ---> Target Network
```

Agent A relays the downstream connection with a direct, bidirectional `io.Copy`
bridge (no nested yamux multiplexing), so the relay adds minimal overhead. Once
Agent B registers on the proxy through the relay, it behaves like any directly
connected agent — tunnels, listeners, and session recovery all work across the
full chain.

### Setup

1. Select an agent and start relay mode:

   ```
   ligolo-ng-relay » session       # select Agent A
   [Agent: user@DMZ] » relay_start --addr <agent-interface-ip>:11602
   ```

2. On the downstream host (reachable from Agent A but not the proxy), connect
   through the relay using the command printed by `relay_start`:

   ```
   ./agent -connect <AgentA_IP>:11602 -accept-fingerprint <fingerprint> -relay-token <relay-token>
   ```

3. Agent B auto-registers on the proxy and can be used like any other agent.

### Commands

| Command | Description |
| --- | --- |
| `relay_start --addr <ip:port> [--token-ttl 8h] [--one-time-token]` | Start a relay listener on the current agent |
| `relay_stop` | Stop the relay on the current agent |
| `relay_token_rotate` | Restart the relay with a fresh token and disconnect descendants |
| `relay_token_revoke` | Revoke relay access by stopping the relay listener |
| `relay_doctor` | Display relay health, token status, recent events, and route warnings |
| `chain_list` | Display the relay chain topology |
| `chain_list --json` | Display structured chain status for automation |
| `chain_routes` | Display route candidates across direct and relayed agents |
| `chain_plan` / `relayctl chain-plan` | Dry-run smart route decisions before writing config |
| `chain_repair` / `relayctl chain-repair` | Dry-run or apply safe route repair actions |
| `chain_failover` / `relayctl chain-failover` | Dry-run or apply safer relay parent recommendations |
| `relayctl autoheal` | Inspect or run bounded relay auto-heal reconciliation |
| `chain_autoroute` | Configure per-agent routes/interfaces across the chain |
| `relayctl ops --fail-on-warning` | Print the relay operations report and fail when health is not `ok` |

### REST API

| Method & path | Description |
| --- | --- |
| `POST /api/v1/relay/:id` | Start relay (body: `{"ListenAddr": "<agent-interface-ip>:11602", "TokenTTLSeconds": 28800}`) |
| `DELETE /api/v1/relay/:id` | Stop relay |
| `POST /api/v1/relay/:id/token` | Rotate the active relay token and restart the listener |
| `DELETE /api/v1/relay/:id/token` | Revoke the active token and stop relay mode |
| `GET /api/v1/chains` | Get human and structured chain topology |
| `GET /api/v1/relay/doctor` | Get relay diagnostics, recent auth failures, and route warnings |
| `GET /api/v1/relay/ops` | Get dashboard-ready relay summary counters and suggested actions |
| `GET /api/v1/relay/autoheal` | Get relay auto-heal policy, run state, and last run |
| `POST /api/v1/relay/autoheal/run` | Run one bounded monitor or apply reconciliation pass |
| `GET /api/v1/chain_routes` | Get route candidates across the chain |
| `GET /api/v1/chain_route_plan` | Dry-run smart route decisions with conflict resolution |
| `GET /api/v1/chain_repair_plan` | Dry-run safe route repair and manual recovery actions |
| `POST /api/v1/chain_repair` | Apply supported repair actions |
| `GET /api/v1/chain_failover_plan` | Dry-run relay parent failover recommendations |
| `POST /api/v1/chain_failover` | Apply selected relay parent failover recommendations |
| `POST /api/v1/chain_autoroute` | Configure selected per-agent routes/interfaces |

### Web UI

The Web UI includes a **Relay** page that polls `/api/v1/relay/ops` and gives
operators summary metrics, chain topology, mesh health, smart route-plan
decisions, repair actions, failover recommendations, suggested actions,
auto-heal status, relay start, and relay token rotation or revocation controls.

### Notes & limits

- A relay branch can contain up to **5 agents**: one direct root agent plus four
  downstream relay levels. Circular chains are detected and rejected.
- The `InfoReplyPacket` now carries a `RelayCapable` field so the proxy knows which
  agents can relay.
- Session recovery is supported for both relay agents and downstream agents.
- A `LIGOLO_SESSION_ID` environment variable allows running multiple agents on a
  single host (useful for testing chains locally).
- `relay_start` and the REST API return a fingerprint-pinned downstream connect
  command using `-accept-fingerprint` plus a proxy-minted `-relay-token`.
- Relay tokens expire by default after **8 hours**. Operators can set shorter
  lifetimes or one-time tokens, rotate active tokens, or revoke access by
  stopping the relay.
- Relay diagnostics distinguish relay-down/control-channel failures from
  downstream auth rejection, pending connection overload, depth rejection, and
  duplicate route candidates.
- Relay operations reports condense diagnostics into stable counters and action
  items for scripts, dashboards, and smoke checks.
- Smart route planning chooses one candidate per CIDR using online state, hop
  depth, path RTT, tunnel state, and agent ID, then explains skipped duplicate
  candidates before autoroute writes config.
- Repair planning converts route and mesh health into safe automatic actions
  such as missing-route ensures and tunnel starts, while leaving token rotation
  and offline reconnects as explicit manual actions.
- Failover planning scores alternate relay parents by online state, relay
  readiness, token state, hop depth, path RTT, and downstream fanout. Reconnect
  commands are emitted only when explicitly requested with `--include-commands`
  or `include_commands=true`; apply mode updates selected agents' reconnect
  targets and closes their old sessions so the existing reconnect loop can join
  through the recommended parent.
- Relay auto-heal is disabled by default and can run in monitor or apply mode.
  Apply mode reuses the supported repair and failover paths with per-run limits.
- Stopping a relay now closes downstream sessions registered through that relay
  and prunes their chain links.
- Structured chain status reports online/offline state and cached proxy-to-agent
  `path_rtt_ms`, relay fingerprint, and token expiry metadata when available.

**Implementation:** new protocol messages (`RelayRequest`, `RelayResponse`,
`RelayNewConnection`, `RelayBridgeRequest`, `RelayEvent`,
`AgentReconnectRequest`, `AgentReconnectResponse`), an agent-side relay listener
with self-signed TLS, and a `ChainManager` that tracks topology, enforces depth
limits, and detects circular chains.

---

## ICMP Port Unreachable for UDP Scans

When a UDP connection to a remote port is refused (`ECONNREFUSED`), the proxy now
generates an ICMP Destination Unreachable packet (Type 3, Code 3 — Port Unreachable)
and injects it back into the TUN interface. Scanners like `nmap` detect closed UDP
ports instantly instead of waiting for a timeout on every port.

The ICMP error payload includes the original IP header plus the first 8 bytes of the
UDP header (per RFC 792), so scanners can correlate the response with the probe that
triggered it.

Previously, UDP failures silently disappeared because `Terminate()` was a no-op for
UDP connections — leaving scanners to time out on every closed port.

ICMP Port Unreachable responses are rate-limited per target/scanner pair. The
default interval is `1s`; tune it with `LIGOLO_ICMP_UNREACHABLE_INTERVAL`
(`250ms`, `1s`, `0` to disable limiting).

**Implementation:** `pkg/proxy/netstack/icmp.go` (new) and a small change in
`pkg/proxy/netstack/handlers.go`.
