# Fork Delta

Ligolo-ng Relay is currently based on upstream Ligolo-ng `master` at `913fe64`
(`v0.8.3`). This maintained fork should stay rebased on upstream; if
`upstream/master` is no longer an ancestor of this branch, review and rebase
before cutting a release.

## Added Capabilities

### Multi-Hop Relay Mode

Agents can act as TLS relay points for downstream agents:

```
Proxy <-> Agent A relay <-> Agent B
```

Relay chains are recursive. A branch can contain up to five agents including the
direct root agent, for example `Proxy <-> A <-> B <-> C <-> D <-> E`; a sixth
agent below `E` is rejected by the chain depth guard.

Key changes:

- relay protocol packets in `pkg/protocol`
- agent relay listener and bridge handling in `pkg/agent/relay.go`
- proxy-side relay registration and topology tracking in `pkg/controller/agent.go`
  and `pkg/proxy/chain.go`
- CLI commands: `relay_start`, `relay_stop`, `relay_token_rotate`,
  `relay_token_revoke`, `relay_doctor`, `chain_list`, `chain_list --json`
- REST endpoints: `POST /api/v1/relay/:id`, `DELETE /api/v1/relay/:id`,
  `POST /api/v1/relay/:id/token`, `DELETE /api/v1/relay/:id/token`,
  `GET /api/v1/relay/doctor`, `GET /api/v1/chains`,
  `GET /api/v1/chain_routes`, `POST /api/v1/chain_autoroute`
- scriptable client: `relayctl`
- relay tokens expire by default, can be one-time, and can be rotated or revoked
- Docker integration lab: `make relay-test`

### UDP Scan Feedback

When a UDP connect attempt returns a refused-port signal, the proxy can inject an
ICMP/ICMPv6 Port Unreachable response into the TUN stack. This lets scanners
classify closed UDP ports instead of waiting for `open|filtered` timeouts.

Key changes:

- ICMP/ICMPv6 builders and tests in `pkg/proxy/netstack/icmp.go`
- UDP failure handling in `pkg/proxy/netstack/handlers.go`
- configurable ICMP response interval through
  `LIGOLO_ICMP_UNREACHABLE_INTERVAL` (`1s` by default, `0` disables limiting)

### Automation and Operations

The proxy now supports noninteractive API startup and config overrides:

- `-api`
- `-api-laddr`
- `-no-web-ui`
- `-web-user` / `-api-user`
- `-web-password` / `-api-password`
- absolute or path-qualified `-config` files

The fork also ships an MCP server exposing the relay control plane to AI agents
such as Claude over stdio or streamable HTTP, in two forms sharing the
`pkg/relaymcp` tool layer (behind a `RelayBackend` interface):

- standalone `relaymcp` (`cmd/relaymcp`, on the shared `pkg/relayapi` client) —
  a client-side bridge over the REST API; and
- embedded in the proxy (`proxy -mcp` stdio, or `proxy -api -mcp-api` mounting
  `/mcp` behind JWT) via an in-process backend in `cmd/proxy/app/mcp.go`.

See `doc/MCP.md`.

The fork also ships operator runbooks for restrictive egress, relay-chain
performance checks, UDP scan benchmarking, and release verification under
`doc/`.

## Compatibility Intent

The fork intentionally keeps the upstream wire protocol and CLI behavior intact
unless a feature requires new messages. Existing direct proxy/agent tunneling,
listeners, and Web UI behavior should remain compatible with upstream usage.

## Release Gates

Before publishing a release:

1. Fetch upstream and confirm `upstream/master` is an ancestor of the release
   branch.
2. Run the Web build and dependency audit:
   `npm ci --prefix web/ligolo-ng-relay-web`,
   `npm run build --prefix web/ligolo-ng-relay-web`, and
   `npm audit --audit-level=moderate --prefix web/ligolo-ng-relay-web`.
3. Run Go quality and vulnerability gates:
   `go vet ./...`, `go test ./...`, `go test -race ./...`,
   `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`, and
   `go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -include=G123 -tests ./...`.
4. Run `go build ./cmd/proxy ./cmd/agent ./cmd/relayctl ./cmd/relaymcp`.
5. Validate release and deployment metadata:
   `go run github.com/goreleaser/goreleaser/v2@v2.16.0 check --config .goreleaser.yaml`
   and
   `helm template ligolo deploy/helm/ligolo-ng-relay --set proxy.webPassword=ci-password >/dev/null`.
6. Run `make relay-test`.
7. Run the UDP scan benchmark in `doc/UDP_SCAN_BENCHMARK.md` when changing
   netstack or ICMP behavior.
