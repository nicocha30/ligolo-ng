# Ligolo-ng Relay Release Notes Draft

Ligolo-ng Relay is a maintained fork of upstream Ligolo-ng `v0.8.3` focused on
operator-safe multi-hop relay chains. The exact fork delta is tracked in
[FORK-DELTA.md](../FORK-DELTA.md).

## Highlights

- Multi-hop relay mode for `Proxy -> Agent A relay -> Agent B` and deeper chains.
- `relayctl` for scriptable API workflows.
- MCP server exposing the relay control plane to AI agents such as Claude over
  stdio or streamable HTTP — as the standalone `relaymcp` bridge or embedded in
  the proxy (`proxy -mcp` / `-mcp-api`); see [MCP.md](MCP.md).
- `relay_doctor` and `relayctl doctor` for chain health, relay token state,
  recent relay events, and duplicate route warnings.
- Relay auth tokens now expire by default, can be one-time, and can be rotated
  or revoked.
- Structured chain JSON now includes relay fingerprint and token expiry metadata.
- `chain_routes` and `chain_autoroute` support route planning across relayed
  agents and flag duplicate CIDRs.
- UDP scan acceleration via ICMP/ICMPv6 Port Unreachable responses.
- API hardening for bearer-token auth, expiring admin sessions, login
  rate-limiting, and HTTP server timeouts.
- Hardened agent certificate fingerprint verification and current Go security
  dependency baselines.
- Release artifacts include proxy, agent, `relayctl`, and `relaymcp` binaries,
  archive SBOMs, checksums, a Sigstore checksum bundle, and GHCR images.

## Operator Docs

- [Relay Quickstart](QUICKSTART_RELAY.md)
- [Relay API and Automation](RELAY_API.md)
- [MCP Server](MCP.md)
- [Restrictive Egress Runbook](RESTRICTIVE_EGRESS.md)
- [Relay Performance Checks](PERFORMANCE.md)
- [UDP Scan Benchmark](UDP_SCAN_BENCHMARK.md)

## Verification

Before publishing, attach or reference the output from:

```
git fetch upstream master
git merge-base --is-ancestor upstream/master HEAD
npm ci --prefix web/ligolo-ng-relay-web
npm run build --prefix web/ligolo-ng-relay-web
npm audit --audit-level=moderate --prefix web/ligolo-ng-relay-web
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/proxy ./cmd/agent ./cmd/relayctl ./cmd/relaymcp
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -include=G123 -tests ./...
go run github.com/goreleaser/goreleaser/v2@v2.16.0 check --config .goreleaser.yaml
helm template ligolo deploy/helm/ligolo-ng-relay --set proxy.webPassword=ci-password >/dev/null
make relay-test
goreleaser release --snapshot --clean --skip=publish
cosign verify-blob --bundle dist/checksums.txt.sigstore.json --key /tmp/ligolo-dryrun.pub dist/checksums.txt
```

For the first public release, also run the OIDC smoke test in
[doc/RELEASE.md](RELEASE.md).
