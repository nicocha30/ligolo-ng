# Restrictive Egress Runbook

Ligolo-ng Relay inherits upstream Ligolo-ng's carrier paths for environments where direct
outbound TCP is blocked. The fork keeps those paths compatible with relay mode: once
Agent A is connected to the proxy, downstream Agent B can register through Agent
A even when the proxy is unreachable from B.

## WebSocket/TLS Callback

Start the proxy with an HTTP(S) listener:

```
proxy -selfcert -laddr https://0.0.0.0:443
```

Connect an agent over WebSocket/TLS:

```
agent -connect https://proxy.example.com:443 -accept-fingerprint <fingerprint>
```

## Egress Proxy

For WebSocket callbacks through an HTTP proxy:

```
agent -connect https://proxy.example.com:443 \
  -proxy http://user:pass@egress-proxy.local:8080 \
  -accept-fingerprint <fingerprint>
```

For direct TCP callbacks through SOCKS:

```
agent -connect proxy.example.com:11601 \
  -proxy socks5://user:pass@egress-proxy.local:1080 \
  -accept-fingerprint <fingerprint>
```

## Relay Chain

After Agent A is reachable from the proxy, start relay mode:

```
relay_start --addr <agent-interface-ip>:11602
```

Then connect Agent B to Agent A using the fingerprint-pinned command printed by
`relay_start` or returned by `POST /api/v1/relay/:id`. The command includes the
relay auth token required by Agent A before it will queue the downstream
connection.

## Verification

Use:

```
chain_list --json
```

Confirm the downstream node has:

- `parent_session_id` set to Agent A's session ID
- `hop_depth` greater than `0`
- `state` set to `online`
