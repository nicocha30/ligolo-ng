# Relay Quickstart

This walkthrough proves the relay product path:

```
Proxy -> Agent A relay -> Agent B
```

It assumes the proxy API is listening on `127.0.0.1:8080`, Agent A can reach the
proxy, and Agent B can reach Agent A but cannot reach the proxy directly.

## 1. Start the proxy API

```
proxy -daemon -selfcert -api -no-web-ui \
  -api-laddr 127.0.0.1:8080 \
  -web-user relay -web-password 'change-me'
```

Authenticate once for scriptable commands:

```
TOKEN="$(curl -fsS http://127.0.0.1:8080/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"Username":"relay","Password":"change-me"}' | jq -r .token)"
```

## 2. Connect Agent A directly

Run Agent A from the network segment that can reach the proxy:

```
./agent -connect <proxy-ip>:11601 -ignore-cert
```

Confirm it registered:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" agents
```

## 3. Start relay mode on Agent A

Use the Agent A ID from the `agents` response:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  relay-start --agent 1 --listen <agent-a-ip>:11602 --token-ttl 8h
```

The response includes:

- `fingerprint`: the relay listener certificate fingerprint
- `auth_token`: the downstream relay token
- `token_expires_at`: when that token stops authenticating new downstream agents
- `connect_command`: a fingerprint-pinned Agent B command

For a single-use downstream join, add `--one-time-token`.

## 4. Connect Agent B through Agent A

Run the printed `connect_command` on Agent B. It will look like:

```
./agent -connect <agent-a-ip>:11602 \
  -accept-fingerprint <fingerprint> \
  -relay-token <auth-token>
```

Agent B registers on the proxy like a direct agent, but its chain path shows it
is behind Agent A.

## 5. Check chain health

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chains
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" doctor
```

`doctor` reports:

- online/offline agent state
- active relay listeners
- relay fingerprint and token expiry metadata
- expired tokens
- recent relay auth failures such as rejected or overloaded downstream joins
- duplicate route warnings before autoroute changes are applied

## 6. Configure routes

Preview route candidates first:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-routes
```

Preview the smart route plan before writing config:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  chain-plan --interface-prefix ligolo --start
```

The plan selects one candidate per CIDR using online state, hop depth, path RTT,
and agent ID. Duplicate lower-ranked candidates are skipped with a reason.

Preview safe repair actions:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  chain-repair --interface-prefix ligolo --start
```

Apply supported repair actions:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  chain-repair --interface-prefix ligolo --start --apply
```

Add `--prune-conflicts` only when you want configured lower-ranked duplicate
routes removed from their interfaces.

Preview relay parent failover recommendations:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-failover
```

Add `--include-commands` only when the output should include downstream
reconnect commands with relay tokens.

Apply a selected failover recommendation:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  chain-failover --apply --sessions <downstream-session-id>
```

Use `--all` only when every supported recommendation should be applied. Apply
mode requires downstream agents to keep reconnect enabled, which is the default.

Preview a bounded auto-heal pass:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" autoheal --run
```

Apply one bounded auto-heal pass:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  autoheal --run --apply --max-repair-actions 10 --max-failovers 1
```

Continuous auto-heal is disabled by default. Start the proxy with
`-relay-autoheal` for monitor mode, or `-relay-autoheal-apply` when the
background reconciler should apply supported repairs and failovers.

Configure selected route/interface entries:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  chain-autoroute --interface-prefix ligolo
```

Add `--start` to start tunnels after writing the route configuration.

## 7. Rotate or revoke relay access

Rotate the token when it has been shared too broadly or before handing the path
to another operator:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  relay-token-rotate --agent 1 --token-ttl 30m
```

Rotation restarts the relay listener and disconnects downstream descendants so
they must reconnect with the new token.

Revoke the token and stop the relay listener:

```
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" \
  relay-token-revoke --agent 1
```

## Local Docker Verification

The repository includes a disposable lab that exercises a deeper path:

```
make relay-test
```

The lab verifies `Proxy -> Agent A relay -> Agent B relay -> Agent C`, route
automation, listener traffic through Agent C, idle traffic recovery, descendant
cleanup, failover recommendations and apply, and `relayctl`.
