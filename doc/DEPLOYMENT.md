# Production Deployment

Ligolo-ng Relay production hosts need proxy privileges to create and manage TUN
interfaces. Keep the API private or place it behind an authenticated reverse
proxy.

## Docker Compose

Set an API password and start the proxy:

```sh
export LIGOLO_WEB_PASSWORD='change-me'
docker compose -f deploy/docker-compose.yml up -d proxy
```

Run a smoke check with the bundled `relayctl` image:

```sh
docker compose -f deploy/docker-compose.yml run --rm relayctl
```

The Compose file publishes:

- `11601/tcp` for direct agent connections
- `127.0.0.1:8080/tcp` for the API and Web UI
- `11602/tcp` for a relay listener when an agent is instructed to bind there

The proxy service runs with `NET_ADMIN` and `/dev/net/tun` so tunnels can be
created from inside the container. Keep the loopback API binding unless you put
the API behind an authenticated, TLS-terminating reverse proxy.

## systemd

Install release binaries under `/usr/local/bin` as `proxy`, `agent`, and
`relayctl`, then install the unit files:

```sh
sudo install -d /etc/ligolo-ng-relay-proxy /etc/ligolo-ng-relay-agent
sudo install -m 0644 deploy/systemd/ligolo-ng-relay-proxy.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/ligolo-ng-relay-agent@.service /etc/systemd/system/
sudo install -m 0600 deploy/systemd/ligolo-ng-relay-proxy.env.example /etc/ligolo-ng-relay-proxy/proxy.env
sudo systemctl daemon-reload
sudo systemctl enable --now ligolo-ng-relay-proxy
```

For an agent service, create `/etc/ligolo-ng-relay-agent/<name>.env` from
`deploy/systemd/ligolo-ng-relay-agent.env.example`, then start:

```sh
sudo systemctl enable --now ligolo-ng-relay-agent@dmz
```

The proxy unit grants `CAP_NET_ADMIN` and access to `/dev/net/tun`; the agent
unit does not require elevated privileges.

## Helm

Render or install the included chart:

```sh
helm template ligolo deploy/helm/ligolo-ng-relay \
  --set proxy.webPassword='change-me'

helm install ligolo deploy/helm/ligolo-ng-relay \
  --set proxy.webPassword='change-me'
```

The chart requires either `proxy.webPassword` or `proxy.existingSecret` so the
API cannot be installed with the packaged demo credential. It creates one proxy
Deployment, a Service exposing proxy/API/relay ports, and an optional PVC for
proxy config. By default it mounts `/dev/net/tun` from the node and requests
`NET_ADMIN` without privileged mode. If your cluster requires a different TUN
model, set `securityContext.privileged` deliberately and document that exception
in the deployment review.

## Route Planning And Smoke Gates

Before writing route config in production, preview the smart route plan:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-plan --interface-prefix ligolo --start
```

Preview safe route and mesh repair actions:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-repair --interface-prefix ligolo --start
```

Apply supported repair actions:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-repair --interface-prefix ligolo --start --apply
```

Add `--prune-conflicts` when you want lower-ranked duplicate route entries
removed from config and active TUN interfaces.

Review parent failover recommendations:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-failover
```

Add `--include-commands` only for trusted operator output that may contain relay
tokens for downstream reconnects.

Apply selected parent failovers:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-failover --apply --sessions agent-c
```

Use `--all` only during controlled maintenance windows. Apply mode updates the
selected downstream agent's reconnect target, then closes its old session so the
agent reconnects through the recommended parent.

Preview a bounded auto-heal run without applying changes:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  autoheal --run
```

Apply one bounded reconciliation pass:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  autoheal --run --apply --max-repair-actions 10 --max-failovers 1
```

For continuous reconciliation, set `relay.autoheal.enabled: true` in
`ligolo-ng-relay.yaml` or start the proxy with `-relay-autoheal`. The loop runs
in monitor mode unless `relay.autoheal.apply: true` or `-relay-autoheal-apply`
is set. Keep `max_failovers` low for production windows.

Apply selected routes and start missing tunnels:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  chain-autoroute --interface-prefix ligolo --start
```

Gate handoff with the operations report:

```sh
relayctl -api http://127.0.0.1:8080 -user ligolo -password "$LIGOLO_WEB_PASSWORD" \
  ops --fail-on-warning
```

`chain-plan` explains duplicate CIDR decisions before anything changes.
`chain-repair` turns those decisions into safe route ensures, tunnel starts, and
optional duplicate-route pruning. `chain-failover` identifies relayed agents
that have a safer or lower-cost parent and can apply selected reconnect target
changes. `autoheal` combines the supported repair and failover apply paths under
per-run limits for monitor or apply mode. `ops --fail-on-warning` surfaces
degraded mesh paths, expired relay tokens, route conflicts, failover
recommendations, and suggested repair actions.
