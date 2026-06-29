# Performance and Throughput Checks

Multi-hop relay mode adds another TCP/TLS/yamux leg. Operators should measure
the actual path instead of assuming direct-tunnel performance.

## Suggested TCP Throughput Check

Run an `iperf3` server on the target side, then test from the proxy side through
the Ligolo tunnel:

```
iperf3 -s
iperf3 -c <target-ip> -P 4 -t 20
```

Record separate results for:

- direct Agent A tunnel
- Agent B through Agent A relay
- Agent C through Agent B if testing deeper chains

## Suggested Path RTT Check

Use a small TCP service or ICMP through the tunnel and compare median round-trip
time for the full active path:

```
ping -c 20 <target-ip>
```

or:

```
for i in $(seq 1 20); do time nc -vz <target-ip> <port>; done
```

## What to Capture

- hop depth
- route/interface name
- median path RTT
- throughput with one stream and with four parallel streams
- CPU use on the proxy and relay agent
- whether the relay agent is also running a tunnel or listeners

Attach these numbers to release notes when relay or yamux tuning changes.
