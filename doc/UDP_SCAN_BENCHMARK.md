# UDP Scan Benchmark

The UDP ICMP feature should be evaluated for both speed and classification
accuracy. The useful claim is not only "faster scans"; it is that refused UDP
ports can be classified as `closed` instead of lingering as `open|filtered`.

## Suggested Lab

Use a controlled target behind a Ligolo tunnel with one closed UDP port and one
open UDP service. Run each scan against upstream Ligolo-ng and Ligolo-ng Relay.

Example commands:

```
time nmap -sU -Pn -p 53,161,500,4500 <target-ip> -oN upstream-udp.txt
time nmap -sU -Pn -p 53,161,500,4500 <target-ip> -oN fork-udp.txt
```

Record:

- elapsed wall-clock time
- how many closed ports are reported as `closed`
- how many closed ports remain `open|filtered`
- whether open UDP services still classify correctly

## ICMP Rate Limiting

Real hosts commonly rate-limit ICMP unreachable responses. This fork defaults
to one ICMP Port Unreachable response per target/scanner pair per second.

Tune or disable the limiter on the proxy:

```
LIGOLO_ICMP_UNREACHABLE_INTERVAL=250ms ./proxy ...
LIGOLO_ICMP_UNREACHABLE_INTERVAL=0 ./proxy ...
```

Use lower values for lab benchmarking and higher values when realistic host-like
behavior matters more than scan speed.
