# Ligolo-ng : Tunneling like a VPN

![Ligolo Logo](doc/logo.png)

An advanced, yet simple, tunneling tool that uses TUN interfaces.

[![GPLv3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Report](https://goreportcard.com/badge/github.com/nicocha30/ligolo-ng)](https://goreportcard.com/report/github.com/nicocha30/ligolo-ng)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/nicocha30)](https://github.com/sponsors/nicocha30)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nicocha30/ligolo-ng/total)

[📑 Ligolo-ng Documentation (Setup/Quickstart)](https://github.com/nicocha30/ligolo-ng/wiki)

You use Ligolo-ng for your penetration tests? Did it help you pass a certification? Please consider sponsoring the project so I can buy my team some drinks. ☕

[:heart: Sponsor nicocha30](https://github.com/sponsors/nicocha30)

We would like to thank the following people for their support in the development of Ligolo-ng.

<!-- sponsors --><a href="https://github.com/OSCPL-byte"><img src="https://github.com/OSCPL-byte.png" width="50px" alt="OSCPL-byte" /></a>&nbsp;&nbsp;<a href="https://github.com/scmanjarrez"><img src="https://github.com/scmanjarrez.png" width="50px" alt="scmanjarrez" /></a>&nbsp;&nbsp;<!-- sponsors -->

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Introduction](#introduction)
- [Features](#features)
- [Demo](#demo)
- [How is this different from Ligolo/Chisel/Meterpreter... ?](#how-is-this-different-from-ligolochiselmeterpreter-)
- [How to use - documentation - tutorial](#how-to-use---documentation---tutorial)
- [Does it require Administrator/root access ?](#does-it-require-administratorroot-access-)
- [Supported protocols/packets](#supported-protocolspackets)
- [Performance](#performance)
- [Caveats](#caveats)
- [Todo](#todo)
- [Credits](#credits)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction

**Ligolo-ng** is a *simple*, *lightweight* and *fast* tool that allows pentesters to establish
tunnels from a reverse TCP/TLS connection using a **tun interface** (without the need of SOCKS).

## Features

- **Tun interface** (No more SOCKS/Proxychains!)
- Simple UI with *agent* selection and *network information*
- Easy to use and setup
- Automatic certificate configuration with Let's Encrypt
- Performant (Multiplexing)
- Does not require privileges on the *agent*
- Socket listening/binding on the *agent*
- Multiple platforms supported for the *agent*
- Can handle multiple tunnels
- Reverse/Bind Connection
- Automatic tunnel/listeners recovery (in case of network issues)
- Websocket support

## Demo

[Ligolo-ng-demo.webm](https://github.com/nicocha30/ligolo-ng/assets/31402213/3070bb7c-0b0d-4c77-9181-cff74fb2f0ba)

## How is this different from Ligolo/Chisel/Meterpreter... ?

Instead of using a SOCKS proxy or TCP/UDP forwarders, **Ligolo-ng** creates a userland network stack using [Gvisor](https://gvisor.dev/).

When running the *relay/proxy* server, a **tun** interface is used, packets sent to this interface are
translated, and then transmitted to the *agent* remote network.

As an example, for a TCP connection:

- SYN are translated to connect() on remote
- SYN-ACK is sent back if connect() succeed
- RST is sent if ECONNRESET, ECONNABORTED or ECONNREFUSED syscall are returned after connect
- Nothing is sent if timeout

This allows running tools like *nmap* without the use of *proxychains* (simpler and faster).

## How to use - documentation - tutorial

You will find the documentation for Ligolo-ng, as well as the steps to follow to get it up and running on the [Ligolo-ng Wiki](https://github.com/nicocha30/ligolo-ng/wiki)

## Does it require Administrator/root access ?

On the *agent* side, no! Everything can be performed without administrative access.

However, on your *relay/proxy* server, you need to be able to create a *tun* interface.

## Supported protocols/packets

* TCP
* UDP
* ICMP (echo requests)

## Performance

You can easily hit more than 100 Mbits/sec. Here is a test using `iperf` from a 200Mbits/s server to a 200Mbits/s connection.
```shell
$ iperf3 -c 10.10.0.1 -p 24483
Connecting to host 10.10.0.1, port 24483
[  5] local 10.10.0.224 port 50654 connected to 10.10.0.1 port 24483
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  12.5 MBytes   105 Mbits/sec    0    164 KBytes       
[  5]   1.00-2.00   sec  12.7 MBytes   107 Mbits/sec    0    263 KBytes       
[  5]   2.00-3.00   sec  12.4 MBytes   104 Mbits/sec    0    263 KBytes       
[  5]   3.00-4.00   sec  12.7 MBytes   106 Mbits/sec    0    263 KBytes       
[  5]   4.00-5.00   sec  13.1 MBytes   110 Mbits/sec    2    134 KBytes       
[  5]   5.00-6.00   sec  13.4 MBytes   113 Mbits/sec    0    147 KBytes       
[  5]   6.00-7.00   sec  12.6 MBytes   105 Mbits/sec    0    158 KBytes       
[  5]   7.00-8.00   sec  12.1 MBytes   101 Mbits/sec    0    173 KBytes       
[  5]   8.00-9.00   sec  12.7 MBytes   106 Mbits/sec    0    182 KBytes       
[  5]   9.00-10.00  sec  12.6 MBytes   106 Mbits/sec    0    188 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec   127 MBytes   106 Mbits/sec    2             sender
[  5]   0.00-10.08  sec   125 MBytes   104 Mbits/sec                  receiver
```

## Caveats

Because the *agent* is running without privileges, it's not possible to forward raw packets.
When you perform a NMAP SYN-SCAN, a TCP connect() is performed on the agent.

When using *nmap*, you should use `--unprivileged` or `-PE` to avoid false positives.

## Todo

- Implement other ICMP error messages (this will speed up UDP scans) ;
- Do not *RST* when receiving an *ACK* from an invalid TCP connection (nmap will report the host as up) ;
- Add mTLS support.

## Credits

- Nicolas Chatelain <nicolas -at- chatelain.me>
