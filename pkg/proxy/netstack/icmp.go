// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package netstack

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"time"

	"encoding/binary"
	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/checksum"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv6"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/raw"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"github.com/sirupsen/logrus"
)

var icmpPortUnreachableLimiter = newICMPRateLimiter(icmpPortUnreachableInterval())

func icmpPortUnreachableInterval() time.Duration {
	value := os.Getenv("LIGOLO_ICMP_UNREACHABLE_INTERVAL")
	if value == "" {
		return time.Second
	}
	interval, err := time.ParseDuration(value)
	if err != nil {
		logrus.Warnf("invalid LIGOLO_ICMP_UNREACHABLE_INTERVAL=%q, using 1s", value)
		return time.Second
	}
	return interval
}

type icmpRateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
	now      func() time.Time
}

func newICMPRateLimiter(interval time.Duration) *icmpRateLimiter {
	return &icmpRateLimiter{
		interval: interval,
		last:     make(map[string]time.Time),
		now:      time.Now,
	}
}

func (rl *icmpRateLimiter) allow(key string) bool {
	if rl.interval <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	if last, ok := rl.last[key]; ok && now.Sub(last) < rl.interval {
		return false
	}
	rl.last[key] = now
	return true
}

// icmpResponder handle ICMP packets coming to gvisor/netstack.
// Instead of responding to all ICMPs ECHO by default, we try to
// execute a ping on the Agent, and depending of the response, we
// send a ICMP reply back.
func icmpResponder(s *NetStack) error {

	var wq waiter.Queue
	rawProto, rawerr := raw.NewEndpoint(s.stack, ipv4.ProtocolNumber, icmp.ProtocolNumber4, &wq)
	if rawerr != nil {
		return errors.New("could not create raw endpoint")
	}
	if err := rawProto.Bind(tcpip.FullAddress{}); err != nil {
		return errors.New("could not bind raw endpoint")
	}
	go func() {
		we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&we)
		for {
			var buff bytes.Buffer
			_, err := rawProto.Read(&buff, tcpip.ReadOptions{})

			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				// Wait for data to become available.
				select {
				case <-ch:
					_, err := rawProto.Read(&buff, tcpip.ReadOptions{})

					if err != nil {
						if _, ok := err.(*tcpip.ErrWouldBlock); ok {
							// Oh, a race condition?
							continue
						} else {
							// This is bad.
							logrus.Error(err)
							return
						}
					}

					iph := header.IPv4(buff.Bytes())

					hlen := int(iph.HeaderLength())
					if buff.Len() < hlen {
						return
					}

					// Reconstruct a ICMP PacketBuffer from bytes.

					view := buffer.MakeWithData(buff.Bytes())
					packetbuff := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload:            view,
						ReserveHeaderBytes: hlen,
					})

					packetbuff.NetworkProtocolNumber = ipv4.ProtocolNumber
					packetbuff.TransportProtocolNumber = icmp.ProtocolNumber4
					packetbuff.NetworkHeader().Consume(hlen)
					tunConn := TunConn{
						Protocol: icmp.ProtocolNumber4,
						Handler:  ICMPConn{Request: packetbuff},
					}

					s.Lock()
					if s.pool == nil || s.pool.Closed() {
						s.Unlock()
						continue // If connPool is closed, ignore packet.
					}

					if err := s.pool.Add(tunConn); err != nil {
						s.Unlock()
						logrus.Error(err)
						continue // Unknown error, continue...
					}
					s.Unlock()
				}
			}

		}
	}()
	return nil
}

// ProcessICMP send back a ICMP echo reply from after receiving a echo request.
// This code come mostly from pkg/tcpip/network/ipv4/icmp.go
func ProcessICMP(nstack *stack.Stack, pkt stack.PacketBufferPtr) {
	// (gvisor) pkg/tcpip/network/ipv4/icmp.go:174 - handleICMP

	// ICMP packets don't have their TransportHeader fields set. See
	// icmp/protocol.go:protocol.Parse for a full explanation.
	v, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
	if !ok {
		return
	}
	h := header.ICMPv4(v)
	// Ligolo-ng Relay: not sure why, but checksum is invalid here.
	/*
		// Only do in-stack processing if the checksum is correct.
		if checksum.Checksum(h, pkt.Data().Checksum()) != 0xffff {
			return
		}
	*/
	iph := header.IPv4(pkt.NetworkHeader().Slice())
	var newOptions header.IPv4Options

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:
		replyData := stack.PayloadSince(pkt.TransportHeader())
		defer replyData.Release()
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())

		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		// It's possible that a raw socket expects to receive this.
		pkt = nil

		// Take the base of the incoming request IP header but replace the options.
		replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
		replyIPHdrView := buffer.NewView(int(replyHeaderLength))
		replyIPHdrView.Write(iph[:header.IPv4MinimumSize])
		replyIPHdrView.Write(newOptions)
		replyIPHdr := header.IPv4(replyIPHdrView.AsSlice())
		replyIPHdr.SetHeaderLength(replyHeaderLength)

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := ipHdr.DestinationAddress()
		if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
			localAddr = tcpip.Address{}
		}

		r, err := nstack.FindRoute(1, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		replyIPHdr.SetSourceAddress(r.LocalAddress())
		replyIPHdr.SetDestinationAddress(r.RemoteAddress())
		replyIPHdr.SetTTL(r.DefaultTTL())

		replyICMPHdr := header.ICMPv4(replyData.AsSlice())
		replyICMPHdr.SetType(header.ICMPv4EchoReply)
		replyICMPHdr.SetChecksum(0)
		replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

		replyBuf := buffer.MakeWithView(replyIPHdrView)
		replyBuf.Append(replyData.Clone())
		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Payload:            replyBuf,
		})

		replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

		if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
			logrus.Error(err)
			return
		}
	}
}

// SendICMPPortUnreachable generates an ICMP Destination Unreachable "port
// unreachable" packet and injects it back into the TUN interface. This is sent
// when a UDP connection to a remote port is refused (ECONNREFUSED), allowing
// tools like nmap to detect closed UDP ports instantly instead of waiting for a
// timeout. It dispatches to the IPv4 (Type 3, Code 3) or IPv6 (Type 1, Code 4)
// path based on the address family.
//
// Per RFC 792 / RFC 4443, the ICMP error payload contains the original IP header
// plus the first 8 bytes of the original datagram (the UDP header), which lets
// the scanner correlate the error with its probe.
func SendICMPPortUnreachable(nstack *stack.Stack, endpointID stack.TransportEndpointID) {
	// The endpointID fields from the perspective of the netstack forwarder:
	//   LocalAddress/LocalPort   = the destination (target host:port)
	//   RemoteAddress/RemotePort = the source (scanner host:port)
	//
	// The ICMP error goes FROM the target back TO the scanner.
	target := endpointID.LocalAddress
	scanner := endpointID.RemoteAddress
	rateLimitKey := target.String() + ">" + scanner.String()
	if !icmpPortUnreachableLimiter.allow(rateLimitKey) {
		logrus.Debugf("SendICMPPortUnreachable: rate-limited response for %s", rateLimitKey)
		return
	}

	if target.Len() == 16 {
		sendICMPv6PortUnreachable(nstack, target, scanner, endpointID.LocalPort, endpointID.RemotePort)
		return
	}
	sendICMPv4PortUnreachable(nstack, target, scanner, endpointID.LocalPort, endpointID.RemotePort)
}

// buildICMPv4PortUnreachable builds a complete, checksummed ICMPv4 Destination
// Unreachable (Type 3, Code 3) message for a refused UDP datagram that went from
// embSrc:embSrcPort to embDst:embDstPort. The returned bytes are the ICMP
// message: header + embedded original IPv4 header + first 8 bytes (UDP header).
func buildICMPv4PortUnreachable(embSrc, embDst tcpip.Address, embSrcPort, embDstPort uint16) header.ICMPv4 {
	origIPHdr := make([]byte, header.IPv4MinimumSize)
	ip := header.IPv4(origIPHdr)
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     embSrc,
		DstAddr:     embDst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	origUDPHdr := make([]byte, header.UDPMinimumSize)
	binary.BigEndian.PutUint16(origUDPHdr[0:2], embSrcPort)
	binary.BigEndian.PutUint16(origUDPHdr[2:4], embDstPort)
	binary.BigEndian.PutUint16(origUDPHdr[4:6], header.UDPMinimumSize)
	// checksum left as 0 (optional for UDP in IPv4)

	icmpLen := header.ICMPv4MinimumSize + len(origIPHdr) + len(origUDPHdr)
	icmpHdr := make(header.ICMPv4, icmpLen)
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(header.ICMPv4PortUnreachable)
	copy(icmpHdr[header.ICMPv4MinimumSize:], origIPHdr)
	copy(icmpHdr[header.ICMPv4MinimumSize+len(origIPHdr):], origUDPHdr)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(^checksum.Checksum(icmpHdr, 0))
	return icmpHdr
}

// buildICMPv6PortUnreachable builds a complete, checksummed ICMPv6 Destination
// Unreachable (Type 1, Code 4) message. The ICMPv6 checksum covers a pseudo-header
// derived from the outer source/destination addresses, so those are required.
func buildICMPv6PortUnreachable(outerSrc, outerDst, embSrc, embDst tcpip.Address, embSrcPort, embDstPort uint16) header.ICMPv6 {
	origIPHdr := make([]byte, header.IPv6MinimumSize)
	ip := header.IPv6(origIPHdr)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.UDPMinimumSize,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           embSrc,
		DstAddr:           embDst,
	})

	origUDPHdr := make([]byte, header.UDPMinimumSize)
	binary.BigEndian.PutUint16(origUDPHdr[0:2], embSrcPort)
	binary.BigEndian.PutUint16(origUDPHdr[2:4], embDstPort)
	binary.BigEndian.PutUint16(origUDPHdr[4:6], header.UDPMinimumSize)

	// [Type=1][Code=4][Checksum][Unused 4 bytes][Original IPv6 Hdr + 8 bytes]
	icmpLen := header.ICMPv6MinimumSize + len(origIPHdr) + len(origUDPHdr)
	icmpHdr := make(header.ICMPv6, icmpLen)
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(header.ICMPv6PortUnreachable)
	copy(icmpHdr[header.ICMPv6MinimumSize:], origIPHdr)
	copy(icmpHdr[header.ICMPv6MinimumSize+len(origIPHdr):], origUDPHdr)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    outerSrc,
		Dst:    outerDst,
	}))
	return icmpHdr
}

func sendICMPv4PortUnreachable(nstack *stack.Stack, target, scanner tcpip.Address, targetPort, scannerPort uint16) {
	r, err := nstack.FindRoute(1, target, scanner, ipv4.ProtocolNumber, false)
	if err != nil {
		logrus.Debugf("SendICMPPortUnreachable: could not find route: %v", err)
		return
	}
	defer r.Release()

	// Embedded original datagram travelled scanner -> target.
	icmpHdr := buildICMPv4PortUnreachable(scanner, target, scannerPort, targetPort)

	outerIPHdr := make(header.IPv4, header.IPv4MinimumSize)
	outerIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + len(icmpHdr)),
		TTL:         r.DefaultTTL(),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     r.LocalAddress(),
		DstAddr:     r.RemoteAddress(),
	})
	outerIPHdr.SetChecksum(^outerIPHdr.CalculateChecksum())

	pktBuf := buffer.MakeWithData(outerIPHdr)
	pktBuf.Append(buffer.NewViewWithData(icmpHdr))
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            pktBuf,
	})
	replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
		logrus.Debugf("SendICMPPortUnreachable: write error: %v", err)
		return
	}

	logrus.Debugf("Sent ICMPv4 Port Unreachable for %s:%d -> %s:%d",
		scanner, scannerPort, target, targetPort)
}

func sendICMPv6PortUnreachable(nstack *stack.Stack, target, scanner tcpip.Address, targetPort, scannerPort uint16) {
	r, err := nstack.FindRoute(1, target, scanner, ipv6.ProtocolNumber, false)
	if err != nil {
		logrus.Debugf("SendICMPPortUnreachable: could not find route: %v", err)
		return
	}
	defer r.Release()

	// Embedded original datagram travelled scanner -> target. The ICMPv6 checksum
	// pseudo-header uses the outer route addresses.
	icmpHdr := buildICMPv6PortUnreachable(r.LocalAddress(), r.RemoteAddress(), scanner, target, scannerPort, targetPort)

	outerIPHdr := make(header.IPv6, header.IPv6MinimumSize)
	outerIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(icmpHdr)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          r.DefaultTTL(),
		SrcAddr:           r.LocalAddress(),
		DstAddr:           r.RemoteAddress(),
	})

	pktBuf := buffer.MakeWithData(outerIPHdr)
	pktBuf.Append(buffer.NewViewWithData(icmpHdr))
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            pktBuf,
	})
	replyPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber

	if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
		logrus.Debugf("SendICMPPortUnreachable: write error: %v", err)
		return
	}

	logrus.Debugf("Sent ICMPv6 Port Unreachable for %s:%d -> %s:%d",
		scanner, scannerPort, target, targetPort)
}
