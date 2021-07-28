package netstack

import (
	"bytes"
	"errors"
	"github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

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
		we, ch := waiter.NewChannelEntry(nil)
		wq.EventRegister(&we, waiter.ReadableEvents)
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
							panic(err)
						}
					}

					iph := header.IPv4(buff.Bytes())

					hlen := int(iph.HeaderLength())
					if buff.Len() < hlen {
						return
					}

					// Reconstruct a ICMP PacketBuffer from bytes.
					view := buffer.NewViewFromBytes(buff.Bytes())
					packetbuff := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Data:               view.ToVectorisedView(),
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
func ProcessICMP(nstack *stack.Stack, pkt *stack.PacketBuffer) {
	// (gvisor) pkg/tcpip/network/ipv4/icmp.go:174 - handleICMP

	// ICMP packets don't have their TransportHeader fields set. See
	// icmp/protocol.go:protocol.Parse for a full explanation.
	v, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
	if !ok {
		return
	}
	h := header.ICMPv4(v)

	// Only do in-stack processing if the checksum is correct.
	if pkt.Data().AsRange().Checksum() != 0xffff {
		return
	}

	iph := header.IPv4(pkt.NetworkHeader().View())
	var newOptions header.IPv4Options

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:

		replyData := pkt.Data().AsRange().ToOwnedView()
		ipHdr := header.IPv4(pkt.NetworkHeader().View())

		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		// It's possible that a raw socket expects to receive this.
		pkt = nil

		// Take the base of the incoming request IP header but replace the options.
		replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
		replyIPHdr := header.IPv4(append(iph[:header.IPv4MinimumSize:header.IPv4MinimumSize], newOptions...))
		replyIPHdr.SetHeaderLength(replyHeaderLength)

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := ipHdr.DestinationAddress()
		if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
			localAddr = ""
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

		replyICMPHdr := header.ICMPv4(replyData)
		replyICMPHdr.SetType(header.ICMPv4EchoReply)
		replyICMPHdr.SetChecksum(0)
		replyICMPHdr.SetChecksum(^header.Checksum(replyData, 0))

		replyVV := buffer.View(replyIPHdr).ToVectorisedView()
		replyVV.AppendView(replyData)
		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Data:               replyVV,
		})
		replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

		if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
			panic(err)
			return
		}
	}
}
