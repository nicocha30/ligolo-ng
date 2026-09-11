// Ligolo-ng
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
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/adapters/gonet"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv6"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/udp"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
)

// handleICMP process incoming ICMP packets and, depending on the target host status, respond a ICMP ECHO Reply
// Please note that other ICMP messages are not yet supported.
func handleICMP(nstack *stack.Stack, localConn TunConn, yamuxConn *yamux.Session) {
	pkt := localConn.GetICMP().Request
	v, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
	if !ok {
		return
	}
	h := header.ICMPv4(v)
	if h.Type() == header.ICMPv4Echo {
		iph := header.IPv4(pkt.NetworkHeader().Slice())
		yamuxConnectionSession, err := yamuxConn.Open()
		if err != nil {
			logrus.Error(err)
			return
		}
		defer yamuxConnectionSession.Close()
		logrus.Debugf("Checking if %s is alive...\n", iph.DestinationAddress().String())
		icmpPacket := protocol.HostPingRequestPacket{Address: iph.DestinationAddress().String()}

		protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
		protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

		if err := protocolEncoder.Encode(icmpPacket); err != nil {
			logrus.Error(err)
			return
		}

		logrus.Debug("Awaiting ping response...")
		if err := protocolDecoder.Decode(); err != nil {
			logrus.Error(err)
			return
		}

		reply, err := protocol.PayloadAs[protocol.HostPingResponsePacket](protocolDecoder.Payload)
		if err != nil {
			logrus.Error(err)
			return
		}
		if reply.Alive {
			logrus.Debug("Host is alive, sending reply")
			ProcessICMP(nstack, pkt)

		}

	}
	// Ignore other ICMPs
	return
}

// sendUDPPortUnreachable reconstructs the UDP datagram that caused the remote
// error and lets gVisor generate the corresponding ICMPv4/ICMPv6 rejection.
func sendUDPPortUnreachable(nstack *stack.Stack, endpointID stack.TransportEndpointID, payload []byte) error {
	networkProtocol := ipv4.ProtocolNumber
	networkHeaderSize := header.IPv4MinimumSize
	maxPayloadSize := int(^uint16(0)) - networkHeaderSize - header.UDPMinimumSize
	if endpointID.LocalAddress.To4() == (tcpip.Address{}) {
		networkProtocol = ipv6.ProtocolNumber
		networkHeaderSize = header.IPv6MinimumSize
		maxPayloadSize = int(^uint16(0)) - header.UDPMinimumSize
	}
	if len(payload) > maxPayloadSize {
		payload = payload[:maxPayloadSize]
	}

	packetBytes := make([]byte, networkHeaderSize+header.UDPMinimumSize+len(payload))
	udpHeader := header.UDP(packetBytes[networkHeaderSize:])
	udpHeader.Encode(&header.UDPFields{
		SrcPort: endpointID.RemotePort,
		DstPort: endpointID.LocalPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(packetBytes[networkHeaderSize+header.UDPMinimumSize:], payload)

	switch networkProtocol {
	case ipv4.ProtocolNumber:
		ipHeader := header.IPv4(packetBytes)
		ipHeader.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(packetBytes)),
			TTL:         64,
			Protocol:    uint8(udp.ProtocolNumber),
			SrcAddr:     endpointID.RemoteAddress,
			DstAddr:     endpointID.LocalAddress,
		})
		ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	case ipv6.ProtocolNumber:
		header.IPv6(packetBytes).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
			TransportProtocol: udp.ProtocolNumber,
			HopLimit:          64,
			SrcAddr:           endpointID.RemoteAddress,
			DstAddr:           endpointID.LocalAddress,
		})
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packetBytes)})
	defer pkt.DecRef()
	pkt.NICID = 1
	pkt.NetworkProtocolNumber = networkProtocol

	network := nstack.NetworkProtocolInstance(networkProtocol)
	if network == nil {
		return fmt.Errorf("network protocol %d is not registered", networkProtocol)
	}
	transportProtocol, hasTransportHeader, ok := network.Parse(pkt)
	if !ok || !hasTransportHeader || transportProtocol != udp.ProtocolNumber {
		return errors.New("unable to parse reconstructed UDP packet")
	}
	pkt.TransportProtocolNumber = transportProtocol
	if result := nstack.ParsePacketBufferTransport(transportProtocol, pkt); result != stack.ParsedOK {
		return fmt.Errorf("unable to parse reconstructed UDP transport header: %d", result)
	}

	switch networkProtocol {
	case ipv4.ProtocolNumber:
		rejector, ok := network.(stack.RejectIPv4WithHandler)
		if !ok {
			return errors.New("IPv4 network protocol cannot generate rejection errors")
		}
		if err := rejector.SendRejectionError(pkt, stack.RejectIPv4WithICMPPortUnreachable, true); err != nil {
			return errors.New(err.String())
		}
	case ipv6.ProtocolNumber:
		rejector, ok := network.(stack.RejectIPv6WithHandler)
		if !ok {
			return errors.New("IPv6 network protocol cannot generate rejection errors")
		}
		if err := rejector.SendRejectionError(pkt, stack.RejectIPv6WithICMPPortUnreachable, true); err != nil {
			return errors.New(err.String())
		}
	}
	return nil
}

func HandlePacket(nstack *stack.Stack, localConn TunConn, yamuxConn *yamux.Session) {

	var endpointID stack.TransportEndpointID
	var prototransport uint8
	var protonet uint8

	// Switching part
	switch localConn.Protocol {
	case tcp.ProtocolNumber:
		endpointID = localConn.GetTCP().EndpointID
		prototransport = protocol.TransportTCP
	case udp.ProtocolNumber:
		endpointID = localConn.GetUDP().EndpointID
		prototransport = protocol.TransportUDP
	case icmp.ProtocolNumber4:
		// ICMPs can't be relayed
		handleICMP(nstack, localConn, yamuxConn)
		return
	}

	if endpointID.LocalAddress.To4() != (tcpip.Address{}) {
		protonet = protocol.Networkv4
	} else {
		protonet = protocol.Networkv6
	}

	logrus.Debugf("Got packet source : %s - endpointID : %s:%d", endpointID.RemoteAddress, endpointID.LocalAddress, endpointID.LocalPort)

	targetIp := endpointID.LocalAddress.String()

	magicNet := net.IPNet{
		IP:   net.IPv4(240, 0, 0, 0),
		Mask: []byte{0xf0, 0x00, 0x00, 0x00},
	}

	if magicNet.Contains(net.ParseIP(targetIp)) {
		logrus.Debug("MagicIP detected, redirecting to agent local machine")
		// Magic IP detected
		targetIp = "127.0.0.1"
	}

	yamuxConnectionSession, err := yamuxConn.Open()
	if err != nil {
		logrus.Error(err)
		// Release the forwarder in-flight slot (and RST the local client) so a
		// failed tunnel Open does not leak a gVisor forwarder request.
		localConn.Terminate(true)
		return
	}
	connectPacket := protocol.ConnectRequestPacket{
		Net:       protonet,
		Transport: prototransport,
		Address:   targetIp,
		Port:      endpointID.LocalPort,
		FramedUDP: localConn.IsUDP(),
	}

	protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
	protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

	if err := protocolEncoder.Encode(connectPacket); err != nil {
		logrus.Error(err)
		_ = yamuxConnectionSession.Close()
		localConn.Terminate(true)
		return
	}

	logrus.Debug("Awaiting response...")
	if err := protocolDecoder.Decode(); err != nil {
		if err != io.EOF {
			logrus.Error(err)
		}
		_ = yamuxConnectionSession.Close()
		localConn.Terminate(true)
		return
	}

	reply, err := protocol.PayloadAs[protocol.ConnectResponsePacket](protocolDecoder.Payload)
	if err != nil {
		logrus.Error(err)
		_ = yamuxConnectionSession.Close()
		localConn.Terminate(true)
		return
	}
	if reply.Established {
		logrus.Debug("Connection established on remote end!")
		go func() {
			var wq waiter.Queue
			if localConn.IsTCP() {
				ep, iperr := localConn.GetTCP().Request.CreateEndpoint(&wq)
				if iperr != nil {
					logrus.Error(iperr)
					localConn.Terminate(true)
					_ = yamuxConnectionSession.Close()
					return
				}
				gonetConn := gonet.NewTCPConn(&wq, ep)
				// Handshake done: release the forwarder in-flight slot (no RST)
				// so it does not leak for the lifetime of the connection.
				localConn.Terminate(false)
				go relay.StartRelay(yamuxConnectionSession, gonetConn)

			} else if localConn.IsUDP() {
				ep, iperr := localConn.GetUDP().Request.CreateEndpoint(&wq)
				if iperr != nil {
					logrus.Error(iperr)
					localConn.Terminate(false)
					_ = yamuxConnectionSession.Close()
					return
				}

				gonetConn := gonet.NewUDPConn(nstack, &wq, ep)
				if reply.FramedUDP {
					go relay.StartFramedPacketRelay(yamuxConnectionSession, gonetConn, nil, func(relayError relay.PacketRelayError, payload []byte) {
						if relayError != relay.PacketRelayPortUnreachable {
							logrus.Warnf("Unsupported UDP relay error: %d", relayError)
							return
						}
						if err := sendUDPPortUnreachable(nstack, endpointID, payload); err != nil {
							logrus.Errorf("Unable to send UDP Port Unreachable: %v", err)
						}
					})
				} else {
					go relay.StartRelay(yamuxConnectionSession, gonetConn)
				}
			}

		}()
	} else {
		// Connection not established: terminate local conn and close request stream.
		localConn.Terminate(reply.Reset)
		_ = yamuxConnectionSession.Close()
	}

}
