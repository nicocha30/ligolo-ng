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
	"io"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/adapters/gonet"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
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

		reply := protocolDecoder.Payload.(*protocol.HostPingResponsePacket)
		if reply.Alive {
			logrus.Debug("Host is alive, sending reply")
			ProcessICMP(nstack, pkt)

		}

	}
	// Ignore other ICMPs
	return
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
		return
	}
	connectPacket := protocol.ConnectRequestPacket{
		Net:       protonet,
		Transport: prototransport,
		Address:   targetIp,
		Port:      endpointID.LocalPort,
	}

	protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
	protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

	if err := protocolEncoder.Encode(connectPacket); err != nil {
		logrus.Error(err)
		return
	}

	logrus.Debug("Awaiting response...")
	if err := protocolDecoder.Decode(); err != nil {
		if err != io.EOF {
			logrus.Error(err)
		}
		return
	}

	reply := protocolDecoder.Payload.(*protocol.ConnectResponsePacket)
	if reply.Established {
		logrus.Debug("Connection established on remote end!")
		go func() {
			var wq waiter.Queue
			if localConn.IsTCP() {
				ep, iperr := localConn.GetTCP().Request.CreateEndpoint(&wq)
				if iperr != nil {
					logrus.Error(iperr)
					localConn.Terminate(true)
					return
				}
				gonetConn := gonet.NewTCPConn(&wq, ep)
				go relay.StartRelay(yamuxConnectionSession, gonetConn)

			} else if localConn.IsUDP() {
				ep, iperr := localConn.GetUDP().Request.CreateEndpoint(&wq)
				if iperr != nil {
					logrus.Error(iperr)
					localConn.Terminate(false)
					return
				}

				gonetConn := gonet.NewUDPConn(nstack, &wq, ep)
				go relay.StartRelay(yamuxConnectionSession, gonetConn)
			}

		}()
	} else {
		localConn.Terminate(reply.Reset)
	}

}
