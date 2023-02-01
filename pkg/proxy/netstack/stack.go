package netstack

import (
	"fmt"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv6"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/udp"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack/tun"
	"github.com/sirupsen/logrus"
	"sync"
)

type TunConn struct {
	Protocol tcpip.TransportProtocolNumber
	Handler  interface{}
}

// IsTCP check if the current TunConn is TCP
func (t TunConn) IsTCP() bool {
	return t.Protocol == tcp.ProtocolNumber
}

// GetTCP returns the handler as a TCPConn
func (t TunConn) GetTCP() TCPConn {
	return t.Handler.(TCPConn)
}

// IsUDP check if the current TunConn is UDP
func (t TunConn) IsUDP() bool {
	return t.Protocol == udp.ProtocolNumber
}

// GetUDP returns the handler as a UDPConn
func (t TunConn) GetUDP() UDPConn {
	return t.Handler.(UDPConn)
}

// IsICMP check if the current TunConn is ICMP
func (t TunConn) IsICMP() bool {
	return t.Protocol == icmp.ProtocolNumber4
}

// GetICMP returns the handler as a ICMPConn
func (t TunConn) GetICMP() ICMPConn {
	return t.Handler.(ICMPConn)
}

// Terminate is call when connections need to be terminated. For now, this is only useful for TCP connections
func (t TunConn) Terminate(reset bool) {
	if t.IsTCP() {
		t.GetTCP().Request.Complete(reset)
	}
}

// TCPConn represents a TCP Forwarder connection
type TCPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *tcp.ForwarderRequest
}

// UDPConn represents a UDP Forwarder connection
type UDPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *udp.ForwarderRequest
}

// ICMPConn represents a ICMP Packet Buffer
type ICMPConn struct {
	Request stack.PacketBufferPtr
}

// NetStack is the structure used to store the connection pool and the gvisor network stack
type NetStack struct {
	pool  *ConnPool
	stack *stack.Stack
	sync.Mutex
}

type StackSettings struct {
	TunName     string
	MaxInflight int
}

// NewStack registers a new GVisor Network Stack
func NewStack(settings StackSettings, connPool *ConnPool) *NetStack {
	ns := NetStack{pool: connPool}
	ns.new(settings)
	return &ns
}

// GetStack returns the current Gvisor stack.Stack object
func (s *NetStack) GetStack() *stack.Stack {
	return s.stack
}

// SetConnPool is used to change the current connPool. It must be used after switching Ligolo agents
func (s *NetStack) SetConnPool(connPool *ConnPool) {
	s.Lock()
	s.pool = connPool
	s.Unlock()
}

// New creates a new userland network stack (using Gvisor) that listen on a tun interface.
func (s *NetStack) new(stackSettings StackSettings) *stack.Stack {

	// Create a new gvisor userland network stack.
	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	s.stack = ns

	// Gvisor Hack: Disable ICMP handling.
	ns.SetICMPLimit(0)
	ns.SetICMPBurst(0)

	// Forward TCP connections
	tcpHandler := tcp.NewForwarder(ns, 0, stackSettings.MaxInflight, func(request *tcp.ForwarderRequest) {
		tcpConn := TCPConn{
			EndpointID: request.ID(),
			Request:    request,
		}
		s.Lock()
		defer s.Unlock()
		if s.pool == nil || s.pool.Closed() {
			return // If connPool is closed, ignore packet.
		}

		if err := s.pool.Add(TunConn{
			tcp.ProtocolNumber,
			tcpConn,
		}); err != nil {
			logrus.Error(err)
		}
	})

	// Forward UDP connections
	udpHandler := udp.NewForwarder(ns, func(request *udp.ForwarderRequest) {

		udpConn := UDPConn{
			EndpointID: request.ID(),
			Request:    request,
		}

		s.Lock()
		defer s.Unlock()

		if s.pool == nil || s.pool.Closed() {
			return // If connPool is closed, ignore packet.
		}

		if err := s.pool.Add(TunConn{
			udp.ProtocolNumber,
			udpConn,
		}); err != nil {
			logrus.Error(err)
		}
	})

	// Register forwarders
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)

	linkEP, err := tun.Open(stackSettings.TunName)
	if err != nil {
		logrus.Fatalf("unable to create tun interface: (tun.Open %v), make sure you created the tun interface", err)
	}
	// Create a new NIC
	if err := ns.CreateNIC(1, linkEP); err != nil {
		panic(fmt.Errorf("CreateNIC: %v", err))
	}

	// Start a endpoint that will reply to ICMP echo queries
	if err := icmpResponder(s); err != nil {
		logrus.Fatal(err)
	}

	// Allow all routes by default

	ns.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	// Enable forwarding
	ns.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, false)
	ns.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, false)

	// Enable TCP SACK
	nsacks := tcpip.TCPSACKEnabled(false)
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &nsacks)

	// Disable SYN-Cookies, as this can mess with nmap scans
	synCookies := tcpip.TCPAlwaysUseSynCookies(false)
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &synCookies)

	// Allow packets from all sources/destinations
	ns.SetPromiscuousMode(1, true)
	ns.SetSpoofing(1, true)

	return ns
}
