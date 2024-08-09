package protocol

import (
	"net"
)

// Envelope is the structure used when Encoding/Decode ligolo packets
type Envelope struct {
	Type    uint8
	Payload interface{}
}

const (
	MessageInfoRequest = uint8(iota)
	MessageInfoReply
	MessageConnectRequest
	MessageConnectResponse
	MessageHostPingRequest
	MessageHostPingResponse
	MessageListenerRequest // Start a listener
	MessageListenerResponse
	MessageListenerBindRequest // Bind to a listener
	MessageListenerBindResponse
	MessageListenerSockRequest // Bind to a socket
	MessageListenerSockResponse
	MessageListenerCloseRequest
	MessageListenerCloseResponse
	MessageClose
)

const (
	TransportTCP = uint8(iota)
	TransportUDP
)

const (
	Networkv4 = uint8(iota)
	Networkv6
)

// InfoRequestPacket is sent by the proxy to discover the agent information
type InfoRequestPacket struct {
}

// InfoReplyPacket contains the Name of the agent and the network interfaces configuration
type InfoReplyPacket struct {
	Name       string
	Interfaces []NetInterface
	SessionID  string
}

// ListenerSockRequestPacket is used by the proxy when relaying a listener socket
type ListenerSockRequestPacket struct {
	SockID int32
}

// ListenerSockRequestPacket is the response to ListenerSockRequestPacket
type ListenerSockResponsePacket struct {
	ErrString string
	Err       bool
}

// ListenerRequestPacket is used when a new listener socket is created by the proxy.
type ListenerRequestPacket struct {
	Network string
	Address string
}

// ListenerResponsePacket is used to indicate if the Listener was created, and send the ListenerID.
type ListenerResponsePacket struct {
	ListenerID int32
	Err        bool
	ErrString  string
}

// ListenerBindPacket is used by the proxy to Bind to a ListenerID, waiting for connections.
type ListenerBindPacket struct {
	ListenerID int32
}

// ListenerBindReponse is returned when listener sockets are ready to be relayed from the agent to the proxy.
type ListenerBindReponse struct {
	SockID    int32
	Err       bool
	ErrString string
}

// ListenerUDPPacket
type ListenerUDPPacket struct {
}

// ListenerCloseRequestPacket is the packet sent when closing Listeners
type ListenerCloseRequestPacket struct {
	ListenerID int32
}

// ListenerCloseResponsePacket is the response to ListenerCloseRequestPacket
type ListenerCloseResponsePacket struct {
	ErrString string
	Err       bool
}

// NetInterface is the structure containing the agent network informations
type NetInterface struct {
	Index        int              // positive integer that starts at one, zero is never used
	MTU          int              // maximum transmission unit
	Name         string           // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr net.HardwareAddr // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        net.Flags        // e.g., FlagUp, FlagLoopback, FlagMulticast
	Addresses    []string
}

// NewNetInterfaces converts a net.Interface slice to a NetInterface slice that can be transmitted over Gob
func NewNetInterfaces(netif []net.Interface) (out []NetInterface) {
	// the net.Interface struct doesn't contains the IP Address, we need a new struct that store IPs
	for _, iface := range netif {
		var addrs []string
		addresses, err := iface.Addrs()
		if err != nil {
			addresses = []net.Addr{}
		}
		for _, addrStr := range addresses {
			addrs = append(addrs, addrStr.String())
		}
		out = append(out, NetInterface{
			Index:        iface.Index,
			MTU:          iface.MTU,
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr,
			Flags:        iface.Flags,
			Addresses:    addrs,
		})
	}
	return
}

// ConnectRequestPacket is sent by the proxy to request a new TCP/UDP connection
type ConnectRequestPacket struct {
	Net       uint8
	Transport uint8
	Address   string
	Port      uint16
}

// ConnectResponsePacket is the response to the ConnectRequestPacket and indicate if the connection can be established, and if a RST packet need to be sent
type ConnectResponsePacket struct {
	Established bool
	Reset       bool
}

// HostPingRequestPacket is used when a ICMP packet is received on the proxy server. It is used to request a ping request to the agent
type HostPingRequestPacket struct {
	Address string
}

// HostPingResponsePacket is sent by the agent to indicate the requested host status
type HostPingResponsePacket struct {
	Alive bool
}
