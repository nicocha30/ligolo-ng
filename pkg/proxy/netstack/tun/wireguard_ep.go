//go:build !linux
// +build !linux

package tun

import (
	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type RWEndpoint struct {
	wgdev      wgtun.Device
	dispatcher stack.NetworkDispatcher
	mtu        uint32
}

func NewRWEndpoint(dev wgtun.Device, mtu uint32) *RWEndpoint {
	return &RWEndpoint{
		wgdev: dev,
		mtu:   mtu,
	}
}

// MTU implements stack.LinkEndpoint.
func (m *RWEndpoint) MTU() uint32 {
	return m.mtu
}

// Capabilities implements stack.LinkEndpoint.
func (m *RWEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (m *RWEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress implements stack.LinkEndpoint.
func (m *RWEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Attach implements stack.LinkEndpoint.
func (m *RWEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	m.dispatcher = dispatcher
	go m.dispatchLoop()
}

func (m *RWEndpoint) dispatchLoop() {
	for {
		packet := make([]byte, m.mtu)

		n, err := m.wgdev.Read(packet, 0)
		if err != nil {
			break
		}

		if !m.IsAttached() {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet[:n]),
		})

		switch header.IPVersion(packet) {
		case header.IPv4Version:
			m.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkb)
		case header.IPv6Version:
			m.dispatcher.DeliverNetworkPacket(header.IPv6ProtocolNumber, pkb)
		}
	}
}

// IsAttached implements stack.LinkEndpoint.
func (m *RWEndpoint) IsAttached() bool {
	return m.dispatcher != nil
}

// WritePackets writes outbound packets
func (m *RWEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if err := m.WritePacket(pkt); err != nil {
			break
		}
		n++
	}
	return n, nil
}

// WritePacket writes outbound packets
func (m *RWEndpoint) WritePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	var buf buffer.Buffer
	pktBuf := pkt.ToBuffer()
	buf.Merge(&pktBuf)

	if _, err := m.wgdev.Write(buf.Flatten(), 0); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (m *RWEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*RWEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*RWEndpoint) AddHeader(pkt stack.PacketBufferPtr) {
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*RWEndpoint) WriteRawPacket(stack.PacketBufferPtr) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*RWEndpoint) ParseHeader(stack.PacketBufferPtr) bool { return true }
