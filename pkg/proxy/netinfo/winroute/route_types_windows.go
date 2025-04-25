//  Copyright 2024 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Code from https://github.com/GoogleCloudPlatform/google-guest-agent

//go:build windows
// +build windows

package winroute

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// anySize is the size of the buffer.
	anySize = 1
)

// AddressFamily enumeration specifies protocol family and is one of the
// windows.AF_* constants.
type AddressFamily uint16

// LUID represents a network interface.
type LUID uint64

// IPAddressPrefix structure stores an IP address prefix.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type IPAddressPrefix struct {
	RawPrefix    RawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

// SetPrefix method sets IP address prefix using netip.Prefix.
func (prefix *IPAddressPrefix) SetPrefix(netPrefix netip.Prefix) error {
	err := prefix.RawPrefix.SetAddr(netPrefix.Addr())
	if err != nil {
		return err
	}
	prefix.PrefixLength = uint8(netPrefix.Bits())
	return nil
}

// RawSockaddrInet union contains an IPv4, an IPv6 address, or an address
// family.
// https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
type RawSockaddrInet struct {
	Family AddressFamily
	data   [26]byte
}

// SetAddrPort method sets family, address, and port to the given IPv4 or IPv6 address and port.
// All other members of the structure are set to zero.
func (addr *RawSockaddrInet) SetAddrPort(addrPort netip.AddrPort) error {
	if addrPort.Addr().Is4() {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		addr4.Family = windows.AF_INET
		addr4.Addr = addrPort.Addr().As4()
		addr4.Port = htons(addrPort.Port())
		for i := 0; i < 8; i++ {
			addr4.Zero[i] = 0
		}
		return nil
	} else if addrPort.Addr().Is6() {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		addr6.Family = windows.AF_INET6
		addr6.Addr = addrPort.Addr().As16()
		addr6.Port = htons(addrPort.Port())
		addr6.Flowinfo = 0
		scopeID := uint32(0)
		if z := addrPort.Addr().Zone(); z != "" {
			if s, err := strconv.ParseUint(z, 10, 32); err == nil {
				scopeID = uint32(s)
			}
		}
		addr6.Scope_id = scopeID
		return nil
	}
	return windows.ERROR_INVALID_PARAMETER
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// SetAddr method sets family and address to the given IPv4 or IPv6 address.
// All other members of the structure are set to zero.
func (addr *RawSockaddrInet) SetAddr(netAddr netip.Addr) error {
	return addr.SetAddrPort(netip.AddrPortFrom(netAddr, 0))
}

// Addr returns an IPv4 or IPv6 address, or an invalid address otherwise.
func (addr *RawSockaddrInet) Addr() (netip.Addr, error) {
	switch addr.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Addr), nil
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		result := netip.AddrFrom16(raw.Addr)
		if raw.Scope_id != 0 {
			result = result.WithZone(strconv.FormatUint(uint64(raw.Scope_id), 10))
		}
		return result, nil
	}
	return netip.Addr{}, fmt.Errorf("invalid address family: %v", addr.Family)
}

// Protocol enumeration type defines the routing mechanism that an IP route
// was added with, as described in RFC 4292.
// https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_route_protocol
type Protocol uint32

// Origin enumeration type defines the origin of the IP route.
// https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_route_origin
type Origin uint32

// MibIPforwardRow2 structure stores information about an IP route entry.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type MibIPforwardRow2 struct {
	InterfaceLUID        LUID
	InterfaceIndex       uint32
	DestinationPrefix    IPAddressPrefix
	NextHop              RawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             Protocol
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               Origin
}

// delete method deletes an IP route entry on the local computer.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
func (row *MibIPforwardRow2) delete() error {
	return deleteIPForwardEntry2(row)
}

// create method creates a new IP route entry on the local computer.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
func (row *MibIPforwardRow2) create() error {
	return createIPForwardEntry2(row)
}

// readTable method returns all table rows.
func (tab *mibIPforwardTable2) readTable() (s []MibIPforwardRow2) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of
// network interfaces, addresses, and routes.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable
func (tab *mibIPforwardTable2) free() {
	freeMibTable(tab)
}
