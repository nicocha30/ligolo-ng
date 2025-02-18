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

package winroute

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
)

var (
	// client is the route operations client.
	client routeOperations
)

type IPAddr struct {
	IP   *net.IP
	CIDR *net.IPNet
}

func (i *IPAddr) String() string {
	if i.CIDR != nil {
		return i.CIDR.String()
	}
	if i.IP != nil {
		return i.IP.String()
	}
	return "<nil>"
}

func ParseIP(ip string) (*IPAddr, error) {
	if ip == "" {
		return nil, errors.New("empty address")
	}

	ipAddress, ipNet, err := net.ParseCIDR(ip)
	if err == nil {
		return &IPAddr{&ipAddress, ipNet}, nil
	}

	ipAddress = net.ParseIP(ip)
	if ipAddress == nil {
		return nil, fmt.Errorf("failed to parse IP address: %s", ip)
	}

	return &IPAddr{&ipAddress, nil}, nil
}

// Handle represents a network route.
type Handle struct {
	// Destination is the destination of the route.
	Destination *IPAddr
	// Gateway is the gateway of the route.
	Gateway *IPAddr
	// InterfaceIndex is the interface index of the route.
	InterfaceIndex uint32
	// InterfaceName is the name of the interface the route should be added to.
	// It's only relevant for linux backend implementation.
	InterfaceName string
	// Metric is the metric of the route.
	Metric uint32
	// Type is the type of the route. On linux systems it's the type of the route
	// (e.g. local, remote, etc). It's only relevant for linux backend
	// implementation.
	Type string
	// Table is the table of the route. It's only relevant for linux backend
	// implementation.
	Table string
	// Persistent indicates whether the route is persistent. It's mostly relevant
	// for windows backend implementation.
	Persistent bool
	// Proto is the proto of the route. It's only relevant for linux backend
	// implementation.
	Proto string
	// Source is the source of the route. It's only relevant for linux backend
	// implementation.
	Source *IPAddr
	// Scope is the scope of the route. It's only relevant for linux backend
	// implementation.
	Scope string
}

// routeOperations is the interface for a route backend.
type routeOperations interface {
	// Add adds a route to the system.
	Add(route Handle) error
	// Delete deletes a route from the system.
	Delete(route Handle) error
	// Table returns the route table.
	Table() ([]Handle, error)
}

// Add adds a route to the system.
func Add(route Handle) error {
	return client.Add(route)
}

// Delete deletes a route from the system.
func Delete(route Handle) error {
	return client.Delete(route)
}

// Table returns the route table.
func Table() ([]Handle, error) {
	return client.Table()
}

// windowsClient is the windows implementation of the routeOperations interface.
type windowsClient struct{}

// init initializes the windows route client.
func init() {
	client = &windowsClient{}
}

// toWindows converts a Route to a window's MibIPforwardRow2.
func (route Handle) toWindows() (MibIPforwardRow2, error) {
	dest := IPAddressPrefix{}

	prefix, err := netip.ParsePrefix(route.Destination.String())
	if err != nil {
		return MibIPforwardRow2{}, fmt.Errorf("failed to get destination prefix: %w", err)
	}

	if err := dest.SetPrefix(prefix); err != nil {
		return MibIPforwardRow2{}, fmt.Errorf("failed to set destination prefix: %w", err)
	}

	gateway := RawSockaddrInet{}

	gatewayAddr, err := netip.ParseAddr(route.Gateway.String())
	if err != nil {
		return MibIPforwardRow2{}, fmt.Errorf("failed to parse gateway address: %w", err)
	}

	if err := gateway.SetAddr(gatewayAddr); err != nil {
		return MibIPforwardRow2{}, fmt.Errorf("failed to set gateway: %w", err)
	}

	return MibIPforwardRow2{
		DestinationPrefix: dest,
		NextHop:           gateway,
		Metric:            route.Metric,
		InterfaceIndex:    route.InterfaceIndex,
	}, nil
}

// Delete deletes a route from the route table.
func (wc *windowsClient) Delete(route Handle) error {
	winRoute, err := route.toWindows()
	if err != nil {
		return fmt.Errorf("failed to convert route to windows: %w", err)
	}

	if err := winRoute.delete(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

// Add adds a route to the route table.
func (wc *windowsClient) Add(route Handle) error {
	winRoute, err := route.toWindows()
	if err != nil {
		return fmt.Errorf("failed to convert route to windows: %w", err)
	}

	if err := winRoute.create(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

// Table returns the route table.
func (wc *windowsClient) Table() ([]Handle, error) {
	table, err := getIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("failed to get route table: %w", err)
	}

	var res []Handle

	for _, route := range table {
		destAddr, err := route.DestinationPrefix.RawPrefix.Addr()
		if err != nil {
			return nil, fmt.Errorf("failed to get destination address: %w", err)
		}

		// Ligolo-ng: parse correct prefix len
		destIPAddr, err := ParseIP(fmt.Sprintf("%s/%d", destAddr.String(), route.DestinationPrefix.PrefixLength))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination address: %w", err)
		}

		gateway, err := route.NextHop.Addr()
		if err != nil {
			return nil, fmt.Errorf("failed to get gateway address: %w", err)
		}

		gatewayIPAddr, err := ParseIP(gateway.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse gateway address: %w", err)
		}

		res = append(res, Handle{
			Destination:    destIPAddr,
			Gateway:        gatewayIPAddr,
			Metric:         route.Metric,
			InterfaceIndex: route.InterfaceIndex,
		})
	}

	return res, nil
}
