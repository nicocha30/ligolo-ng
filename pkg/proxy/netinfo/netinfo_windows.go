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

package netinfo

import (
	"errors"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo/winroute"
	"golang.zx2c4.com/wintun"
	"net"
)

type Tun struct {
	idx  int
	name string
}

/*
The Wintun driver is not made for persistent interfaces.
*/
func CreateTUN(name string) error {
	return errors.New("tun should be created when starting tunnel")
}

func CanCreateTUNs() bool {
	return false
}

func (t *Tun) Destroy() error {
	adapter, err := wintun.OpenAdapter(t.name)
	if err != nil {
		return err
	}
	if err := adapter.Close(); err != nil {
		return err
	}
	return nil
}

func (t *Tun) AddRoute(network string) error {
	dstIp, err := winroute.ParseIP(network)
	if err != nil {
		return err
	}
	gwIp, err := winroute.ParseIP("0.0.0.0")
	if err != nil {
		return err
	}
	return winroute.Add(winroute.Handle{Destination: dstIp, InterfaceIndex: uint32(t.idx), Gateway: gwIp})
}

func (t *Tun) DelRoute(network string) error {

	// Find route...
	routes, err := winroute.Table()
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Destination.String() == network {
			return winroute.Delete(route)
		}
	}
	return errors.New("route not found")
}

func (t *Tun) Name() string {
	return t.name
}

func GetTunByName(name string) (Tun, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return Tun{}, err
	}
	return Tun{idx: iface.Index, name: name}, nil
}

func (t *Tun) Routes() (tapRoutes []Route) {
	routes, err := winroute.Table()
	if err != nil {
		return nil
	}
	for _, route := range routes {
		shouldAddRoute := true
		if route.InterfaceIndex != uint32(t.idx) {
			continue
		}
		if route.Destination == nil {
			continue
		}
		if !route.Destination.IP.IsGlobalUnicast() {
			continue
		}
		rt := Route{}
		rt.Dst = route.Destination.String()

		if route.Gateway != nil {
			rt.Gw = route.Gateway.String()
		}
		if route.Source != nil {
			rt.Src = route.Source.String()
		}

		// Check if IPv4 is /32 or IPv6 is /128
		var shouldCheckRoutes bool
		if route.Destination.CIDR.IP.To4() != nil { // IPv4
			mask := route.Destination.CIDR.Mask

			if mask[0] == 255 && mask[1] == 255 && mask[2] == 255 && mask[3] == 255 {
				shouldCheckRoutes = true
			}
		} else { // IPv6
			mask := route.Destination.CIDR.Mask
			ones, bits := mask.Size()
			if ones == bits {
				shouldCheckRoutes = true
			}
		}

		// Cleanup routing table
		if shouldCheckRoutes {
			for _, tRoute := range tapRoutes {
				_, ipNet, err := net.ParseCIDR(tRoute.Dst)
				if err != nil {
					continue
				}
				if ipNet.Contains(*route.Destination.IP) {
					shouldAddRoute = false
					continue
				}
			}
		}
		if shouldAddRoute {
			tapRoutes = append(tapRoutes, rt)
		}
	}
	return tapRoutes
}

func GetTunTaps() ([]Tun, error) {
	tuns, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var tuntaps []Tun
	for _, link := range tuns {
		tuntaps = append(tuntaps, Tun{idx: link.Index, name: link.Name})
	}
	return tuntaps, nil
}
