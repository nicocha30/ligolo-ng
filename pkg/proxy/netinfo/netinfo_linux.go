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

//go:build linux

package netinfo

import (
	"encoding/json"
	"github.com/vishvananda/netlink"
	"net"
)

type Tun struct {
	tap netlink.Link
}

func CreateTUN(name string) error {
	tun := &Tun{}
	la := netlink.NewLinkAttrs()
	la.Name = name
	tun.tap = &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TUN,
	}
	if err := netlink.LinkAdd(tun.tap); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(tun.tap); err != nil {
		return err
	}
	return nil
}

func CanCreateTUNs() bool {
	return true
}

func (t *Tun) MarshalJSON() ([]byte, error) {
	return json.Marshal(TunInfo{Name: t.tap.Attrs().Name, Index: t.tap.Attrs().Index, Routes: t.Routes()})
}

func (t *Tun) AddRoute(network string) error {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: t.tap.Attrs().Index,
		Dst:       ipnet,
	}); err != nil {
		return err
	}
	return nil
}

func (t *Tun) DelRoute(network string) error {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(&netlink.Route{
		LinkIndex: t.tap.Attrs().Index,
		Dst:       ipnet,
	}); err != nil {
		return err
	}
	return nil
}

func (t *Tun) Destroy() error {
	return netlink.LinkDel(t.tap)
}

func (t *Tun) Name() string {
	return t.tap.Attrs().Name
}

func GetTunByName(name string) (Tun, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return Tun{}, err
	}
	return Tun{
		tap: link,
	}, nil
}

func (t *Tun) Routes() (tapRoutes []Route) {
	routes, err := netlink.RouteList(t.tap, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	for _, route := range routes {
		tapRoutes = append(tapRoutes, Route{
			Dst: route.Dst.String(),
			Src: route.Src.String(),
			Gw:  route.Gw.String(),
		})
	}
	return tapRoutes
}

func GetTunTaps() ([]Tun, error) {
	tuns, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var tuntaps []Tun
	for _, link := range tuns {
		if link.Type() == "tuntap" {
			tuntaps = append(tuntaps, Tun{
				tap: link,
			})
		}
	}
	return tuntaps, nil
}
