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
