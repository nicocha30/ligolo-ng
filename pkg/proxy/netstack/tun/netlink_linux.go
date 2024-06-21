//go:build linux

package tun

import (
	"errors"
	"github.com/vishvananda/netlink"
	"net"
)

type Tun struct {
	Tap netlink.Link
}

func CreateTUN(name string) error {
	tun := &Tun{}
	la := netlink.NewLinkAttrs()
	la.Name = name
	tun.Tap = &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TUN,
	}
	if err := netlink.LinkAdd(tun.Tap); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(tun.Tap); err != nil {
		return err
	}
	return nil
}

func (t *Tun) AddRoute(network string) error {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: t.Tap.Attrs().Index,
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
		LinkIndex: t.Tap.Attrs().Index,
		Dst:       ipnet,
	}); err != nil {
		return err
	}
	return nil
}

func (t *Tun) Destroy() error {
	return netlink.LinkDel(t.Tap)
}

func (t *Tun) Name() string {
	return t.Tap.Attrs().Name
}

func GetTunByName(name string) (Tun, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return Tun{}, err
	}
	return Tun{
		Tap: link,
	}, nil
}

func GetTunByRoute(route string) (Tun, error) {
	tuns, err := GetTunTaps()
	if err != nil {
		return Tun{}, err
	}
	for _, tun := range tuns {
		if _, ok := tun.Routes()[route]; ok {
			return tun, nil
		}
	}
	return Tun{}, errors.New("could not find interface belonging to route")
}

func (t *Tun) Routes() map[string]netlink.Route {
	routes, err := netlink.RouteList(t.Tap, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	tapRoutes := make(map[string]netlink.Route)
	for _, route := range routes {
		tapRoutes[route.Dst.String()] = route
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
				Tap: link,
			})
		}
	}
	return tuntaps, nil
}
