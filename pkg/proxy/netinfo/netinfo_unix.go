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

//go:build darwin || openbsd || freebsd

package netinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type Tun struct {
	name string
}

func CreateTUN(name string) error {
	return errors.New("tun should be created when starting tunnel")
}

func CanCreateTUNs() bool {
	return false
}

func (t *Tun) MarshalJSON() ([]byte, error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, err
	}
	return json.Marshal(TunInfo{Name: t.name, Index: iface.Index, Routes: t.Routes()})
}

func (t *Tun) Destroy() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0) // unix.SOCK_CLOEXEC?
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr [32]byte
	copy(ifr[:], t.name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCIFDESTROY), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return fmt.Errorf("failed to destroy interface %s: %w", t.name, errno)
	}

	return nil
}

func toRouteAddr(ip net.IP) (addr route.Addr) {
	if ip4 := ip.To4(); ip4 != nil {
		dst := route.Inet4Addr{}
		copy(dst.IP[:], ip4)
		addr = &dst
	} else {
		dst := route.Inet6Addr{}
		copy(dst.IP[:], ip)
		addr = &dst
	}
	return addr
}

func toRouteMask(mask net.IPMask) (addr route.Addr) {
	if _, bits := mask.Size(); bits == 32 {
		dst := route.Inet4Addr{}
		copy(dst.IP[:], mask)
		addr = &dst
	} else {
		dst := route.Inet6Addr{}
		copy(dst.IP[:], mask)
		addr = &dst
	}
	return addr
}

func (t *Tun) getNetInterface() (*net.Interface, error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, err
	}
	return iface, nil
}

func (t *Tun) AddRoute(network string) error {
	return t.unixUpdateRoute(unix.RTM_ADD, network)
}

func (t *Tun) DelRoute(network string) error {
	return t.unixUpdateRoute(unix.RTM_DELETE, network)
}

func (t *Tun) unixUpdateRoute(action int, network string) error {
	ip, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	ligoloIface, err := t.getNetInterface()
	if err != nil {
		return err
	}

	rtmsg := route.RouteMessage{
		Version: unix.RTM_VERSION,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Type:    action,
		Flags:   unix.RTF_UP | unix.RTF_STATIC,
		Addrs: []route.Addr{
			unix.RTAX_DST: toRouteAddr(ip),
			unix.RTAX_GATEWAY: &route.LinkAddr{
				Index: ligoloIface.Index,
				Name:  ligoloIface.Name,
				Addr:  ligoloIface.HardwareAddr,
			},
			unix.RTAX_NETMASK: toRouteMask(cidr.Mask),
		},
	}
	s, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	buf, err := rtmsg.Marshal()
	if err != nil {
		return err
	}

	_, err = syscall.Write(s, buf)
	if err != nil {
		return err
	}
	return nil
}

func (t *Tun) Name() string {
	return t.name
}

func GetTunByName(name string) (Tun, error) {
	_, err := net.InterfaceByName(name)
	if err != nil {
		return Tun{}, err
	}

	return Tun{name: name}, nil
}

func (t *Tun) Routes() (routes []Route) {

	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}

	ifaces, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		routem := m.(*route.RouteMessage)
		if routem.Flags&unix.RTF_UP == 0 {
			continue
		}

		dst, gw, mask := routem.Addrs[unix.RTAX_DST], routem.Addrs[unix.RTAX_GATEWAY], routem.Addrs[unix.RTAX_NETMASK]
		if gwtun, ok := gw.(*route.LinkAddr); !ok || gwtun.Index != ifaces.Index {
			continue
		}
		switch dstIP := dst.(type) {
		case *route.Inet4Addr:
			maskip, ok := mask.(*route.Inet4Addr)
			if !ok {
				maskip = &route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}}
			}

			dstIpNet := net.IPNet{dstIP.IP[:], maskip.IP[:]}

			target := Route{
				Dst: dstIpNet.String(),
				Src: "",
				Gw:  "",
			}
			routes = append(routes, target)
		case *route.Inet6Addr:
			maskip, ok := mask.(*route.Inet6Addr)
			if !ok {
				maskip = &route.Inet6Addr{IP: [16]byte(net.IPv6unspecified)}
			}
			dstIpNet := &net.IPNet{dstIP.IP[:], maskip.IP[:]}
			target := Route{
				Dst: dstIpNet.String(),
				Src: "",
				Gw:  "",
			}
			routes = append(routes, target)
		}
	}

	return
}

func GetTunTaps() ([]Tun, error) {
	tuns, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var tuntaps []Tun
	for _, link := range tuns {
		tuntaps = append(tuntaps, Tun{name: link.Name})
	}
	return tuntaps, nil
}
