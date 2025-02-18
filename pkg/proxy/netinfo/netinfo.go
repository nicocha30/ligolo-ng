package netinfo

import (
	"errors"
	"net"
)

type Route struct {
	Dst string
	Src string
	Gw  string
}

// Used by Ligolo-API
type TunInfo struct {
	Index  int
	Name   string
	Routes []Route
}

func GetTunByRoute(route string) (Tun, error) {
	tuns, err := GetTunTaps()
	if err != nil {
		return Tun{}, err
	}
	for _, tun := range tuns {
		for _, rt := range tun.Routes() {
			if rt.Dst == route {
				return tun, nil
			}
		}
	}
	return Tun{}, errors.New("could not find interface belonging to route")
}

func InterfaceExist(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}
