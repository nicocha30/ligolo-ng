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
