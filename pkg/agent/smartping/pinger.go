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

package smartping

import (
	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"runtime"
	"time"
)

// TryResolve tries to discover if the remote host is up using ICMP
func TryResolve(address string) bool {
	// Always return true for localhost
	magicNet := net.IPNet{
		IP:   net.IPv4(240, 0, 0, 0),
		Mask: []byte{0xf0, 0x00, 0x00, 0x00},
	}

	if magicNet.Contains(net.ParseIP(address)) {
		logrus.Debug("MagicIP Ping detected, returning true")
		// Magic IP detected
		return true
	}
	methods := []func(string) (bool, error){
		RawPinger,
		CommandPinger,
	}
	for _, method := range methods {
		if result, err := method(address); err == nil {
			return result
		}
	}
	// Everything failed...
	return false
}

// RawPinger use ICMP sockets to discover if a host is up. This could require administrative permissions on some hosts
func RawPinger(target string) (bool, error) {
	pinger, err := ping.NewPinger(target)
	if err != nil {
		return false, err
	}
	pinger.Count = 1
	pinger.Timeout = 4 * time.Second // NMAP default timeout ?
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}
	err = pinger.Run()
	if err != nil {
		return false, err
	}

	return pinger.PacketsRecv != 0, nil
}

// CommandPinger uses the internal ping command (dirty), but should not require privileges
func CommandPinger(target string) (bool, error) {
	countArg := "-c"
	waitArg := "-W"
	waitTime := "3"
	if runtime.GOOS == "windows" {
		countArg = "/n"
		waitArg = "/w"
		waitTime = "3000"
	}

	cmd := exec.Command("ping", countArg, "1", waitArg, waitTime, target)
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return true, nil
}
