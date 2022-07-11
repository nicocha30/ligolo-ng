//go:build !linux
// +build !linux

package tun

import (
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"golang.zx2c4.com/wireguard/tun"
)

func Open(tunName string) (stack.LinkEndpoint, error) {
	wgtun, err := tun.CreateTUN(tunName, 1500)
	if err != nil {
		return nil, err
	}

	return NewRWEndpoint(wgtun, 1500), nil
}
