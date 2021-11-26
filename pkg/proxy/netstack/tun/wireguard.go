//go:build !linux
// +build !linux

package tun

import (
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func Open(tunName string) (stack.LinkEndpoint, error) {
	wgtun, err := tun.CreateTUN(tunName, 1500)
	if err != nil {
		return nil, err
	}

	return NewRWEndpoint(wgtun, 1500), nil
}
