//go:build !windows
// +build !windows

package tun

import (
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func Open(tunName string) (stack.LinkEndpoint, error) {
	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		return nil, err
	}

	fd, err := tun.Open(tunName)
	if err != nil {
		return nil, err
	}

	linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		return nil, err
	}
	return linkEP, nil
}
