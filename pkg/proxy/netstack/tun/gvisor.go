//go:build linux

package tun

import (
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/fdbased"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/rawfile"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/tun"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"golang.org/x/sys/unix"
)

type TunInterface struct {
	LinkEP stack.LinkEndpoint
	fd     int
	name   string
}

func New(tunName string) (*TunInterface, error) {
	tunIface := TunInterface{}
	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		return nil, err
	}

	fd, err := tun.Open(tunName)
	if err != nil {
		return nil, err
	}
	tunIface.fd = fd
	tunIface.name = tunName

	linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		return nil, err
	}
	tunIface.LinkEP = linkEP

	return &tunIface, nil
}

func (t TunInterface) Name() (string, error) {
	return t.name, nil
}

func (t *TunInterface) Close() error {
	return unix.Close(t.fd)
}
