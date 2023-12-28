//go:build !linux
// +build !linux

package tun

import (
	"golang.zx2c4.com/wireguard/tun"
)

type TunInterface struct {
	LinkEP *RWEndpoint
	device tun.Device
}

func New(tunName string) (*TunInterface, error) {
	tunIface := TunInterface{}
	wgtun, err := tun.CreateTUN(tunName, 1500)
	if err != nil {
		return nil, err
	}
	tunIface.LinkEP = NewRWEndpoint(wgtun, 1500)
	tunIface.device = wgtun
	return &tunIface, nil
}

func (i TunInterface) Name() (string, error) {
	return i.device.Name()
}

func (i TunInterface) Close() error {
	return i.device.Close()
}
