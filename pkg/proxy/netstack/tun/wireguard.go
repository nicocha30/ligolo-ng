//go:build !linux
// +build !linux

package tun

import (
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netinfo"
	"golang.zx2c4.com/wireguard/tun"
)

type TunInterface struct {
	LinkEP *RWEndpoint
	device tun.Device
}

func New(tunName string) (*TunInterface, error) {
	tunIface := TunInterface{}
	//Do we need to remove already existent interfaces? (BSD systems)
	if !AllowExisting() {
		// Check if interface exist
		iface, err := netinfo.GetTunByName(tunName)
		if err == nil {
			// Destroy it
			if err = iface.Destroy(); err != nil {
				return nil, err
			}
		}
	}
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
