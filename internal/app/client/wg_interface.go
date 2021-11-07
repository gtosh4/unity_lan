package client

import (
	"net"
	"os"
	"time"

	"github.com/gtosh4/unity_lan/internal/pkg/wails_store"
	wgiface "github.com/gtosh4/unity_lan/pkg/wg_iface"
)

type Wireguard struct {
	srv   *ClientService
	store *wails_store.Store
}

const InterfaceName = "unity_wg0"

func (wg *Wireguard) fetchConfig() (wgiface.BaseConfig, error) {
	return wgiface.BaseConfig{
		Name: InterfaceName,
		Addresses: []net.IPNet{
			{IP: net.ParseIP("10.0.0.4"), Mask: net.IPv4Mask(255, 255, 255, 255)},
		},
	}, nil
}

func (wg *Wireguard) createDevice() error {
	cfg, err := wg.fetchConfig()
	if err != nil {
		return err
	}

	return wgiface.RunInterface(cfg)
}

func (wg *Wireguard) startInterfacePoll() {
	wg.store = wails_store.NewStore(wg.srv.frontend.runtime, "WGDevice", "no_device")

	refresh := func() {
		client := wg.srv.Clients.Wireguard
		dev, err := client.Device(InterfaceName)
		switch {
		case os.IsNotExist(err):
			wg.store.Set("creating_device")
			if err := wg.createDevice(); err != nil {
				wg.srv.Warnf("Error creating device: %v", err)
			}

		case err != nil:
			wg.srv.Warnf("Error polling for wg interface: %v", err)

		default:
			wg.store.Set("ok")
			wg.srv.Infof("Got device: %+v", dev)
		}
	}

	refresh()

	go func() {
		t := time.NewTicker(time.Minute)
		for {
			select {
			case <-wg.srv.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}
