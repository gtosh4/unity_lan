package client

import (
	"os"
	"time"

	"github.com/gtosh4/unity_lan/internal/pkg/wg"
)

func (srv *ClientService) startInterfacePoll() {
	store := srv.frontend.runtime.Store.New("WGDevice", "no_device")

	go func() {
		for {
			if srv.ctx.Err() != nil {
				return
			}

			dev, err := wg.FindDevice(srv.ctx.Wireguard)
			switch {
			case os.IsNotExist(err):
				store.Set("no_device")

			case err != nil:
				srv.Log().Warnf("Error polling for wg interface: %v", err)

			default:
				store.Set("ok")
				srv.Log().Infof("Got device: %+v", dev)
			}
			time.Sleep(time.Minute)
		}
	}()
}
