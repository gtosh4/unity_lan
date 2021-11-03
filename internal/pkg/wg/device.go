package wg

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const InterfaceName = "unity_wg0"

func FindDevice(client *wgctrl.Client) (*wgtypes.Device, error) {
	return client.Device(InterfaceName)
}
