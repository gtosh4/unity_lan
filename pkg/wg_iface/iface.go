package wgiface

import (
	"bytes"
	"io"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/conf"
)

type BaseConfig struct {
	Name       string
	PrivateKey wgtypes.Key
	Addresses  []net.IPNet
}

var emptyKey wgtypes.Key

func (cfg *BaseConfig) EnsureKey() error {
	if !bytes.Equal(cfg.PrivateKey[:], emptyKey[:]) {
		return nil
	}

	var err error
	cfg.PrivateKey, err = wgtypes.GeneratePrivateKey()
	return err
}

func (cfg BaseConfig) ToConf() conf.Config {
	c := conf.Config{
		Name: cfg.Name,
		Interface: conf.Interface{
			PrivateKey: conf.Key(cfg.PrivateKey),
			Addresses:  make([]conf.IPCidr, len(cfg.Addresses)),
		},
	}
	for i, ipn := range cfg.Addresses {
		c.Interface.Addresses[i].IP = ipn.IP
		ones, _ := ipn.Mask.Size()
		c.Interface.Addresses[i].Cidr = uint8(ones)
	}
	return c
}

func (cfg BaseConfig) WriteTo(w io.Writer) (int64, error) {
	c := cfg.ToConf()
	content := c.ToWgQuick()
	n, err := w.Write([]byte(content))
	return int64(n), err
}
