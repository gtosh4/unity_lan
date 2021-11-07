//go:build windows
// +build windows

package wgiface

import (
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

func RunInterface(cfg BaseConfig) error {
	c := cfg.ToConf()
	if err := c.Save(true); err != nil {
		return errors.Wrap(err, "could not save conf file")
	}
	path, err := c.Path()
	if err != nil {
		return errors.Wrap(err, "could not determine path")
	}

	err = tunnel.Run(path)
	return err
}
