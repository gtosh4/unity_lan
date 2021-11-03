package server

import (
	"github.com/bwmarrin/discordgo"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type Clients struct {
	Discord   *discordgo.Session
	Wireguard *wgctrl.Client
}
