package client

import (
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/wailsapp/wails/runtime"
)

func (srv *ClientService) startGuildsStore() {
	var store *runtime.Store

	refresh := func() {
		if store == nil {
			if srv.frontend.runtime != nil {
				srv.frontend.runtime.Store.New("Guilds", []*discordgo.UserGuild{})
			} else {
				return
			}
		}
		guilds, err := getGuilds(srv.ctx.Discord)
		if err != nil {
			srv.Log().Warnf("Error retrieving guilds: %v", err)
			return
		}
		if guilds == nil {
			guilds = []*discordgo.UserGuild{}
		}

		if err := store.Set(guilds); err != nil {
			srv.Log().Warnf("Error updating guilds store: %v", err)
			return
		}
	}

	go func() {
		t := time.NewTicker(time.Minute)
		for {
			select {
			case <-srv.ctx.Done():
				return

			case <-t.C:
				refresh()
			}
		}
	}()
}

func getGuilds(client *discordgo.Session) (guilds []*discordgo.UserGuild, err error) {
	var lastId string
	const pageSize = 20
	for {
		page, pageErr := client.UserGuilds(pageSize, "", lastId)
		if pageErr != nil {
			return nil, pageErr
		}
		if len(page) == 0 {
			return
		}
		guilds = append(guilds, page...)
		if len(page) < pageSize {
			return
		}
		lastId = page[len(page)-1].ID
	}
}
