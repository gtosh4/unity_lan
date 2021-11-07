package client

import (
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gtosh4/unity_lan/internal/pkg/wails_store"
)

func (srv *ClientService) startGuildsStore() {
	store := wails_store.NewStore(srv.frontend.runtime, "Guilds", []*discordgo.UserGuild{})

	refresh := func() {
		discord := srv.Clients.Discord
		if discord == nil {
			return
		}

		guilds, err := getGuilds(discord)
		if err != nil {
			srv.Warnf("Error retrieving guilds: %v", err)
			return
		}

		if err := store.Set(guilds); err != nil {
			srv.Warnf("Error updating guilds store: %v", err)
			return
		}
	}

	refresh()

	go func() {
		t := time.NewTicker(time.Minute)
		for {
			select {
			case <-srv.Done():
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
