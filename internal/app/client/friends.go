package client

import (
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/gtosh4/unity_lan/internal/pkg/wails_store"
)

func (srv *ClientService) startFriendsStore() {
	store := wails_store.NewStore(srv.frontend.runtime, "Friends", []*discordgo.Relationship{})

	refresh := func() {
		discord := srv.Clients.Discord
		if discord == nil {
			return
		}

		guilds, err := getFriends(discord)
		if err != nil {
			srv.Warnf("Error retrieving friends: %v", err)
			return
		}

		if err := store.Set(guilds); err != nil {
			srv.Warnf("Error updating friends: %v", err)
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

func getFriends(client *discordgo.Session) (friends []*discordgo.Relationship, err error) {
	all, err := client.RelationshipsGet()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.Type == 1 {
			friends = append(friends, r)
		}
	}
	return
}
