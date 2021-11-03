package secrets

import (
	_ "embed"
)

//go:embed discord_client
var DiscordClientSecret string
