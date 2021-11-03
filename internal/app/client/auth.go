package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	"github.com/gtosh4/unity_lan/frontend"
	"github.com/gtosh4/unity_lan/internal/pkg/auth"
	"github.com/gtosh4/unity_lan/pkg/credstore"
	"github.com/gtosh4/unity_lan/secrets"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var Discordtoken = auth.TokenSecret{
	Secret: credstore.Secret{
		Name: "unitylan:auth_token",
	},
}

var discordAuthConfig = &oauth2.Config{
	ClientID:     "902361055957770261",
	ClientSecret: strings.TrimSpace(secrets.DiscordClientSecret),
	Endpoint: oauth2.Endpoint{
		AuthURL:   "https://discord.com/api/oauth2/authorize",
		TokenURL:  "https://discord.com/api/oauth2/token",
		AuthStyle: oauth2.AuthStyleInParams,
	},
	RedirectURL: fmt.Sprintf("http://localhost:%d/v1/oauth2redirect", port),
	Scopes: []string{
		"identify",
		"guilds",
		// "rpc",
		// "rpc.voice.read",
	},
}

var authState string

func init() {
	n, err := rand.Int(rand.Reader, big.NewInt(99999))
	if err != nil {
		n = big.NewInt(90813)
	}
	authState = n.String()
}

func (srv *ClientService) oauthRedirect(c *gin.Context) {
	log := srv.Log().With(zap.String("method", c.Request.Method), zap.String("remote", c.Request.RemoteAddr))

	code := c.Query("code")
	state := c.Query("state")

	log.Infof("code: '%s' // state: '%s' (expected: '%s')", code, state, authState)

	if code == "" {
		log.Warnf("No oauth2 code")
		c.AbortWithStatus(http.StatusBadRequest)
		srv.frontend.emit("loginFailed")
		return
	}

	if state != authState {
		log.Warnf("State param (%s) doesn't match expected (%s)", state, authState)
		c.AbortWithStatus(http.StatusBadRequest)
		srv.frontend.emit("loginFailed")
		return
	}

	// tmp := &http.Client{
	// 	Transport: &debug.LogRoundTrip{Base: http.DefaultTransport, Log: srv.Log()},
	// }
	// ctx := context.WithValue(srv.ctx, oauth2.HTTPClient, tmp)
	token, err := discordAuthConfig.Exchange(srv.ctx, code)
	if err != nil {
		log.Warnf("Could not exchange code for token: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		srv.frontend.emit("loginFailed")
		return
	}
	Discordtoken.Token = *token

	if err := srv.DiscordClientInit(); err != nil {
		log.Warnf("Could not setup discord client: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		srv.frontend.emit("loginFailed")
		return
	}

	srv.frontend.emit("loggedIn")

	if _, err := c.Writer.Write(frontend.AuthSuccess); err != nil {
		log.Warnf("Error returning auth success page: %v", err)
	}
}

func (srv *ClientService) DiscordClientInit() error {
	if err := Discordtoken.Save(); err != nil {
		return err
	}

	client, err := discordgo.New(Discordtoken.Token.Type() + " " + Discordtoken.Token.AccessToken)
	if err != nil {
		return err
	}

	// Swap in the oauth2 token auto-refreshing client
	discordCtx := context.WithValue(srv.ctx, oauth2.HTTPClient, client.Client)
	client.Client = discordAuthConfig.Client(discordCtx, &Discordtoken.Token)

	srv.ctx.Clients.Discord = client

	srv.startGuildsStore()

	return nil
}
