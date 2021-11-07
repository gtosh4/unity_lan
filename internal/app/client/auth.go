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
	"github.com/gtosh4/unity_lan/internal/pkg/wails_store"
	"github.com/gtosh4/unity_lan/pkg/credstore"
	"github.com/gtosh4/unity_lan/pkg/openurl"
	"github.com/gtosh4/unity_lan/secrets"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var Discordtoken = auth.TokenSecret{
	Secret: credstore.Secret{
		Name: "unitylan:auth_token",
	},
}

var discordAuthConfig = &oauth2.Config{
	ClientID:     "905550991955460126",
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
		"rpc",
		"rpc.voice.read",
		// "relationships.read",
	},
}

type DiscordAuth struct {
	srv *ClientService

	oath2State string
	store      *wails_store.Store
}

func (auth *DiscordAuth) updateState(user *discordgo.User) {
	if auth.store == nil {
		if rt := auth.srv.frontend.runtime; rt != nil {
			auth.store = wails_store.NewStore(rt, "LoginState", user)
			auth.store.Set(user)
			return
		} else {
			auth.srv.Warnf("Tried to update state (to %+v) before runtime ready", user)
		}
	} else {
		auth.store.Set(user)
	}
}

func (auth *DiscordAuth) oauthRedirect(c *gin.Context) {
	srv := auth.srv
	log := srv.SugaredLogger.With(zap.String("method", c.Request.Method), zap.String("remote", c.Request.RemoteAddr))

	code := c.Query("code")
	state := c.Query("state")

	log.Infof("code: '%s' // state: '%s' (expected: '%s')", code, state, auth.oath2State)

	retryRedirect := func() {
		c.Redirect(http.StatusTemporaryRedirect, auth.AuthCodeURL())
	}

	errCode := c.Query("error")
	errDesc := c.Query("error_description")

	if errCode != "" {
		log.Warnf("Got error from discord API: %s: %s", errCode, errDesc)
		retryRedirect()
		auth.updateState(nil)
		return
	}

	if code == "" {
		log.Warnf("No oauth2 code")
		retryRedirect()
		auth.updateState(nil)
		return
	}

	if state != auth.oath2State {
		log.Warnf("State param (%s) doesn't match expected (%s)", state, auth.oath2State)
		retryRedirect()
		auth.updateState(nil)
		return
	}

	token, err := discordAuthConfig.Exchange(srv.Context, code)
	if err != nil {
		log.Warnf("Could not exchange code for token: %v", err)
		retryRedirect()
		auth.updateState(nil)
		return
	}
	Discordtoken.Token = *token

	if err := auth.DiscordClientInit(); err != nil {
		log.Warnf("Could not setup discord client: %v", err)
		retryRedirect()
		auth.updateState(nil)
		return
	}

	if _, err := c.Writer.Write(frontend.AuthSuccess); err != nil {
		log.Warnf("Error returning auth success page: %v", err)
	}
}

func (auth *DiscordAuth) AuthCodeURL() string {
	if auth.oath2State == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(99999))
		if err != nil {
			n = big.NewInt(90813)
		}
		auth.oath2State = n.String()
	}
	u := discordAuthConfig.AuthCodeURL(auth.oath2State)
	auth.srv.Infof("opening %s", u)
	return u
}

func (auth *DiscordAuth) OpenAuthPage() error {
	return openurl.Open(auth.srv.Context, auth.AuthCodeURL())
}

func (auth *DiscordAuth) InitFromStore() error {
	if err := Discordtoken.Load(); err != nil {
		return errors.Wrap(err, "Error loading discord token from credential store")
	}
	if Discordtoken.Token.AccessToken == "" {
		// No error, just not logged in
		return nil
	}

	if err := auth.DiscordClientInit(); err != nil {
		return errors.Wrap(err, "Got error setting up discord client with initial token")
	} else {
		auth.srv.Info("Succesfully created discord client from cred store token")
	}
	return nil
}

func (auth *DiscordAuth) DiscordClientInit() error {
	if err := Discordtoken.Save(); err != nil {
		return err
	}

	client, err := discordgo.New(Discordtoken.Token.Type() + " " + Discordtoken.Token.AccessToken)
	if err != nil {
		return err
	}

	user, err := client.User("@me")
	if err != nil {
		return err
	}

	auth.updateState(user)

	// Swap in the oauth2 token auto-refreshing client
	discordCtx := context.WithValue(auth.srv.Context, oauth2.HTTPClient, client.Client)
	client.Client = discordAuthConfig.Client(discordCtx, &Discordtoken.Token)

	auth.srv.Clients.Discord = client

	return nil
}
