package client

import (
	"fmt"
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"

	"github.com/gtosh4/unity_lan/internal/pkg/admin"
)

type ClientService struct {
	*Context

	router *gin.Engine

	frontend Frontend
	auth     DiscordAuth
	wg       Wireguard
}

const port = 58104

func NewClientService(ctx *Context) *ClientService {
	srv := &ClientService{
		Context: ctx,
	}
	srv.frontend.srv = srv
	srv.auth.srv = srv
	srv.wg.srv = srv

	srv.setupApp()
	srv.setupRouter()

	return srv
}

func (srv *ClientService) setupRouter() {
	r := gin.New()
	r.Use(
		ginzap.RecoveryWithZap(srv.SugaredLogger.Desugar(), true),
		ginzap.Ginzap(srv.SugaredLogger.Desugar(), time.RFC3339, false),
	)

	admin.RegisterDebug(r)
	admin.RegisterMetricsHandler(r)

	v1 := r.Group("/v1")
	v1.GET("oauth2redirect", srv.auth.oauthRedirect)

	srv.router = r
}

func (srv *ClientService) Start() {
	go func() {
		s := http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: srv.router,
		}

		srv.OnDoneClose(s.Close)

		for srv.Context.Err() == nil {
			if err := s.ListenAndServe(); err != nil {
				srv.Errorf("Gin error: %v", err)
			}
		}
	}()

	go func() {
		for srv.Context.Err() == nil {
			if err := srv.frontend.app.Run(); err != nil {
				srv.Errorf("Wails error: %v", err)
			}
		}
	}()

	go func() {
		if err := srv.auth.InitFromStore(); err != nil {
			srv.Warnf("Error auth init from store: %v", err)
		}
		for srv.Context.Err() == nil {
			if srv.Clients.Discord == nil {
				if err := srv.auth.OpenAuthPage(); err != nil {
					srv.Warnf("Error opening auth page: %v", err)
					time.Sleep(30 * time.Second)
				} else {
					return
				}
			}
		}
	}()
}
