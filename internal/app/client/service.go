package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gtosh4/unity_lan/internal/pkg/admin"
)

type ClientService struct {
	ctx Context

	router   *gin.Engine
	frontend Frontend
}

const port = 58104

func NewClientService(ctx Context) *ClientService {
	srv := &ClientService{
		ctx: ctx,
	}
	srv.setupApp()
	srv.setupRouter()

	return srv
}

func (srv *ClientService) Context() context.Context {
	return srv.ctx
}

func (srv *ClientService) Log() *zap.SugaredLogger {
	return srv.ctx.SugaredLogger
}

func (srv *ClientService) setupRouter() {
	r := gin.New()
	r.Use(
		ginzap.RecoveryWithZap(srv.Log().Desugar(), true),
		ginzap.Ginzap(srv.Log().Desugar(), time.RFC3339, false),
	)

	admin.RegisterDebug(r)
	admin.RegisterMetricsHandler(r)

	v1 := r.Group("/v1")
	v1.GET("oauth2redirect", srv.oauthRedirect)

	srv.router = r
}

func (srv *ClientService) Start() {
	go func() {
		s := http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: srv.router,
		}

		srv.ctx.OnDoneClose(s.Close)

		for srv.ctx.Err() == nil {
			if err := s.ListenAndServe(); err != nil {
				srv.Log().Errorf("Gin error: %v", err)
			}
		}
	}()

	go func() {
		for srv.ctx.Err() == nil {
			if err := srv.frontend.app.Run(); err != nil {
				srv.Log().Errorf("Wails error: %v", err)
			}
		}
	}()
}
