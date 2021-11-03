package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/gtosh4/unity_lan/internal/pkg/admin"
	"github.com/gtosh4/unity_lan/internal/pkg/wg"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Server struct {
	ctx Context

	router *gin.Engine
}

const port = 58105

func NewServer(ctx Context) *Server {
	srv := &Server{
		ctx: ctx,
	}
	srv.setupRouter()

	return srv
}

func (srv *Server) Context() context.Context {
	return srv.ctx
}

func (srv *Server) Log() *zap.SugaredLogger {
	return srv.ctx.SugaredLogger
}

func (srv *Server) setupRouter() {
	r := gin.New()
	r.Use(
		ginzap.RecoveryWithZap(srv.Log().Desugar(), true),
		ginzap.Ginzap(srv.Log().Desugar(), time.RFC3339, false),
	)

	admin.RegisterDebug(r)
	admin.RegisterMetricsHandler(r)

	// v1 := r.Group("/v1")

	srv.router = r
}

func (srv *Server) Start() error {
	if _, err := wg.FindDevice(srv.ctx.Wireguard); err != nil {
		return errors.Wrap(err, "could not find wg interface")
	}

	go func() {
		s := &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: srv.router,
		}
		srv.ctx.OnDoneClose(s.Close)

		err := s.ListenAndServe()
		if err != nil {
			srv.Log().Errorf("Gin error: %v", err)
		}
	}()

	return nil
}
