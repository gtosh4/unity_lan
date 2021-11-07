package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	unitylanv1 "github.com/gtosh4/unity_lan/gen/proto/go/unitylan/v1"
	"github.com/gtosh4/unity_lan/internal/pkg/admin"
	"github.com/metal-stack/go-ipam"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type Server struct {
	ctx Context

	router *gin.Engine
	ipam   ipam.Ipamer

	prefix *ipam.Prefix
}

const httpPort = 58105
const grpcPubPort = 58106
const grpcPrivPort = 58107

func NewServer(ctx Context) (*Server, error) {
	srv := &Server{
		ctx:  ctx,
		ipam: ipam.New(),
	}
	var err error
	srv.prefix, err = srv.ipam.NewPrefix("10.0.0.0/8")
	if err != nil {
		return nil, err
	}
	srv.setupAPI()

	return srv, nil
}

func (srv *Server) Context() context.Context {
	return srv.ctx
}

func (srv *Server) Log() *zap.SugaredLogger {
	return srv.ctx.SugaredLogger
}

func (srv *Server) setupAPI() {
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
	go func() {
		s := &http.Server{
			Addr:    fmt.Sprintf(":%d", httpPort),
			Handler: srv.router,
		}
		srv.ctx.OnDoneClose(s.Close)

		for srv.ctx.Err() == nil {
			err := s.ListenAndServe()
			if err != nil {
				srv.Log().Errorf("Gin error: %v", err)
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		unitylanv1.RegisterUnityPublicServiceServer(grpcServer, srv)

		for srv.ctx.Err() == nil {
			addr := fmt.Sprintf(":%d", grpcPubPort)
			lis, err := net.Listen("tcp", addr)
			if err != nil {
				srv.Log().Errorf("GRPC/pub: failed to listen on %s: %v", addr, err)
				time.Sleep(time.Second)
			} else {
				grpcServer.Serve(lis)
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		unitylanv1.RegisterUnityPrivateServiceServer(grpcServer, srv)

		for srv.ctx.Err() == nil {
			addr := fmt.Sprintf(":%d", grpcPrivPort)
			lis, err := net.Listen("tcp", addr)
			if err != nil {
				srv.Log().Errorf("GRPC/priv: failed to listen on %s: %v", addr, err)
				time.Sleep(time.Second)
			} else {
				grpcServer.Serve(lis)
			}
		}
	}()

	return nil
}
