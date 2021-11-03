package admin

import (
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/chenjiandongx/ginprom"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/trace"
)

func isLocalIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func localOnlyMiddleware(c *gin.Context) {
	if !isLocalIP(c.ClientIP()) {
		c.AbortWithStatus(http.StatusNotFound)
	}
}

func RegisterMetricsHandler(r *gin.Engine) {
	r.GET("/metrics", localOnlyMiddleware, ginprom.PromHandler(promhttp.Handler()))
}

func RegisterDebug(r *gin.Engine) {
	debug := r.Group("/debug")
	debug.Use(localOnlyMiddleware)

	pprofRouter := debug.Group("/pprof")
	pprofRouter.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	pprofRouter.GET("/profile", gin.WrapF(pprof.Profile))
	pprofRouter.GET("/symbol", gin.WrapF(pprof.Symbol))
	pprofRouter.GET("/trace", gin.WrapF(pprof.Trace))
	pprofRouter.GET("/", gin.WrapF(pprof.Index))
	pprofRouter.GET("", gin.WrapF(pprof.Index))

	traceRouter := debug.Group("/trace")
	traceRouter.GET("/requests", gin.WrapF(trace.Traces))
	traceRouter.GET("/events", gin.WrapF(trace.Events))
}
