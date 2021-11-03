package server

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

type Context struct {
	context.Context
	*zap.SugaredLogger
	Clients

	onDone    chan func()
	drainDone sync.Once
}

func (ctx *Context) OnDone(f func()) {
	ctx.drainDone.Do(func() {
		ctx.onDone = make(chan func(), 10000)
		go func() {
			<-ctx.Done()
			close(ctx.onDone)
			for d := range ctx.onDone {
				d()
			}
		}()
	})

	if ctx.Err() != nil {
		f()
		return
	}

	select {
	case ctx.onDone <- f:
	default:
		ctx.Warn("could not add onDone callback to channel")
	}
}

func (ctx *Context) OnDoneClose(close func() error) {
	ctx.OnDone(func() {
		if err := close(); err != nil {
			ctx.Warnf("Error closing: %v", err)
		}
	})
}
