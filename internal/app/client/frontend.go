package client

import (
	"github.com/gtosh4/unity_lan/frontend"
	"github.com/wailsapp/wails"
)

type Frontend struct {
	srv     *ClientService
	app     *wails.App
	runtime *wails.Runtime
}

func (srv *ClientService) setupApp() {
	app := wails.CreateApp(&wails.AppConfig{
		Width:  1024,
		Height: 768,
		Title:  "Unity LAN",
		JS:     frontend.Javascript,
		CSS:    frontend.CSS,
		Colour: "#131313",
	})

	srv.frontend = Frontend{
		srv: srv,
		app: app,
	}

	app.Bind(&srv.frontend)
}

func (f *Frontend) WailsInit(runtime *wails.Runtime) error {
	f.runtime = runtime

	runtime.Events.On("wails:loaded", f.onLoad)

	f.srv.startInterfacePoll()

	return nil
}

func (f *Frontend) onLoad(_ ...interface{}) {
	clients := f.srv.ctx.Clients

	if clients.Discord == nil {
		f.emit("doLogin", discordAuthConfig.AuthCodeURL(authState))
	} else {
		f.emit("loggedIn")
	}
}

func (f *Frontend) emit(name string, data ...interface{}) {
	f.runtime.Events.Emit(name, data...)
}
