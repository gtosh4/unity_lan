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
	srv.frontend.app = wails.CreateApp(&wails.AppConfig{
		Width:  1024,
		Height: 768,
		Title:  "Unity LAN",
		JS:     frontend.Javascript,
		CSS:    frontend.CSS,
		Colour: "#131313",
	})

	srv.frontend.app.Bind(&srv.frontend)
}

func (f *Frontend) WailsInit(runtime *wails.Runtime) error {
	f.runtime = runtime

	runtime.Events.On("wails:loaded", f.onLoad)

	f.srv.wg.startInterfacePoll()
	f.srv.startGuildsStore()
	f.srv.startFriendsStore()

	return nil
}

func (f *Frontend) onLoad(_ ...interface{}) {
	clients := f.srv.Clients

	if clients.Discord == nil {

	} else {
		f.emit("loggedIn")
	}
}

func (f *Frontend) emit(name string, data ...interface{}) {
	f.runtime.Events.Emit(name, data...)
}
