package main

import (
	"context"
	"errors"
	"os"
	"os/signal"

	"github.com/gtosh4/unity_lan/internal/app/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var root = &cobra.Command{
	Use:  "unitylan",
	RunE: run,
}

var cfg struct {
	verbose bool
}

func main() {
	flags := root.Flags()

	flags.BoolVar(&cfg.verbose, "verbose", false, "Verbose flag")

	root.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	var zapCfg zap.Config
	if cfg.verbose {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	zapCfg.Encoding = "console"
	logger, err := zapCfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()
	log := logger.Sugar()

	wg, err := wgctrl.New()
	if err != nil {
		panic(err)
	}

	ctx := &client.Context{
		SugaredLogger: log,
		Clients: client.Clients{
			Wireguard: wg,
		},
	}

	var cancel context.CancelFunc
	ctx.Context, cancel = context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		s := <-sig
		ctx.Infof("Got signal %s, shutting down", s)
		cancel()

		s = <-sig
		ctx.Warnf("Got signal %s, exiting", s)
		os.Exit(1)
	}()

	srv := client.NewClientService(ctx)

	srv.Start()

	<-ctx.Done()

	if err := ctx.Err(); !errors.Is(context.Canceled, err) {
		return err
	}
	return nil
}
