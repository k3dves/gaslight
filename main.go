package main

import (
	"context"

	"github.com/k3dves/gaslight/models"
	"github.com/k3dves/gaslight/plugins"
	"go.uber.org/zap"
)

func main() {
	//Logger affecting performance?? Avoid sugar logger
	zlog := zap.Must(zap.NewProduction())
	logger := zlog.Sugar()
	defer logger.Sync()

	ctx := context.WithValue(context.Background(), "logger", logger)

	config := &models.ProxyConfig{
		ServerCert:     "certs/ifconfig.me+1.pem",
		ServerHostName: "gaslight.local",
		ServerKey:      "certs/ifconfig.me+1-key.pem",
		ProxyPort:      "8888",
		ProxyIP:        "127.0.0.1",
	}
	//create a new proxy instance
	proxy := New(ctx, config)

	//registe hooks
	proxy.RegisterHook(models.HookTypeClientToServer, plugins.SimpleLogger)
	proxy.RegisterHook(models.HookTypeServerToClient, plugins.SimpleLogger)

	logger.Info("Starting proxy server", config)
	proxy.Start()

}
