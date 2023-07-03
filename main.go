package main

import (
	"context"

	"github.com/k3dves/gaslight/models"
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
	proxy := New(ctx, config)

	logger.Info("Starting proxy server", config)
	proxy.Start()

}
