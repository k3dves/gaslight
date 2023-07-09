package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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

	data, err := os.ReadFile("config.json")
	if err != nil {
		logger.Fatal("cannot read config file")
	}
	config := new(models.ProxyConfig)
	err = json.Unmarshal(data, config)
	if err != nil {
		logger.Fatal("invalid config")
	}

	fmt.Printf("config %+v\n", config)
	//create a new proxy instance
	proxy := New(ctx, config)

	//registe hooks
	proxy.RegisterHook(models.HookTypeClientToServer, plugins.SimpleLogger)
	proxy.RegisterHook(models.HookTypeServerToClient, plugins.SimpleLogger)

	logger.Info("Starting proxy server", config)
	proxy.Start()

}
