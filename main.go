package main

import (
	"log"

	"github.com/k3dves/gaslight/models"
)

func main() {

	config := &models.ProxyConfig{
		ServerCert:     "certs/ifconfig.me+1.pem",
		ServerHostName: "gaslight.local",
		ServerKey:      "certs/ifconfig.me+1-key.pem",
		ProxyPort:      "8888",
		ProxyIP:        "127.0.0.1",
	}
	proxy := New(config)

	log.Printf("Starting proxy server %+v ", config)
	proxy.Start()

}
