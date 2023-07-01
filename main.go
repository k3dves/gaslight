package main

import "log"

func main() {

	config := &ProxyConfig{
		ServerCert:           "certs/server.crt",
		Hostname:             "gaslight.local",
		ServerKey:            "certs/server.key",
		InputPort:            "8888",
		ReturnPort:           "4444",
		InterceptorPort:      "5555",
		InputBindIP:          "127.0.0.1",
		InterceptorConnectIP: "127.0.0.1",
		ReturnBindIP:         "127.0.0.1",
		OutputConnectIP:      "127.0.0.1",
	}
	proxy := New(config)

	log.Printf("Starting proxy server %+v ", config)
	proxy.Start()

}
