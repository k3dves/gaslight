package main

import "log"

func main() {

	config := &ProxyConfig{
		ServerCert: "certs/ifconfig.me+1.pem",
		Hostname:   "gaslight.local",
		ServerKey:  "certs/ifconfig.me+1-key.pem",
		ProxyPort:  "8888",
		ProxyIP:    "127.0.0.1",
	}
	proxy := New(config)

	log.Printf("Starting proxy server %+v ", config)
	proxy.Start()

}
