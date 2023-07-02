package models

import (
	"crypto/tls"
	"net"
)

type ProxyConfig struct {
	ServerCert     string
	ServerKey      string
	ServerHostName string
	ProxyPort      string
	ProxyIP        string
}

// Internal connInfo struct which get updated based on incoming connection
type ConnInfo struct {
	Conn         net.Conn
	TlsConn      *tls.Conn
	Is_https     bool
	Hostname     string
	Hostip       string
	Hostport     string
	FirstRequest []byte
}
