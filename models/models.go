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

//Link is a custom type having underlying type as string.
//It is used to describe the tcp connection direction, i.e. if the link is form client->server
//we read from client and write it to server and NOT vice-versa
type Link string

var LinkClientToServer Link = "client->server"
var LinkServerToClient Link = "server->client"
