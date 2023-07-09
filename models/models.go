package models

import (
	"context"
	"crypto/tls"
	"net"
)

type ProxyConfig struct {
	ServerCert     string `json:"server_cert"`
	ServerKey      string `json:"server_key"`
	ServerHostName string `json:"server_hostname"`
	ProxyPort      string `json:"proxy_port"`
	ProxyIP        string `json:"proxty_ip"`
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

//HookType is a custom type having underlying type as string.
//It is used to describe the tcp connection direction, i.e. if the link is form client->server
//we read from client and write it to server and NOT vice-versa
type HookType string

var HookTypeClientToServer HookType = "client->server"
var HookTypeServerToClient HookType = "server->client"

//Hook is a custom function that sits in the middle of stipped SSL or Plain HTTP connection and call a function func
// whose input is a raw byte array of captured TCP data
type Hook func(context.Context, *[]byte) error
