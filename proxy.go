package main

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	"github.com/k3dves/gaslight/helpers"
	"github.com/k3dves/gaslight/models"
	"go.uber.org/zap"
)

type Proxy struct {
	ctx context.Context
	cfg *models.ProxyConfig
}

func New(ctx context.Context, cfg *models.ProxyConfig) *Proxy {
	return &Proxy{ctx: ctx, cfg: cfg}
}

func (p *Proxy) Start() {
	//get logger from context
	log := p.ctx.Value("logger").(*zap.SugaredLogger)
	// Get the SSL certificate and private key.
	// TODO: generate certs on the fly
	cer, err := tls.LoadX509KeyPair(p.cfg.ServerCert, p.cfg.ServerKey)
	if err != nil {
		log.Error("Error loading certs.", "err", err)
		return
	}
	log.Info("Loaded certificates")

	// Setup the TLS configuration.
	TLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
		ServerName:   p.cfg.ServerHostName,
	}

	// Listen on the input port.
	ln, err := net.Listen("tcp", p.cfg.ProxyIP+":"+p.cfg.ProxyPort)
	if err != nil {
		log.Error("Error starting listener", "err", err)
		return
	}
	defer ln.Close()

	log.Info("Stared Proxy Listener", "IP", p.cfg.ProxyIP, "PORT", p.cfg.ProxyPort)
	for {
		log.Debug("Waiting for incoming connections")
		conn, err := ln.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		//initalise a new connInfo struct for this conn
		connObj := &models.ConnInfo{Conn: conn}
		//HandleFirstRequest updates connObj is_https
		hostString, err := helpers.HandleFirstRequest(log, connObj)
		if err != nil {
			log.Warn("invalid first request ", "err ", err)
			conn.Close()
			continue
		}
		hostname, hostip, port, _ := helpers.ResolveHost(log, hostString, connObj.Is_https)
		//update the connObj
		connObj.Hostip = hostip
		connObj.Hostport = port
		connObj.Hostname = hostname

		if strings.HasSuffix(hostname, "ifconfig.me") && connObj.Is_https {
			tlsConn := tls.Server(conn, TLSConfig)
			connObj.TlsConn = tlsConn
			go handleNewConnection(p.ctx, connObj, p.cfg)

		} else {
			go handleNewConnectionTransparent(p.ctx, connObj, p.cfg)
		}
	}

}

func handleNewConnectionTransparent(ctx context.Context, connObj *models.ConnInfo, cfg *models.ProxyConfig) {
	defer connObj.Conn.Close()
	log := ctx.Value("logger").(*zap.SugaredLogger)
	log.Debug("Received connection from: ", "add", connObj.Conn.RemoteAddr())
	// Connect to the external host.
	externalHost, err := net.Dial("tcp", connObj.Hostip+":"+connObj.Hostport)
	if err != nil {
		log.Error("Error connecting external host", "err", err)
		return
	}
	defer externalHost.Close()
	// if this is a HTTP connection , we've to send the first response
	if !connObj.Is_https {
		externalHost.Write(connObj.FirstRequest)
	}
	done := make(chan models.Link)
	ctx, ctxCancel := context.WithCancel(ctx)
	go helpers.Pipe(ctx, "client->host", connObj.Conn, externalHost, done)
	go helpers.Pipe(ctx, "host-client", externalHost, connObj.Conn, done)

	log.Info("Go Routine %s finished", <-done)
	ctxCancel()
	log.Debug("Closing connection for host ", connObj.Hostname)
}

func handleNewConnection(ctx context.Context, connObj *models.ConnInfo, cfg *models.ProxyConfig) {
	defer connObj.TlsConn.Close()
	log := ctx.Value("logger").(*zap.SugaredLogger)
	log.Debug("Received connection ", "addr", connObj.Conn.RemoteAddr())

	// Perform the TLs handshake with client.
	err := connObj.TlsConn.Handshake()
	if err != nil {
		log.Error(err)
		return
	}

	log.Debug("Resolved %s::%s:%s\n", connObj.Hostname, connObj.Hostip, connObj.Hostport)
	// Setup the TLS configuration for connecting to the target.
	// Note that this configuration is deliberately insecure!
	config := tls.Config{
		InsecureSkipVerify: true,
	}
	// Connect to the external host.
	externalHost, err := tls.Dial("tcp", connObj.Hostip+":"+connObj.Hostport, &config)
	if err != nil {
		log.Error("Error connecting external host", "err", err)
		return
	}

	defer externalHost.Close()

	done := make(chan models.Link)
	ctx, ctxCancel := context.WithCancel(ctx)
	go helpers.Pipe(ctx, "client->host", connObj.TlsConn, externalHost, done)
	go helpers.Pipe(ctx, "host-client", externalHost, connObj.TlsConn, done)

	log.Debug("Routine %s finished", <-done)
	ctxCancel()
	log.Debug("Closing connection for host ", connObj.Hostname)

}
