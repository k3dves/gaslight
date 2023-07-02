package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"

	"github.com/k3dves/gaslight/helpers"
	"github.com/k3dves/gaslight/models"
)

type Proxy struct {
	cfg *models.ProxyConfig
}

func New(cfg *models.ProxyConfig) *Proxy {
	return &Proxy{cfg: cfg}
}

func (p *Proxy) Start() {
	// Get the SSL certificate and private key.
	// TODO: generate certs on the fly
	cer, err := tls.LoadX509KeyPair(p.cfg.ServerCert, p.cfg.ServerKey)
	if err != nil {
		log.Println("Error loading certs : ", err)
		return
	}
	log.Println("INFO || Loaded certs.")

	// Setup the TLS configuration.
	TLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
		ServerName:   p.cfg.ServerHostName,
	}

	// Listen on the input port.
	ln, err := net.Listen("tcp", p.cfg.ProxyIP+":"+p.cfg.ProxyPort)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Printf("INFO || Started Listner on %s::%s\n", p.cfg.ProxyIP, p.cfg.ProxyPort)
	for {
		log.Println("INFO || [main] Waiting for incoming connections...")
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		//initalise a new connInfo struct for this conn
		connObj := &models.ConnInfo{Conn: conn}
		//HandleFirstRequest updates connObj is_https
		hostString, err := helpers.HandleFirstRequest(connObj)
		if err != nil {
			log.Printf("ERR:: Invalid first request, err=%s\n", err)
			conn.Close()
			continue
		}
		hostname, hostip, port, _ := helpers.ResolveHost(hostString, connObj.Is_https)
		//update the connObj
		connObj.Hostip = hostip
		connObj.Hostport = port
		connObj.Hostname = hostname

		if strings.HasSuffix(hostname, "ifconfig.me") && connObj.Is_https {
			tlsConn := tls.Server(conn, TLSConfig)
			connObj.TlsConn = tlsConn
			go handleNewConnection(connObj, p.cfg)

		} else {
			go handleNewConnectionTransparent(connObj, p.cfg)
		}
	}

}

func handleNewConnectionTransparent(connObj *models.ConnInfo, cfg *models.ProxyConfig) {
	defer connObj.Conn.Close()
	log.Println("[Transparent]:: Received connection from: ", connObj.Conn.RemoteAddr())
	// Connect to the external host.
	externalHost, err := net.Dial("tcp", connObj.Hostip+":"+connObj.Hostport)
	if err != nil {
		log.Printf("[Transparent]:: Error connecting external host: %s\n", err)
		return
	}
	defer externalHost.Close()
	// if this is a HTTP connection , we've to send the first response
	if !connObj.Is_https {
		externalHost.Write(connObj.FirstRequest)
	}
	done := make(chan string)
	ctx, ctxCancel := context.WithCancel(context.Background())
	go pipe(ctx, "client->host", connObj.Conn, externalHost, done)
	go pipe(ctx, "host-client", externalHost, connObj.Conn, done)

	log.Printf("[Transparent]::Routine %s finished", <-done)
	ctxCancel()
}

func handleNewConnection(connObj *models.ConnInfo, cfg *models.ProxyConfig) {
	defer connObj.TlsConn.Close()
	log.Println("[PROXY] Received connection from: ", connObj.Conn.RemoteAddr())

	// Perform the TLs handshake with client.
	err := connObj.TlsConn.Handshake()
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("[PROXY]:: Resolved %s::%s:%s\n", connObj.Hostname, connObj.Hostip, connObj.Hostport)
	// Setup the TLS configuration for connecting to the target.
	// Note that this configuration is deliberately insecure!
	config := tls.Config{
		InsecureSkipVerify: true,
	}
	// Connect to the external host.
	externalHost, err := tls.Dial("tcp", connObj.Hostip+":"+connObj.Hostport, &config)
	if err != nil {
		log.Printf("[PROXY]:: Error connecting external host: %s\n", err)
		return
	}
	defer externalHost.Close()

	done := make(chan string)
	ctx, ctxCancel := context.WithCancel(context.Background())
	go pipe(ctx, "client->host", connObj.TlsConn, externalHost, done)
	go pipe(ctx, "host-client", externalHost, connObj.TlsConn, done)

	log.Printf("[PROXY]:: Routine %s finished", <-done)
	ctxCancel()

}

func pipe(ctx context.Context, name string, src, dest io.ReadWriter, done chan string) {
	defer func() {
		log.Print("[Pipe]::Closing go routine ", name)
		done <- name
	}()

	for {
		select {

		case <-ctx.Done():
			return

		default:
			buff := make([]byte, 10000000)
			n, readErr := src.Read(buff)
			if readErr != nil || n == 0 {
				// log.Print("[Pipe]::Error while reading err=", readErr)
				return
			} else {
				// log.Printf("[Pipe]::Read %d bytes ", n)
			}

			_, writeErr := dest.Write(buff[:n])

			if writeErr != nil {
				// log.Print("[Pipe]::Error while writing err: ", writeErr)
				return
			} else {
				// log.Printf("[Pipe]::Written %d bytes\n", n2)
			}
		}
	}
}
