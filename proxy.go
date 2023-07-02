package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"

	"github.com/k3dves/gaslight/helpers"
)

type ProxyConfig struct {
	ServerCert string
	Hostname   string
	ServerKey  string
	ProxyPort  string
	ProxyIP    string
	HostString string
	HostIP     string
	HostPort   string
}

type Proxy struct {
	cfg *ProxyConfig
}

func New(cfg *ProxyConfig) *Proxy {
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
		ServerName:   p.cfg.Hostname,
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

		// TODO: What happens when first req is not HTTP CONNECT??
		hostString, _ := helpers.ConsumeConnect(conn)
		hostname, hostip, port, _ := helpers.ResolveHost(hostString)
		p.cfg.HostIP = hostip
		p.cfg.HostPort = port
		p.cfg.HostString = hostString
		p.cfg.Hostname = hostname
		tlsConn := tls.Server(conn, TLSConfig)
		if strings.HasSuffix(hostname, "ifconfig.me") {

			go handleNewConnection(tlsConn, p.cfg)

		} else {

			go handleNewConnectionTransparent(conn, p.cfg)
		}
	}

}

func handleNewConnectionTransparent(conn net.Conn, cfg *ProxyConfig) {
	defer conn.Close()
	log.Println("[Transparent]:: Received connection from: ", conn.RemoteAddr())
	// Connect to the external host.
	externalHost, err := net.Dial("tcp", cfg.HostIP+":"+cfg.HostPort)
	if err != nil {
		log.Printf("[Transparent]:: Error connecting external host: %s\n", err)
		return
	}
	defer externalHost.Close()
	done := make(chan string)
	ctx, ctxCancel := context.WithCancel(context.Background())
	go pipe(ctx, "client->host", conn, externalHost, done)
	go pipe(ctx, "host-client", externalHost, conn, done)

	log.Printf("[Transparent]::Routine %s finished", <-done)
	ctxCancel()
}
func handleNewConnection(conn *tls.Conn, cfg *ProxyConfig) {
	defer conn.Close()
	log.Println("[PROXY] Received connection from: ", conn.RemoteAddr())

	// Perform the TLs handshake with client.
	err := conn.Handshake()
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("[PROXY]:: Resolved %s::%s:%s\n", cfg.Hostname, cfg.HostIP, cfg.HostPort)
	// Setup the TLS configuration for connecting to the target.
	// Note that this configuration is deliberately insecure!
	config := tls.Config{
		InsecureSkipVerify: true,
	}
	// Connect to the external host.
	externalHost, err := tls.Dial("tcp", cfg.HostIP+":"+cfg.HostPort, &config)
	if err != nil {
		log.Printf("[PROXY]:: Error connecting external host: %s\n", err)
		return
	}
	defer externalHost.Close()

	done := make(chan string)
	ctx, ctxCancel := context.WithCancel(context.Background())
	go pipe(ctx, "client->host", conn, externalHost, done)
	go pipe(ctx, "host-client", externalHost, conn, done)

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
				log.Print("[Pipe]::Error while reading err=", readErr)
				return
			} else {
				log.Printf("[Pipe]::Read %d bytes ", n)
			}

			n2, writeErr := dest.Write(buff[:n])

			if writeErr != nil {
				log.Print("[Pipe]::Error while writing err: ", writeErr)
				return
			} else {
				log.Printf("[Pipe]::Written %d bytes\n", n2)
			}
		}
	}
}
