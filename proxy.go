package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/k3dves/gaslight/helpers"
)

type ProxyConfig struct {
	ServerCert      string
	Hostname        string
	ServerKey       string
	InputPort       string
	InputBindIP     string
	OutputConnectIP string
	HostString      string
	HostIP          string
	HostPort        string
}

type Proxy struct {
	cfg *ProxyConfig
}

func New(cfg *ProxyConfig) *Proxy {
	return &Proxy{cfg: cfg}
}

func (p *Proxy) Start() {
	// Get the SSL certificate and private key.
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
		ClientAuth:   tls.NoClientCert,
	}

	// Listen on the input port.
	ln, err := net.Listen("tcp", p.cfg.InputBindIP+":"+p.cfg.InputPort)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Printf("INFO || Started Listner on %s::%s\n", p.cfg.InputBindIP, p.cfg.InputPort)
	for {
		log.Println("INFO || [main] Waiting for incoming connections...")
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		hostString, _ := helpers.ConsumeConnect(conn)
		p.cfg.HostString = hostString
		tlsConn := tls.Server(conn, TLSConfig)
		handleNewConnection(tlsConn, p.cfg)
	}

}

func handleNewConnection(conn *tls.Conn, cfg *ProxyConfig) {
	defer conn.Close()
	log.Println("[main] Received connection from: ", conn.RemoteAddr())

	// Perform the TLs handshake with client.
	err := conn.Handshake()
	if err != nil {
		log.Println(err)
		return
	}

	host, port, _ := helpers.ResolveHost(cfg.HostString)

	log.Print("Reslved host:port = " + host + ":" + port)
	// Setup the TLS configuration for connecting to the target.
	// Note that this configuration is deliberately insecure!
	config := tls.Config{
		InsecureSkipVerify: true,
	}
	// Connect to the external host.
	externalHost, err := tls.Dial("tcp", host+":"+port, &config)
	if err != nil {
		log.Printf("[main] Error connecting external host: %s\n", err)
		return
	}
	defer externalHost.Close()

	done := make(chan string)
	ctx, ctxCancel := context.WithCancel(context.Background())
	go pipe(ctx, "client->host", conn, externalHost, done)
	go pipe(ctx, "host-client", externalHost, conn, done)

	log.Printf("Routine %s finished", <-done)
	ctxCancel()

}

func pipe(ctx context.Context, name string, src, dest io.ReadWriter, done chan string) {
	defer func() {
		log.Print("Closing go routine ", name)
		done <- name
	}()

	for {
		select {

		case <-ctx.Done():
			return

		default:
			buff := make([]byte, 0xffff)
			n, readErr := src.Read(buff)
			if readErr != nil {
				log.Print("Error while reading err=", readErr)
				return
			} else {
				log.Printf("Read %d bytes %s", n, buff)
			}

			n2, writeErr := dest.Write(buff[:n])

			if writeErr != nil {
				log.Print("Error while writing err: ", writeErr)
				return
			} else {
				log.Printf("Written %d bytes\n", n2)
			}
		}
	}
}
