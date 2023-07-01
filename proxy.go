package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

type ProxyConfig struct {
	ServerCert           string
	Hostname             string
	ServerKey            string
	InputPort            string
	ReturnPort           string
	InterceptorPort      string
	InputBindIP          string
	InterceptorConnectIP string
	ReturnBindIP         string
	OutputConnectIP      string
	HostString           string
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

		hostString, _ := consumeConnect(conn)
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

	host, port, _ := resolveHost(cfg.HostString)

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
	return

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

func consumeConnect(conn net.Conn) (string, error) {
	// 64k data buffer.
	buff := make([]byte, 0xffff)
	conn.Read(buff)
	r, _ := http.ReadRequest(bufio.NewReader(bytes.NewReader(buff)))
	if r.Method != http.MethodConnect {
		log.Panic("Client not using connect, method: ", r.Method)
	}
	conn.Write([]byte("HTTP/1.1 200 OK\n\r\n"))
	log.Printf("Read %s from conn", string(buff))
	log.Printf("Connect Consumed")
	return r.Host, nil
}

func resolveHost(hostString string) (string, string, error) {
	arr := strings.Split(hostString, ":")
	host, port := arr[0], arr[1]
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Panic("DNS resolution error " + err.Error())
	}
	log.Printf("Resolved hosts ip : %v", ips)
	return ips[len(ips)-1].String(), port, nil
}
