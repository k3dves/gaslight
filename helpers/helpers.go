package helpers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/k3dves/gaslight/models"
)

func consumeConnect(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\n\r\n"))
	if err != nil {
		log.Print("consumeConnect:: Error := ", err)
		return err
	}
	log.Printf("Connect Request Consumed")
	return nil
}

func ResolveHost(hostString string, isHTTPS bool) (string, string, string, error) {
	arr := strings.Split(hostString, ":")
	var host, port string
	if len(arr) < 2 {
		// no port specified in hoststring assuming deafaults
		host = arr[0]
		port = "80"
		if isHTTPS {
			port = "443"
		}

	} else {
		host, port = arr[0], arr[1]
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Panic("DNS resolution error " + err.Error())
	}
	log.Printf("Resolved hosts ip : %v", ips)
	return host, ips[len(ips)-1].String(), port, nil
}

func GetCertificate(hello *tls.ClientHelloInfo) {
	log.Printf("Got client hello %+v \n", hello)
}

func HandleFirstRequest(connObj *models.ConnInfo) (string, error) {
	// 64k data buffer.
	//TODO is 64K enough??
	buff := make([]byte, 0xffff)
	n, _ := connObj.Conn.Read(buff)
	connObj.FirstRequest = buff[:n]
	// ReadRequest does not support HTTP2 !!
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buff)))
	log.Print("Got request:: ", r)

	if err != nil {
		log.Print("Possibly not a vaid HTTP request, req= ", buff)
		return "", err
	}
	switch r.Method {
	case http.MethodConnect:
		connObj.Is_https = true
		// This is a connect method, call consume connect
		consumeConnect(connObj.Conn)

	default:
		// set the contex is_https to false
		connObj.Is_https = false
		// Probably not using TLS , route transparently
	}

	// finally return host string
	return r.Host, nil
}
