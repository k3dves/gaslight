package helpers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
)

func ConsumeConnect(conn net.Conn) (string, error) {
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

func ResolveHost(hostString string) (string, string, string, error) {
	arr := strings.Split(hostString, ":")
	host, port := arr[0], arr[1]
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Panic("DNS resolution error " + err.Error())
	}
	log.Printf("Resolved hosts ip : %v", ips)
	return host, ips[len(ips)-1].String(), port, nil
}

func GetCertificate(hello *tls.ClientHelloInfo) {
	log.Printf("Got client hello %+v \n", hello)
	return
}
