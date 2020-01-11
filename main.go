package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"github.com/pires/go-proxyproto"
)

var localAddress string
var backendAddress string
var certificatePath string
var keyPath string

func main() {
	flag.StringVar(&localAddress, "l", "89.184.72.25:443", "local address")
	flag.StringVar(&backendAddress, "b", "89.184.72.25:80", "backend address")
	flag.StringVar(&certificatePath, "c", "/etc/nginx/ssl/s3rj1k-54758.crt", "SSL certificate path")
	flag.StringVar(&keyPath, "k", "/etc/nginx/ssl/s3rj1k-54758.key", "SSL key path")

	flag.Parse()

	cert, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		log.Fatalf("error in tls.LoadX509KeyPair: %s\n", err)
	}

	config := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", localAddress, &config)
	if err != nil {
		log.Fatalf("error in tls.Listen: %s\n", err)
	}

	defer listener.Close()

	log.Printf("local server on: %s, backend server on: %s\n", localAddress, backendAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error in listener.Accept: %s\n", err)

			break
		}

		go handle(conn)
	}
}

func handle(clientConn net.Conn) {
	defer clientConn.Close()

	tlsconn, ok := clientConn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsconn.Handshake(); err != nil {
		log.Printf("error in tls.Handshake: %s\n", err)

		return
	}

	backendConn, err := net.Dial("tcp", backendAddress)
	if err != nil {
		log.Printf("error in net.Dial: %s\n", err)

		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go tunnelProxy(clientConn, backendConn, wg)
	go tunnel(backendConn, clientConn, wg)

	wg.Wait()
}

func tunnel(from, to net.Conn, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()

		if r := recover(); r != nil {
			log.Printf("recovered while tunneling")
		}
	}()

	if _, err := io.Copy(from, to); err != nil {
		log.Printf("error in io.Copy: %s\n", err)
	}

	to.Close()
	from.Close()
}

func tunnelProxy(from, to net.Conn, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()

		if r := recover(); r != nil {
			log.Printf("recovered while tunneling")
		}
	}()

	// Write out the header!
	header := &proxyproto.Header{
		Version:            2,
		Command:            proxyproto.PROXY,
		TransportProtocol:  proxyproto.TCPv4,
		SourceAddress:      net.ParseIP("1.1.1.1"),
		SourcePort:         51000,
		DestinationAddress: net.ParseIP("89.184.72.25"),
		DestinationPort:    80,
	}
	header.WriteTo(to)

	if _, err := io.Copy(from, to); err != nil {
		log.Printf("error in io.Copy: %s\n", err)
	}

	to.Close()
	from.Close()
}
