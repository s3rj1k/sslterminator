package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/garyburd/redigo/redis"
	"github.com/pires/go-proxyproto"
)

const (
	dbAddress = "127.0.0.1:6379"
)

// nolint: gochecknoglobals
var (
	localAddress   string
	backendAddress string

	db             *redis.Pool
	reDomainPrefix *regexp.Regexp
)

func loadCertficateAndKey(data []byte) (*tls.Certificate, error) {
	var cert tls.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			var err error

			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failure reading private key: %w", err)
			}
		}

		data = rest
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}

	if cert.PrivateKey == nil {
		return nil, fmt.Errorf("no private key found")
	}

	return &cert, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := db.Get()
	defer c.Close()

	exact := strings.ToLower(info.ServerName)
	wildcard := reDomainPrefix.ReplaceAllString(exact, ".")

	if data, err := redis.Bytes(
		c.Do("GET", exact),
	); err == nil && len(data) > 0 {
		if crt, err := loadCertficateAndKey(data); err == nil {
			return crt, nil
		}
	}

	if data, err := redis.Bytes(
		c.Do("GET", wildcard),
	); err == nil && len(data) > 0 {
		if crt, err := loadCertficateAndKey(data); err == nil {
			return crt, nil
		}
	}

	return nil, errors.New("no certificate found")
}

func main() {
	reDomainPrefix = regexp.MustCompile(`^.*?\.`)

	db = &redis.Pool{
		MaxIdle:   2,
		MaxActive: 20,
		Dial: func() (redis.Conn, error) {
			return redis.Dial(
				"tcp",
				dbAddress,
				redis.DialDatabase(15),
			)
		},
	}

	flag.StringVar(&localAddress, "l", "89.184.72.25:443", "local address")
	flag.StringVar(&backendAddress, "b", "89.184.72.25:80", "backend address")

	flag.Parse()

	config := tls.Config{
		Certificates:   nil,
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS12,
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

	if _, err := header.WriteTo(to); err != nil {
		log.Printf("error in header.WriteTo: %s\n", err)
	}

	if _, err := io.Copy(from, to); err != nil {
		log.Printf("error in io.Copy: %s\n", err)
	}

	to.Close()
	from.Close()
}
