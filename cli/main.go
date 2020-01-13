package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/gomodule/redigo/redis"
)

const (
	dbAddress = "127.0.0.1:6379"
)

func main() {
	db := &redis.Pool{
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

	var (
		certPEMBlock, keyPEMBlock []byte

		err error
	)

	certPEMBlock, err = ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	keyPEMBlock, err = ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	crt, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}

	if len(crt.Certificate) < 1 {
		log.Fatal(1)
	}

	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	m := make(map[string]struct{})

	m[strings.TrimPrefix(crt.Leaf.Subject.CommonName, "*")] = struct{}{}
	for i := range crt.Leaf.DNSNames {
		m[strings.TrimPrefix(crt.Leaf.DNSNames[i], "*")] = struct{}{}
	}

	c := db.Get()
	defer c.Close()

	keyPEMBlock = append(keyPEMBlock, []byte("\n")...)
	val := append(keyPEMBlock, certPEMBlock...)

	for k := range m {
		if err = c.Send("SET", k, val); err != nil {
			log.Fatal(err)
		}
	}
}
