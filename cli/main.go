package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
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

	crt, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	if len(crt.Certificate) < 1 {
		log.Fatal(1)
	}

	var leaf *x509.Certificate

	leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	m := make(map[string]struct{})

	m[strings.TrimPrefix(leaf.Subject.CommonName, "*")] = struct{}{}
	for i := range leaf.DNSNames {
		m[strings.TrimPrefix(leaf.DNSNames[i], "*")] = struct{}{}
	}

	gob.RegisterName("rsa.PublicKey", rsa.PublicKey{})
	gob.RegisterName("rsa.PrivateKey", rsa.PrivateKey{})

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(crt); err != nil {
		log.Fatal(err)
	}

	c := db.Get()
	defer c.Close()

	for k := range m {
		if err = c.Send("SET", k, b); err != nil {
			log.Fatal(err)
		}
	}

	// var decCrt tls.Certificate

	// dec := gob.NewDecoder(&b)
	// err = dec.Decode(&decCrt)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// spew.Dump(m, b, decCrt)
}
