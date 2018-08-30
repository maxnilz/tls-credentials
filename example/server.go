package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/labstack/gommon/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func NewGRpcServer(addr string, caPath, serverCrt, serverKey string) error {
	var gRpcOptions []grpc.ServerOption

	// Parse certificates from certificate file and key file for server.
	cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
	if err != nil {
		return fmt.Errorf("invalid config: error parsing gRPC certificate file: %v", err)
	}

	if caPath != "" {
		// Parse certificates from client CA file to a new CertPool.
		cPool := x509.NewCertPool()
		clientCert, err := ioutil.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("invalid config: reading from client CA file: %v", err)
		}
		if cPool.AppendCertsFromPEM(clientCert) != true {
			return fmt.Errorf("invalid config: failed to parse client CA")
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    cPool,
		}
		gRpcOptions = append(gRpcOptions, grpc.Creds(credentials.NewTLS(&tlsConfig)))
	} else {
		opt, err := credentials.NewServerTLSFromFile(serverCrt, serverKey)
		if err != nil {
			return fmt.Errorf("invalid config: load grpc certs: %v", err)
		}
		gRpcOptions = append(gRpcOptions, grpc.Creds(opt))
	}

	errc := make(chan error, 1)
	go func() {
		errc <- func() error {
			list, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listening on %s failed: %v", addr, err)
			}
			s := grpc.NewServer(gRpcOptions...)
			//
			// here skip register server spawn by proto
			//
			err = s.Serve(list)
			return fmt.Errorf("listening on %s failed: %v", addr, err)
		}()
	}()

	return <-errc
}

func NewTLSServer(addr string, serverCrt, serverKey string) error {

	errc := make(chan error, 1)

	go func() {
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				echo := "hello world"
				w.Write([]byte(echo))
			})
			err := http.ListenAndServeTLS(addr, serverCrt, serverKey, nil)
			errc <- fmt.Errorf("listening on %s failed: %v", addr, err)
		}()
	}()

	return <-errc
}

func main() {
	caCrt := flag.String("ca-crt", "", "CA certificate")
	serverCrt := flag.String("server-crt", "", "Server certificate")
	serverKey := flag.String("server-key", "", "Server key")
	flag.Parse()

	if *serverCrt == "" || *serverKey == "" {
		log.Fatal("Please provide CA & client certificates and client key. Usage: ./server --ca-crt=[path ca.crt] --server-crt=<path client.crt> --server-key=<path client key>")
	}

	if err := NewGRpcServer("127.0.0.1:5557", *caCrt, *serverCrt, *serverKey); err != nil {
		log.Fatal(err)
	}

	if err := NewTLSServer("127.0.0.1:5557", *serverCrt, *serverKey); err != nil {
		log.Fatal(err)
	}
}
