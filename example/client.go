package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func newGRpcClient(hostAndPort, caPath, clientCrt, clientKey string) (*grpc.ClientConn, error) {
	cPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("invalid CA crt file: %s", caPath)
	}
	if cPool.AppendCertsFromPEM(caCert) != true {
		return nil, fmt.Errorf("failed to parse CA crt")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt file: %s", caPath)
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}

	creds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.Dial(hostAndPort, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dail: %v", err)
	}

	return conn, nil
}

func newTLSClient(hostAndPort, caPath, clientCrt, clientKey string) (*tls.Conn, error) {
	cPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("invalid CA crt file: %s", caPath)
	}
	if cPool.AppendCertsFromPEM(caCert) != true {
		return nil, fmt.Errorf("failed to parse CA crt")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt file: %s", caPath)
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}

	conn, err := tls.Dial("tcp", hostAndPort, clientTLSConfig)
	if err != nil {
		return nil, fmt.Errorf("dail: %v", err)
	}

	return conn, nil
}

func main() {
	caCrt := flag.String("ca-crt", "", "CA certificate")
	clientCrt := flag.String("client-crt", "", "Client certificate")
	clientKey := flag.String("client-key", "", "Client key")
	flag.Parse()

	if *clientCrt == "" || *caCrt == "" || *clientKey == "" {
		log.Fatal("Please provide CA & client certificates and client key. Usage: ./client --ca-crt=<path ca.crt> --client-crt=<path client.crt> --client-key=<path client key>")
	}

	rawGRpcClient, err := newGRpcClient("127.0.0.1:5557", *caCrt, *clientCrt, *clientKey)
	if err != nil {
		log.Fatalf("failed creating raw client: %v ", err)
	}
	defer rawGRpcClient.Close()

	//
	// skip register gRpc client spawn by proto
	//
	_ = rawGRpcClient

	tlsClient, err := newTLSClient("127.0.0.1:5557", *caCrt, *clientCrt, *clientKey)
	if err != nil {
		log.Fatalf("failed creating raw client: %v ", err)
	}
	defer tlsClient.Close()

	_ = tlsClient
}
