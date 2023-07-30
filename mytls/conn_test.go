package mytls_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"testing"

	core "github.com/arailly/mytls13"
	"github.com/arailly/mytls13/mytls"
	"github.com/arailly/mytls13/util"
	"github.com/google/go-cmp/cmp"
)

func TestClient(t *testing.T) {
	// setup
	cert, err := tls.LoadX509KeyPair(
		"../config/server.pem",
		"../config/server-key.pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	cacert, err := util.LoadCertificate("../config/ca.der")
	if err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(
		"/tmp/tls-secrets.txt",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		Rand:         util.NewConstRand(),
		KeyLogWriter: w,
		// ClientAuth: tls.RequestClientCert,
	}
	l, err := tls.Listen(
		"tcp",
		":0",
		tlsConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte("hello world")
	go func() {
		conn, _ := l.Accept()
		io.Copy(conn, conn)
		conn.Close()
	}()
	config := &core.Config{
		RootCAs:      []*x509.Certificate{cacert},
		KeyLogWriter: w,
	}

	// exercise
	conn, err := mytls.Dial("tcp", l.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}

	// exercise
	if err := conn.Send(expected); err != nil {
		t.Fatal(err)
	}

	// exercise
	actual := make([]byte, len(expected))
	n, err := conn.Read(actual)
	if err != nil {
		t.Error(err)
	}

	// verify
	if n != len(expected) {
		t.Error(n)
	}
	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Error(diff)
	}

	// exercise
	if err := conn.Close(); err != nil {
		t.Error(err)
	}
}

// func TestHTTPS(t *testing.T) {
// 	cacert, err := util.LoadCertificate(
// 		"../config/Starfield Services Root Certificate Authority - G2.der",
// 	)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	config := &core.Config{
// 		RootCAs: []*x509.Certificate{cacert},
// 	}
// 	conn, err := mytls.Dial("tcp", "www.cybozu.com:443", config)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer conn.Close()
// 	conn.Send([]byte("GET / HTTP/1.1\r\nHOST: www.cybozu.com\r\n\r\n"))
// 	data := make([]byte, 8)
// 	conn.Read(data)
// 	if string(data) != "HTTP/1.1" {
// 		t.Errorf(string(data))
// 	}
// }
