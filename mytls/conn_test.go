package mytls_test

import (
	"crypto/tls"
	"crypto/x509"
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
		conn.Write(expected)
		conn.Close()
	}()
	config := &core.Config{
		RootCAs:      []*x509.Certificate{cacert},
		KeyLogWriter: w,
	}

	// exercise
	conn, err := mytls.Dial("tcp", l.Addr().String(), config)

	// verify
	if err != nil {
		t.Fatal(err)
	}

	// setup
	actual := make([]byte, len(expected))

	// exercise
	n, err := conn.Read(actual)

	// verify
	if err != nil {
		t.Error(err)
	}
	if n != len(expected) {
		t.Error(n)
	}
	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Error(diff)
	}
}
