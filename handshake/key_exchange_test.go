package handshake

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/arailly/mytls13/util"
	"github.com/google/go-cmp/cmp"
)

func GetPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	certData, err := os.ReadFile("../config/server.der")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	return pubKey
}

func GetPrivateKey(t *testing.T) *rsa.PrivateKey {
	keyData, err := os.ReadFile("../config/server-key.der")
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	return privKey
}

func TestEncryptPreMasterSecret(t *testing.T) {
	rng := rand.Reader
	random := make([]byte, 46)
	rng.Read(random)
	pubKey := GetPublicKey(t)
	encrypted := CalcEncryptedPreMasterSecret(random, pubKey)
	privKey := GetPrivateKey(t)
	decrypted, err := rsa.DecryptPKCS1v15(rng, privKey, encrypted.encryptedKey)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(random, decrypted[2:]); diff != "" {
		t.Error(diff)
	}
}

func TestECDH(t *testing.T) {
	c25519 := ecdh.X25519()

	privateAlice, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Alice's private/public key pair: %s\n", err)
	}
	publicAlice := privateAlice.PublicKey()

	privateBob, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Bob's private/public key pair: %s\n", err)
	}
	publicBob := privateBob.PublicKey()

	secretAlice, err := privateAlice.ECDH(publicBob)
	if err != nil {
		t.Fatal(err)
	}

	secretBob, err := privateBob.ECDH(publicAlice)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretAlice, secretBob) {
		fmt.Printf("key exchange failed - secret X coordinates not equal\n")
	}
}

func TestVerifyPSS(t *testing.T) {
	ecdhPubKey := []byte{
		0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43,
		0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29, 0x07,
		0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2,
		0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb, 0x3b, 0x74,
	}
	signature := []byte{
		0xba, 0xbd, 0x24, 0x84, 0xb7, 0x61, 0xfc, 0xc1,
		0xf0, 0x36, 0x99, 0x93, 0x41, 0xd2, 0xee, 0xf8,
		0x7f, 0xe6, 0x65, 0xe1, 0xec, 0xe5, 0x04, 0xe0,
		0x37, 0xc8, 0xff, 0xaf, 0x76, 0x85, 0x79, 0xa3,
		0xac, 0x59, 0xbd, 0xfa, 0x07, 0xa7, 0xd3, 0x89,
		0x57, 0xc4, 0xf0, 0xbf, 0xf9, 0x06, 0xfa, 0x46,
		0x03, 0xc6, 0x8b, 0x98, 0x7b, 0xf8, 0xbd, 0x8e,
		0x66, 0xb4, 0x00, 0x95, 0xfc, 0xa2, 0xea, 0x76,
		0x22, 0x4b, 0xa0, 0xd2, 0x24, 0x47, 0x4c, 0xc8,
		0xaa, 0x42, 0xd9, 0xbd, 0x33, 0x26, 0x45, 0xbd,
		0xff, 0x93, 0x3c, 0x81, 0x1c, 0xde, 0x53, 0xef,
		0x78, 0xf6, 0x77, 0xa2, 0x33, 0x2a, 0x84, 0x44,
		0xf8, 0xe7, 0x09, 0xeb, 0xec, 0xea, 0x6e, 0x45,
		0xb9, 0xb5, 0x88, 0x3f, 0x95, 0x77, 0x01, 0xa4,
		0xd9, 0x83, 0xc6, 0xf2, 0x7e, 0x45, 0x24, 0x5b,
		0x0a, 0x81, 0xd2, 0xcb, 0x2d, 0xe0, 0x7e, 0x0a,
		0xf7, 0x0d, 0x6c, 0x8e, 0xcd, 0xe6, 0xc9, 0xda,
		0xf0, 0x64, 0x44, 0x5d, 0x23, 0x2e, 0xd6, 0xb3,
		0xe3, 0x29, 0x43, 0xb3, 0xe4, 0x78, 0xa5, 0x04,
		0x3b, 0x54, 0x81, 0x3d, 0xa2, 0x78, 0xba, 0x25,
		0x77, 0xca, 0xf6, 0x9c, 0x77, 0xd6, 0xc4, 0x93,
		0xb2, 0x6c, 0x94, 0xda, 0xa4, 0xa4, 0xc2, 0x64,
		0x78, 0xad, 0x90, 0xb9, 0xde, 0x11, 0x16, 0x34,
		0x35, 0xcc, 0xca, 0x58, 0x38, 0x4b, 0xca, 0xf1,
		0x09, 0x58, 0xa6, 0x04, 0xdc, 0x9a, 0xdb, 0xc0,
		0x1c, 0x07, 0xa0, 0x47, 0xd8, 0x77, 0xba, 0x5e,
		0x5c, 0x01, 0x2d, 0xfa, 0x7a, 0x14, 0xf3, 0x61,
		0x94, 0x22, 0x2b, 0xa1, 0xa4, 0x49, 0x68, 0x75,
		0xa8, 0x02, 0x3c, 0x1f, 0x57, 0x3b, 0x9e, 0xdc,
		0x7e, 0x0c, 0xe1, 0x90, 0x59, 0xc3, 0x11, 0x2f,
		0x62, 0xfb, 0x63, 0x6f, 0x42, 0x41, 0x66, 0xba,
		0x11, 0xda, 0xe1, 0xe9, 0x2f, 0x15, 0x8f, 0xcd,
	}
	serverRandom := make([]byte, 32)
	clientRandom := serverRandom
	ecdhParams := util.ToBytes(NewECDHServerParams(ecdhPubKey))
	pubKey := GetPublicKey(t)
	data := append(clientRandom, serverRandom...)
	data = append(data, ecdhParams...)
	digest := sha256.Sum256(data)
	if err := rsa.VerifyPSS(
		pubKey,
		crypto.SHA256,
		digest[:],
		signature,
		nil,
	); err != nil {
		t.Error(err)
	}
}

func TestSignPSS(t *testing.T) {
	ecdhPubKey := []byte{
		0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43,
		0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29, 0x07,
		0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2,
		0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb, 0x3b, 0x74,
	}
	serverRandom := make([]byte, 32)
	clientRandom := serverRandom
	ecdhParams := util.ToBytes(NewECDHServerParams(ecdhPubKey))
	pubKey := GetPublicKey(t)
	privKey := GetPrivateKey(t)
	data := append(clientRandom, serverRandom...)
	data = append(data, ecdhParams...)
	digest := sha256.Sum256(data)
	sig, err := rsa.SignPSS(
		util.NewConstRand(),
		privKey,
		crypto.SHA256,
		digest[:],
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	if err := rsa.VerifyPSS(
		pubKey,
		crypto.SHA256,
		digest[:],
		sig,
		nil,
	); err != nil {
		t.Error(err)
	}
}
