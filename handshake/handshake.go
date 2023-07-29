package handshake

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rsa"
	"errors"

	core "github.com/arailly/mytls13"
	"github.com/arailly/mytls13/key"
	"github.com/arailly/mytls13/record"
	"github.com/arailly/mytls13/util"
	"github.com/google/go-cmp/cmp"
)

const (
	contentTypeChangeCipherSpec uint8 = 20
	contentTypeHandshake        uint8 = 22

	handshakeTypeClientHello        uint8 = 1
	handshakeTypeServerHello        uint8 = 2
	handshakeTypeCertificate        uint8 = 11
	handshakeTypeServerKeyExchange  uint8 = 12
	handshakeTypeClientKeyExchange  uint8 = 16
	handshakeTypeFinished           uint8 = 20
	handshakeTypeCertificateStatus  uint8 = 22
	handshakeTypeCertificateRequest uint8 = 13
	handshakeTypeCertificateVerify  uint8 = 15
)

var (
	ellipticCurve           = ecdh.X25519()
	changeCipherSpecMessage = []byte{1}
)

type handshake struct {
	msgType uint8
	length  util.Uint24
	body    []byte
}

func newHandshake(
	msgType uint8,
	body []byte,
) *handshake {
	length := util.NewUint24(uint32(len(body)))
	return &handshake{
		msgType: msgType,
		length:  length,
		body:    body,
	}
}

func readHandshakeMessage(conn *record.Conn) ([]byte, []byte) {
	header := make([]byte, 4)
	conn.Read(header)
	length := util.Uint24(header[1:])
	body := make([]byte, length.Int())
	conn.Read(body)
	return header, body
}

func StartHandshake(conn *record.Conn, config *core.Config) error {
	conn.Keys.SetEarlySecret(nil)

	// Client Hello
	clientHello, err := newClientHello(
		config.ServerName,
	)
	if err != nil {
		return err
	}
	message := util.ToBytes(newHandshake(
		handshakeTypeClientHello,
		clientHello.bytes(),
	))
	conn.Push(
		contentTypeHandshake,
		message,
	)
	conn.Flush()
	handshakeMsgs := message

	// Server Hello
	header, body := readHandshakeMessage(conn)
	handshakeMsgs = append(handshakeMsgs, header...)
	handshakeMsgs = append(handshakeMsgs, body...)

	offset := 2
	serverRandom := body[offset : offset+32]
	_ = serverRandom
	offset += 32
	sessionIDLen := int(body[offset])
	offset += 1 + sessionIDLen
	cipherSuite := util.ToUint16(body[offset : offset+2])
	_ = cipherSuite
	offset += 2 + 1
	extensionLen := int(util.ToUint16(body[offset : offset+2]))
	offset += 2
	exts := ParseExtensions(body[offset : offset+extensionLen])
	var serverECDHPubKey *ecdh.PublicKey
	for _, ext := range exts {
		if ext.extensionType != extTypeKeyShare {
			continue
		}
		offset := 2
		length := int(util.ToUint16(ext.extensionData[offset : offset+2]))
		offset += 2
		serverECDHPubKey, err = ellipticCurve.NewPublicKey(
			ext.extensionData[offset : offset+length])
		if err != nil {
			return err
		}
	}
	ecdhPrivKey := clientHello.privateKey.(*ecdh.PrivateKey)
	sharedKey, err := ecdhPrivKey.ECDH(serverECDHPubKey)
	if err != nil {
		return err
	}

	conn.Keys.SetHandshakeSecret(sharedKey, handshakeMsgs)

	// Change Cipher Spec
	changeCipherSpec := make([]byte, 1)
	conn.Read(changeCipherSpec)
	conn.StartCipherRead()

	// Encrypted Extensions
	header, body = readHandshakeMessage(conn)
	handshakeMsgs = append(handshakeMsgs, header...)
	handshakeMsgs = append(handshakeMsgs, body...)
	conn.IncrementReadSeqNum()

	// Certificate
	header, body = readHandshakeMessage(conn)
	handshakeMsgs = append(handshakeMsgs, header...)
	handshakeMsgs = append(handshakeMsgs, body...)
	conn.IncrementReadSeqNum()

	// skip Certificate Request Context
	certificates, err := parseCertificates(body[4:])
	if err != nil {
		return err
	}
	if err := verifyCertificateChain(
		config.ServerName,
		certificates,
		config.RootCAs,
	); err != nil {
		return err
	}

	// Certificate Verify
	header, body = readHandshakeMessage(conn)
	offset = 2
	signatureLen := int(util.ToUint16(body[offset : offset+2]))
	offset += 2
	sig := body[offset : offset+signatureLen]
	hashedMsgs := key.TranscriptHash(handshakeMsgs)
	content := computeCertificateVerifyContent(hashedMsgs)
	hashed := key.TranscriptHash(content)
	rsaPubKey := certificates[0].PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hashed, sig, nil)
	if err != nil {
		return err
	}
	handshakeMsgs = append(handshakeMsgs, header...)
	handshakeMsgs = append(handshakeMsgs, body...)
	conn.IncrementReadSeqNum()

	// Finished
	header, body = readHandshakeMessage(conn)
	serverVerifyData := computeVerifyData(
		conn.Keys.ServerHandshakeTrafficSecret,
		handshakeMsgs,
	)
	if diff := cmp.Diff(serverVerifyData, body); diff != "" {
		return errors.New("invalid verify data")
	}
	handshakeMsgs = append(handshakeMsgs, header...)
	handshakeMsgs = append(handshakeMsgs, body...)
	conn.IncrementReadSeqNum()

	// Change Cipher Spec
	conn.Push(
		contentTypeChangeCipherSpec,
		changeCipherSpecMessage,
	)
	conn.StartCipherWrite()

	// Finished
	clientVerifyData := computeVerifyData(
		conn.Keys.ClientHandshakeTrafficSecret,
		handshakeMsgs,
	)
	message = util.ToBytes(newHandshake(
		handshakeTypeFinished,
		clientVerifyData,
	))
	conn.Push(contentTypeHandshake, message)
	conn.Flush()
	conn.IncrementWriteSeqNum()

	conn.Keys.SetAppSecret(handshakeMsgs)
	conn.ResetReadSeqNum()
	conn.ResetWriteSeqNum()

	return nil
}

func RespondHandshake(conn *record.Conn, config *core.Config) error {
	return nil
}
