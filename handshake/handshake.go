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
	handshakeTypeNewSessionTicket   uint8 = 4
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

func readHandshake(conn *record.Conn) (*handshake, error) {
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}
	length := util.Uint24(header[1:])
	body := make([]byte, length.Int())
	if _, err := conn.Read(body); err != nil {
		return nil, err
	}
	return &handshake{
		msgType: header[0],
		length:  length,
		body:    body,
	}, nil
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
		util.ToBytes(clientHello),
	))
	conn.Push(
		contentTypeHandshake,
		message,
	)
	conn.Flush()
	handshakeMsgs := message

	// Server Hello
	handshakeMsg, err := readHandshake(conn)
	if err != nil {
		return err
	}
	handshakeMsgs = append(handshakeMsgs, util.ToBytes(handshakeMsg)...)

	serverHello, err := parseServerHello(handshakeMsg)
	if err != nil {
		return err
	}
	ecdhPrivKey := clientHello.privateKey
	sharedKey, err := ecdhPrivKey.ECDH(serverHello.publicKey)
	if err != nil {
		return err
	}

	conn.Keys.SetHandshakeSecret(sharedKey, handshakeMsgs)

	// Change Cipher Spec
	changeCipherSpec := make([]byte, 1)
	conn.Read(changeCipherSpec)
	conn.StartCipherRead()

	// Encrypted Extensions
	handshakeMsg, err = readHandshake(conn)
	if err != nil {
		return err
	}
	handshakeMsgs = append(handshakeMsgs, util.ToBytes(handshakeMsg)...)

	// Certificate
	handshakeMsg, err = readHandshake(conn)
	if err != nil {
		return err
	}
	handshakeMsgs = append(handshakeMsgs, util.ToBytes(handshakeMsg)...)

	// skip Certificate Request Context
	certificates, err := parseCertificates(handshakeMsg)
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
	handshakeMsg, err = readHandshake(conn)
	if err != nil {
		return err
	}

	certificateVerify, err := parseCertificateVerify(handshakeMsg)
	if err != nil {
		return err
	}
	hashedMsgs := key.TranscriptHash(handshakeMsgs)
	content := computeCertificateVerifyContent(hashedMsgs)
	hashed := key.TranscriptHash(content)
	rsaPubKey := certificates[0].PublicKey.(*rsa.PublicKey)
	if err = rsa.VerifyPSS(
		rsaPubKey,
		crypto.SHA256,
		hashed,
		certificateVerify.signature,
		nil,
	); err != nil {
		return err
	}

	handshakeMsgs = append(handshakeMsgs, util.ToBytes(handshakeMsg)...)

	// Finished
	handshakeMsg, err = readHandshake(conn)
	if err != nil {
		return err
	}

	serverVerifyData := computeVerifyData(
		conn.Keys.ServerHandshakeTrafficSecret,
		handshakeMsgs,
	)
	if diff := cmp.Diff(serverVerifyData, handshakeMsg.body); diff != "" {
		return errors.New("invalid verify data")
	}

	handshakeMsgs = append(handshakeMsgs, util.ToBytes(handshakeMsg)...)

	// Change Cipher Spec
	conn.Push(contentTypeChangeCipherSpec, changeCipherSpecMessage)
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

	conn.Keys.SetAppSecret(handshakeMsgs)
	conn.ResetReadSeqNum()
	conn.ResetWriteSeqNum()

	// TODO: process if next message is new session ticket message

	return nil
}

func RespondHandshake(conn *record.Conn, config *core.Config) error {
	return nil
}
