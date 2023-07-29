package key

// TODO: make key module

import (
	"crypto/sha256"
	"fmt"

	"github.com/arailly/mytls13/util"
	"golang.org/x/crypto/hkdf"
)

var (
	hashFunc = sha256.New
)

func TranscriptHash(messages []byte) []byte {
	h := hashFunc()
	h.Write(messages)
	return h.Sum(nil)
}

func HKDFExpandLabel(
	secret []byte,
	label string,
	context []byte,
	length int,
) []byte {
	hkdfLabel := util.ToBytes(uint16(length))
	prefixedLabel := fmt.Sprintf("tls13 %s", label)
	hkdfLabel = append(hkdfLabel, util.ToBytes(uint8(len(prefixedLabel)))...)
	hkdfLabel = append(hkdfLabel, prefixedLabel...)
	hkdfLabel = append(hkdfLabel, util.ToBytes(uint8(len(context)))...)
	hkdfLabel = append(hkdfLabel, context...)
	out := make([]byte, length)
	n, err := hkdf.Expand(hashFunc, secret, hkdfLabel).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

func deriveSecret(secret []byte, label string, messages []byte) []byte {
	return HKDFExpandLabel(
		secret,
		label,
		TranscriptHash(messages),
		hashFunc().Size(),
	)
}

type Keys struct {
	connectionEnd string

	earlySecret                  []byte
	handshakeSecret              []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	masterSecret                 []byte
	clientAppTrafficSecret       []byte
	serverAppTrafficSecret       []byte
	exporterMasterSecret         []byte
	resumptionMasterSecret       []byte

	WriteKey []byte
	WriteIV  []byte
	ReadKey  []byte
	ReadIV   []byte
}

func NewKeys(connectionEnd string) *Keys {
	return &Keys{
		connectionEnd: connectionEnd,
	}
}

func (k *Keys) SetEarlySecret(psk []byte) {
	if psk == nil {
		psk = make([]byte, hashFunc().Size())
	}
	k.earlySecret = hkdf.Extract(hashFunc, psk, nil)
}

func (k *Keys) SetHandshakeSecret(sharedKey []byte, messages []byte) {
	salt := deriveSecret(k.earlySecret, "derived", nil)
	k.handshakeSecret = hkdf.Extract(hashFunc, sharedKey, salt)

	k.ClientHandshakeTrafficSecret = deriveSecret(
		k.handshakeSecret,
		"c hs traffic",
		messages,
	)
	k.ServerHandshakeTrafficSecret = deriveSecret(
		k.handshakeSecret,
		"s hs traffic",
		messages,
	)

	clientWriteKey := HKDFExpandLabel(
		k.ClientHandshakeTrafficSecret, "key", nil, 16)
	clientWriteIV := HKDFExpandLabel(
		k.ClientHandshakeTrafficSecret, "iv", nil, 12)
	serverWriteKey := HKDFExpandLabel(
		k.ServerHandshakeTrafficSecret, "key", nil, 16)
	serverWriteIV := HKDFExpandLabel(
		k.ServerHandshakeTrafficSecret, "iv", nil, 12)

	if k.connectionEnd == "client" {
		k.WriteKey = clientWriteKey
		k.WriteIV = clientWriteIV
		k.ReadKey = serverWriteKey
		k.ReadIV = serverWriteIV
	} else if k.connectionEnd == "server" {
		k.WriteKey = serverWriteKey
		k.WriteIV = serverWriteIV
		k.ReadKey = clientWriteKey
		k.ReadIV = clientWriteIV
	} else {
		panic("unexpected connection end: " + k.connectionEnd)
	}
}

func (k *Keys) SetAppSecret(messages []byte) {
	salt := deriveSecret(k.handshakeSecret, "derived", nil)
	k.masterSecret = hkdf.Extract(
		hashFunc,
		make([]byte, hashFunc().Size()),
		salt,
	)
	k.clientAppTrafficSecret = deriveSecret(
		k.masterSecret,
		"c ap traffic",
		messages,
	)
	k.serverAppTrafficSecret = deriveSecret(
		k.masterSecret,
		"s ap traffic",
		messages,
	)

	clientWriteKey := HKDFExpandLabel(
		k.clientAppTrafficSecret, "key", nil, 16)
	clientWriteIV := HKDFExpandLabel(
		k.clientAppTrafficSecret, "iv", nil, 12)
	serverWriteKey := HKDFExpandLabel(
		k.serverAppTrafficSecret, "key", nil, 16)
	serverWriteIV := HKDFExpandLabel(
		k.serverAppTrafficSecret, "iv", nil, 12)

	if k.connectionEnd == "client" {
		k.WriteKey = clientWriteKey
		k.WriteIV = clientWriteIV
		k.ReadKey = serverWriteKey
		k.ReadIV = serverWriteIV
	} else if k.connectionEnd == "server" {
		k.WriteKey = serverWriteKey
		k.WriteIV = serverWriteIV
		k.ReadKey = clientWriteKey
		k.ReadIV = clientWriteIV
	} else {
		panic("unexpected connection end: " + k.connectionEnd)
	}
}
