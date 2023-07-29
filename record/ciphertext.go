package record

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/arailly/mytls13/util"
)

type tlsInnerPlaintext struct {
	content     []byte
	contentType uint8
}

type tlsCiphertext struct {
	contentType     uint8
	protocolVersion uint16
	length          uint16
	encrypted       []byte
}

func newTLSCipherText(encrypted []byte) *tlsCiphertext {
	return &tlsCiphertext{
		contentType:     contentTypeApplicationData,
		protocolVersion: ProtocolVersionTLS12,
		length:          uint16(len(encrypted)),
		encrypted:       encrypted,
	}
}

func encrypt(
	key []byte,
	iv []byte,
	seqNum uint64,
	plaintext []byte,
) (
	[]byte,
	error,
) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 4)
	nonce = append(nonce, util.ToBytes(seqNum)...)
	for i, elem := range iv {
		nonce[i] ^= elem
	}
	additionalData := []byte{0x17}
	additionalData = append(additionalData, 0x03, 0x03)
	additionalData = append(
		additionalData,
		util.ToBytes(uint16(len(plaintext)+16))...,
	)
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

func decrypt(
	key []byte,
	iv []byte,
	seqNum uint64,
	ciphertext []byte,
) (
	[]byte,
	error,
) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 4)
	nonce = append(nonce, util.ToBytes(seqNum)...)
	for i, elem := range iv {
		nonce[i] ^= elem
	}
	additionalData := []byte{0x17}
	additionalData = append(additionalData, 0x03, 0x03)
	additionalData = append(
		additionalData,
		util.ToBytes(uint16(len(ciphertext)))...,
	)
	plainText, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	// TODO: remove zero padding
	return plainText[:len(plainText)-1], nil
}
