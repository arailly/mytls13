package handshake

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/arailly/mytls13/key"
)

var (
	hashFunc = sha256.New
)

func computeVerifyData(baseKey, messages []byte) []byte {
	finishedKey := key.HKDFExpandLabel(
		baseKey,
		"finished",
		nil,
		hashFunc().Size(),
	)
	h := hmac.New(hashFunc, finishedKey)
	h.Write(key.TranscriptHash(messages))
	return h.Sum(nil)
}
