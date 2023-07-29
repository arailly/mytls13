package handshake

import (
	"crypto/ecdh"
	"errors"

	core "github.com/arailly/mytls13"
	"github.com/arailly/mytls13/record"
	"github.com/arailly/mytls13/util"
)

const (
	supportedGroupX25519              uint16 = 0x001d
	extTypeSNI                        uint16 = 0
	extTypeStatusRequest              uint16 = 5
	extTypeSupportedGroups            uint16 = 10
	extTypeECPointFormats             uint16 = 11
	extTypeSignatureAlgorithms        uint16 = 13
	extTypeRenegotiationInfo          uint16 = 65281
	extTypeSignedCertificateTimestamp uint16 = 18
	extTypeSupportedVersions          uint16 = 43
	extTypeKeyShare                   uint16 = 51
)

var (
	extStatusRequest = newExtension(
		extTypeStatusRequest,
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00},
	)
	extSupportedGroups = newExtension(
		extTypeSupportedGroups,
		[]byte{
			0x00, 0x08,
			0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
		},
	)
	extECPointFormats = newExtension(
		extTypeECPointFormats,
		[]byte{0x01, 0x00},
	)
	extSignatureAlgorithms = newExtension(
		extTypeSignatureAlgorithms,
		[]byte{
			0x00, 0x18,
			0x08, 0x04, 0x04, 0x03, 0x08, 0x07, 0x08, 0x05,
			0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
			0x05, 0x03, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
		},
	)
	extRenegotiationInfo = newExtension(
		extTypeRenegotiationInfo,
		[]byte{0x00},
	)
	extSignedCertificateTimestamp = newExtension(
		extTypeSignedCertificateTimestamp,
		make([]byte, 0),
	)
	extSupportedVersions = newExtension(
		extTypeSupportedVersions,
		[]byte{0x02, 0x03, 0x04},
	)
)

type cipherSuites struct {
	length uint16
	body   []uint16
}

func newCipherSuites(suites []uint16) *cipherSuites {
	return &cipherSuites{
		length: uint16(len(suites) * 2),
		body:   suites,
	}
}

type extension struct {
	extensionType uint16
	length        uint16
	extensionData []byte
}

func newExtension(extensionType uint16, data []byte) extension {
	return extension{
		extensionType: extensionType,
		length:        uint16(len(data)),
		extensionData: data,
	}
}

type extensions struct {
	length uint16
	body   []extension
}

func newExtensions(exts []extension) *extensions {
	var length uint16 = 0
	for _, ext := range exts {
		length += 2 + 2 + ext.length
	}
	return &extensions{
		length: length,
		body:   exts,
	}
}

type clientHello struct {
	version            uint16
	random             []byte
	sessionID          uint8
	cipherSuites       *cipherSuites
	compressionMethods uint16
	extensions         *extensions

	// not export
	privateKey *ecdh.PrivateKey
}

func (ch *clientHello) Bytes() []byte {
	data := util.ToBytes(ch.version)
	data = append(data, ch.random...)
	data = append(data, ch.sessionID)
	data = append(data, util.ToBytes(ch.cipherSuites)...)
	data = append(data, util.ToBytes(ch.compressionMethods)...)
	data = append(data, util.ToBytes(ch.extensions)...)
	return data
}

func newExtSNI(serverName string) extension {
	data := util.ToBytes(uint16(len(serverName) + 3))
	data = append(data, 0x00)
	data = append(data, util.ToBytes(uint16(len(serverName)))...)
	data = append(data, []byte(serverName)...)
	return newExtension(
		extTypeSNI,
		data,
	)
}

func newExtKeyShare(keyExchange []byte) extension {
	group := supportedGroupX25519
	keyExchangeLen := uint16(len(keyExchange))
	length := util.ToBytes(uint16(4 + len(keyExchange)))
	data := append(length, util.ToBytes(group)...)
	data = append(data, util.ToBytes(keyExchangeLen)...)
	data = append(data, keyExchange...)
	return newExtension(extTypeKeyShare, data)
}

func newBasicExtensions(serverName string, keyExchange []byte) *extensions {
	extensions := []extension{
		newExtSNI(serverName),
		// extStatusRequest,
		extSupportedGroups,
		extECPointFormats,
		extSignatureAlgorithms,
		extRenegotiationInfo,
		extSignedCertificateTimestamp,
		extSupportedVersions,
		newExtKeyShare(keyExchange),
	}
	return newExtensions(extensions)
}

func newClientHello(
	serverName string,
) (*clientHello, error) {
	rng := util.NewConstRand()
	clientRandom := make([]byte, 32)
	rng.Read(clientRandom)
	cipherSuites := []uint16{core.TLS_AES_128_GCM_SHA256}

	ecdhPrivKey, err := ellipticCurve.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	ecdhPubKey := ecdhPrivKey.PublicKey().Bytes()

	return &clientHello{
		version:            record.ProtocolVersionTLS12,
		random:             clientRandom,
		sessionID:          0x00,
		cipherSuites:       newCipherSuites(cipherSuites),
		compressionMethods: 0x0100,
		extensions:         newBasicExtensions(serverName, ecdhPubKey),

		privateKey: ecdhPrivKey,
	}, nil
}

type serverHello struct {
	serverVersion     uint16
	random            []byte
	sessionId         uint8
	cipherSuite       uint16
	compressionMethod uint8
	extensions        *extensions

	// not export
	publicKey *ecdh.PublicKey
}

func (sh *serverHello) Bytes() []byte {
	data := util.ToBytes(sh.serverVersion)
	data = append(data, sh.random...)
	data = append(data, sh.sessionId)
	data = append(data, util.ToBytes(sh.cipherSuite)...)
	data = append(data, sh.compressionMethod)
	data = append(data, util.ToBytes(sh.extensions)...)
	return data
}

func newServerHello(
	random []byte,
	cipherSuite uint16,
	extensions []extension,
) *serverHello {
	return &serverHello{
		serverVersion:     record.ProtocolVersionTLS12,
		random:            random,
		sessionId:         0x00,
		cipherSuite:       cipherSuite,
		compressionMethod: 0,
		extensions:        newExtensions(extensions),
	}
}

func ParseExtensions(b []byte) []*extension {
	offset := 0
	var exts []*extension
	for {
		if offset >= len(b) {
			break
		}
		extType := util.ToUint16(b[offset : offset+2])
		offset += 2
		length := util.ToUint16(b[offset : offset+2])
		offset += 2
		data := b[offset : offset+int(length)]
		offset += int(length)
		exts = append(exts, &extension{
			extensionType: extType,
			length:        length,
			extensionData: data,
		})
	}
	return exts
}

func parseServerHello(hs *handshake) (*serverHello, error) {
	if hs.msgType != handshakeTypeServerHello {
		return nil, errors.New("not server hello")
	}
	body := hs.body

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
	var err error
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
			return nil, err
		}
	}
	return &serverHello{
		random:      serverRandom,
		cipherSuite: cipherSuite,
		publicKey:   serverECDHPubKey,
	}, nil
}
