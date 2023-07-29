package record

const (
	contentTypeInvalid          uint8 = 0
	contentTypeChangeCipherSpec uint8 = 20
	contentTypeAlert            uint8 = 21
	contentTypeApplicationData  uint8 = 23

	ProtocolVersionTLS10 uint16 = 0x0301
	ProtocolVersionTLS12 uint16 = 0x0303
)

type tlsPlainText struct {
	contentType uint8
	version     uint16
	length      uint16
	fragment    []byte
}

func newTLSPlainText(
	contentType uint8,
	fragment []byte,
) *tlsPlainText {
	return &tlsPlainText{
		contentType: contentType,
		version:     ProtocolVersionTLS12,
		length:      uint16(len(fragment)),
		fragment:    fragment,
	}
}
