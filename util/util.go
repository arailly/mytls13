package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
)

func NewRand() io.Reader {
	return rand.Reader
}

type constRand struct{}

func (r *constRand) Read(p []byte) (n int, err error) {
	return 1, nil
}

func NewConstRand() io.Reader {
	return &constRand{}
}

func ToUint16(data []byte) uint16 {
	return uint16(data[0])*256 + uint16(data[1])
}

type Uint24 []byte

func NewUint24(a uint32) Uint24 {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, a)
	return buf[1:]
}

func (u *Uint24) Int() int {
	b := []byte(*u)
	return int(b[0])*256*256 + int(b[1])*256 + int(b[2])
}

func ToBytes(data any) []byte {
	return toBytes(reflect.ValueOf(data))
}

func toBytes(v reflect.Value) []byte {
	// call Bytes() if the type implements Bytes() []byte
	if bytesFunc := v.MethodByName("Bytes"); bytesFunc.IsValid() {
		return bytesFunc.Call(nil)[0].Bytes()
	}

	buf := make([]byte, 0)
	switch v.Kind() {
	case reflect.Uint8:
		buf = append(buf, uint8(v.Uint()))
	case reflect.Uint16:
		buf = make([]byte, 2)
		binary.BigEndian.PutUint16(buf[0:], uint16(v.Uint()))
	case reflect.Uint32:
		buf = make([]byte, 4)
		binary.BigEndian.PutUint32(buf[0:], uint32(v.Uint()))
	case reflect.Uint64:
		buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf[0:], uint64(v.Uint()))
	case reflect.Slice:
		switch v.Type().Elem().Kind() {
		case reflect.Uint8:
			buf = append(buf, v.Bytes()...)
		default:
			for i := 0; i < v.Len(); i++ {
				buf = append(buf, toBytes(v.Index(i))...)
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			buf = append(buf, toBytes(v.Index(i))...)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			buf = append(buf, toBytes(v.Field(i))...)
		}
	case reflect.Pointer:
		buf = append(buf, toBytes(v.Elem())...)
	default:
		panic(fmt.Sprintf("unexpected type: %s", v.Kind()))
	}
	return buf
}

func LoadCertificate(derFilePath string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(derFilePath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func LoadPrivateKey(derFilePath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(derFilePath)
	if err != nil {
		return nil, err
	}
	privKey, err := x509.ParsePKCS1PrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}
