package handshake

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"

	"github.com/arailly/mytls13/util"
	"github.com/google/go-cmp/cmp"
)

var (
	certsBody = []byte{
		0x00, 0x05, 0xd8, 0x30, 0x82, 0x05, 0xd4, 0x30,
		0x82, 0x04, 0xbc, 0xa0, 0x03, 0x02, 0x01, 0x02,
		0x02, 0x10, 0x07, 0x2e, 0xc5, 0x29, 0xc8, 0x76,
		0x10, 0x11, 0x62, 0xca, 0x0e, 0x45, 0x3c, 0xbd,
		0x45, 0x0a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
		0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
		0x00, 0x30, 0x46, 0x31, 0x0b, 0x30, 0x09, 0x06,
		0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
		0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
		0x0a, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f,
		0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
		0x04, 0x0b, 0x13, 0x0c, 0x53, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x43, 0x41, 0x20, 0x31, 0x42,
		0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f,
		0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x31,
		0x31, 0x30, 0x36, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x5a, 0x17, 0x0d, 0x32, 0x33, 0x31, 0x32,
		0x30, 0x35, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
		0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x06,
		0x03, 0x55, 0x04, 0x03, 0x13, 0x0e, 0x77, 0x77,
		0x77, 0x2e, 0x63, 0x79, 0x62, 0x6f, 0x7a, 0x75,
		0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22,
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
		0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
		0x02, 0x82, 0x01, 0x01, 0x00, 0xba, 0xae, 0x10,
		0x6b, 0xd9, 0x1a, 0xe3, 0x01, 0x57, 0xae, 0xaa,
		0xc9, 0x2d, 0x28, 0xe0, 0x41, 0x27, 0xb7, 0x9e,
		0xc3, 0x27, 0x18, 0x5c, 0x66, 0x3e, 0x13, 0x19,
		0x4f, 0x40, 0x88, 0x8e, 0xf4, 0xf9, 0x6e, 0x87,
		0xdf, 0x5e, 0x74, 0xaa, 0x7f, 0x5e, 0x12, 0x76,
		0xfc, 0xd6, 0x27, 0xd7, 0xfe, 0xb8, 0x88, 0x63,
		0xe3, 0x82, 0x05, 0x98, 0x6e, 0xd8, 0x4a, 0xb7,
		0x83, 0xeb, 0xe1, 0x48, 0x4f, 0xff, 0x2f, 0x02,
		0x5d, 0xd4, 0x9d, 0xd3, 0x98, 0xdd, 0x26, 0xa1,
		0x10, 0xb3, 0xb7, 0xfb, 0x73, 0x88, 0xb9, 0xa8,
		0x35, 0xcf, 0x61, 0x0b, 0xfc, 0xd6, 0xf9, 0xe3,
		0xf4, 0x6a, 0x13, 0xb0, 0x94, 0xd6, 0xd4, 0xf4,
		0x9d, 0x33, 0x6d, 0xe1, 0xad, 0x33, 0xe1, 0x43,
		0xe8, 0xa1, 0x1b, 0xe2, 0x9e, 0x8c, 0x78, 0x9e,
		0xdc, 0xdf, 0xfa, 0x2c, 0x51, 0x45, 0x34, 0x37,
		0xe2, 0x26, 0x45, 0x6c, 0xb3, 0x80, 0x58, 0xa0,
		0x9e, 0xdb, 0x15, 0x2e, 0xd1, 0x3b, 0x65, 0xbd,
		0xad, 0x98, 0xc7, 0x92, 0x91, 0x36, 0x96, 0x7b,
		0xcd, 0xe1, 0xd3, 0x75, 0xa2, 0x3e, 0xbf, 0x5b,
		0xb4, 0x68, 0x77, 0x2c, 0xaa, 0x2d, 0x73, 0x74,
		0xad, 0xa0, 0xf5, 0xf1, 0xe7, 0xcd, 0x82, 0x94,
		0xa0, 0x57, 0xfb, 0x84, 0x0e, 0x26, 0x65, 0x96,
		0xf8, 0x21, 0x21, 0x97, 0xd1, 0x6e, 0x99, 0x95,
		0x2d, 0xda, 0x36, 0x07, 0x20, 0x8a, 0x05, 0xb6,
		0x82, 0xba, 0x20, 0x22, 0xa4, 0x36, 0xdf, 0x45,
		0x09, 0x03, 0xfb, 0xe6, 0x47, 0xcf, 0x13, 0x0e,
		0x8a, 0x2d, 0xd4, 0x55, 0xbd, 0x79, 0x16, 0xca,
		0x4f, 0x78, 0x23, 0xec, 0x0f, 0x7a, 0x11, 0x31,
		0x3d, 0x71, 0x06, 0x1b, 0x76, 0xb5, 0xa1, 0xd9,
		0x48, 0x5e, 0x94, 0xe0, 0xf6, 0x82, 0x1e, 0x18,
		0x17, 0xab, 0x0d, 0xcd, 0xd2, 0x37, 0xe2, 0x8f,
		0xfe, 0xae, 0xa2, 0xc1, 0x23, 0x02, 0x03, 0x01,
		0x00, 0x01, 0xa3, 0x82, 0x02, 0xe9, 0x30, 0x82,
		0x02, 0xe5, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
		0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x59,
		0xa4, 0x66, 0x06, 0x52, 0xa0, 0x7b, 0x95, 0x92,
		0x3c, 0xa3, 0x94, 0x07, 0x27, 0x96, 0x74, 0x5b,
		0xf9, 0x3d, 0xd0, 0x30, 0x1d, 0x06, 0x03, 0x55,
		0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x5a, 0x91,
		0x05, 0x97, 0x0b, 0xb3, 0x88, 0x7f, 0xa9, 0x89,
		0x8b, 0xa3, 0x8e, 0x91, 0x31, 0x3a, 0xe2, 0x7a,
		0xc5, 0xb5, 0x30, 0x19, 0x06, 0x03, 0x55, 0x1d,
		0x11, 0x04, 0x12, 0x30, 0x10, 0x82, 0x0e, 0x77,
		0x77, 0x77, 0x2e, 0x63, 0x79, 0x62, 0x6f, 0x7a,
		0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0e, 0x06,
		0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
		0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06,
		0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x03, 0x02, 0x30, 0x3d, 0x06, 0x03,
		0x55, 0x1d, 0x1f, 0x04, 0x36, 0x30, 0x34, 0x30,
		0x32, 0xa0, 0x30, 0xa0, 0x2e, 0x86, 0x2c, 0x68,
		0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72,
		0x6c, 0x2e, 0x73, 0x63, 0x61, 0x31, 0x62, 0x2e,
		0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72,
		0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
		0x73, 0x63, 0x61, 0x31, 0x62, 0x2d, 0x31, 0x2e,
		0x63, 0x72, 0x6c, 0x30, 0x13, 0x06, 0x03, 0x55,
		0x1d, 0x20, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08,
		0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01,
		0x30, 0x75, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x01, 0x01, 0x04, 0x69, 0x30, 0x67,
		0x30, 0x2d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x30, 0x01, 0x86, 0x21, 0x68, 0x74,
		0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73,
		0x70, 0x2e, 0x73, 0x63, 0x61, 0x31, 0x62, 0x2e,
		0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72,
		0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
		0x36, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
		0x07, 0x30, 0x02, 0x86, 0x2a, 0x68, 0x74, 0x74,
		0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x74, 0x2e,
		0x73, 0x63, 0x61, 0x31, 0x62, 0x2e, 0x61, 0x6d,
		0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72, 0x75, 0x73,
		0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x63,
		0x61, 0x31, 0x62, 0x2e, 0x63, 0x72, 0x74, 0x30,
		0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
		0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x82, 0x01,
		0x7e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
		0xd6, 0x79, 0x02, 0x04, 0x02, 0x04, 0x82, 0x01,
		0x6e, 0x04, 0x82, 0x01, 0x6a, 0x01, 0x68, 0x00,
		0x76, 0x00, 0xe8, 0x3e, 0xd0, 0xda, 0x3e, 0xf5,
		0x06, 0x35, 0x32, 0xe7, 0x57, 0x28, 0xbc, 0x89,
		0x6b, 0xc9, 0x03, 0xd3, 0xcb, 0xd1, 0x11, 0x6b,
		0xec, 0xeb, 0x69, 0xe1, 0x77, 0x7d, 0x6d, 0x06,
		0xbd, 0x6e, 0x00, 0x00, 0x01, 0x84, 0x4b, 0x4b,
		0x89, 0x4c, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47,
		0x30, 0x45, 0x02, 0x21, 0x00, 0x85, 0x10, 0x8d,
		0x01, 0x78, 0xb8, 0x5d, 0x14, 0xfa, 0x90, 0x8a,
		0x27, 0xe2, 0x4e, 0x90, 0xde, 0x6a, 0x3b, 0x8f,
		0xb6, 0x92, 0x89, 0x30, 0xa7, 0x30, 0x0c, 0x44,
		0x2a, 0x60, 0xe0, 0xdb, 0xec, 0x02, 0x20, 0x5c,
		0x4f, 0x0f, 0xac, 0x05, 0xf4, 0x3d, 0x4c, 0x9a,
		0x03, 0x4f, 0x46, 0x5e, 0xcd, 0x53, 0x72, 0x16,
		0xc9, 0xaa, 0xd9, 0x6c, 0xa5, 0xa8, 0xb5, 0x43,
		0x59, 0x48, 0x88, 0xd0, 0xa2, 0xd5, 0xd8, 0x00,
		0x76, 0x00, 0xb3, 0x73, 0x77, 0x07, 0xe1, 0x84,
		0x50, 0xf8, 0x63, 0x86, 0xd6, 0x05, 0xa9, 0xdc,
		0x11, 0x09, 0x4a, 0x79, 0x2d, 0xb1, 0x67, 0x0c,
		0x0b, 0x87, 0xdc, 0xf0, 0x03, 0x0e, 0x79, 0x36,
		0xa5, 0x9a, 0x00, 0x00, 0x01, 0x84, 0x4b, 0x4b,
		0x89, 0x8a, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47,
		0x30, 0x45, 0x02, 0x20, 0x73, 0xf5, 0x40, 0x36,
		0xad, 0x17, 0xd4, 0xac, 0xff, 0x44, 0x12, 0x42,
		0xd4, 0xd8, 0xa4, 0x35, 0x51, 0x65, 0xea, 0x4d,
		0x89, 0x3d, 0xd2, 0x99, 0xdd, 0x9a, 0x77, 0x1b,
		0x83, 0xcf, 0xf5, 0x42, 0x02, 0x21, 0x00, 0xb9,
		0xfe, 0x1a, 0x36, 0x89, 0xea, 0x8e, 0x16, 0xe8,
		0x07, 0x1b, 0x39, 0xf3, 0xcd, 0x20, 0x47, 0x89,
		0x37, 0xea, 0x4e, 0xfe, 0x79, 0x8f, 0x02, 0xc8,
		0x9f, 0x9d, 0x60, 0x1b, 0x1e, 0xb3, 0x33, 0x00,
		0x76, 0x00, 0xb7, 0x3e, 0xfb, 0x24, 0xdf, 0x9c,
		0x4d, 0xba, 0x75, 0xf2, 0x39, 0xc5, 0xba, 0x58,
		0xf4, 0x6c, 0x5d, 0xfc, 0x42, 0xcf, 0x7a, 0x9f,
		0x35, 0xc4, 0x9e, 0x1d, 0x09, 0x81, 0x25, 0xed,
		0xb4, 0x99, 0x00, 0x00, 0x01, 0x84, 0x4b, 0x4b,
		0x89, 0x61, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47,
		0x30, 0x45, 0x02, 0x20, 0x7d, 0x39, 0x76, 0x85,
		0x7c, 0x97, 0x18, 0x22, 0x7f, 0x1d, 0xfc, 0x47,
		0x1a, 0x53, 0xa7, 0xc9, 0x0c, 0xfa, 0x2f, 0x95,
		0x3d, 0x4c, 0xe9, 0xb9, 0x34, 0xfe, 0xfd, 0xfa,
		0xcf, 0xcc, 0x08, 0x59, 0x02, 0x21, 0x00, 0xfd,
		0x9e, 0x37, 0xfb, 0xe5, 0x12, 0x9c, 0x81, 0x50,
		0x0a, 0x50, 0xa2, 0xb4, 0xc1, 0x7d, 0xb8, 0x4d,
		0xe6, 0xc8, 0xe4, 0xc4, 0x0c, 0x90, 0x17, 0x8d,
		0x9d, 0xaa, 0x98, 0x08, 0xd2, 0x85, 0xf4, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
		0x01, 0x01, 0x00, 0x8b, 0xc8, 0xe0, 0x99, 0x64,
		0x58, 0xeb, 0xcf, 0x50, 0x5b, 0xf6, 0xf1, 0x17,
		0x17, 0xb4, 0xf9, 0x32, 0xf5, 0x81, 0x91, 0xab,
		0x26, 0x1b, 0xd7, 0x80, 0x56, 0xb2, 0xa0, 0xa0,
		0x20, 0xa7, 0x53, 0x5e, 0x81, 0x3d, 0xba, 0xea,
		0x5b, 0x22, 0xf2, 0x7d, 0x10, 0x6b, 0xa3, 0xf5,
		0x6e, 0x46, 0x43, 0x49, 0x5a, 0x09, 0xd1, 0xa7,
		0x70, 0xcf, 0x92, 0x6e, 0x37, 0x64, 0xa2, 0x0f,
		0x9e, 0x3e, 0xa6, 0x53, 0x22, 0x12, 0x99, 0xf6,
		0x40, 0xfc, 0x59, 0xf3, 0x64, 0x55, 0x8e, 0x52,
		0x35, 0x49, 0x01, 0x72, 0x8b, 0xba, 0x1e, 0x54,
		0xcc, 0x75, 0x4c, 0x25, 0xe2, 0x1a, 0xf2, 0xda,
		0x41, 0x8c, 0x28, 0xd1, 0x0f, 0x8e, 0x64, 0x21,
		0xc2, 0x9b, 0x25, 0x77, 0xf1, 0x3d, 0xb9, 0x6a,
		0xbc, 0xd6, 0x2b, 0x6d, 0x29, 0x1d, 0x81, 0xb7,
		0xc3, 0xd5, 0x96, 0x94, 0xbd, 0xc3, 0xff, 0x5d,
		0x52, 0x87, 0x54, 0xeb, 0x3a, 0x62, 0x2d, 0x0d,
		0x1c, 0x8c, 0x40, 0xb1, 0x8e, 0x95, 0x1a, 0x6d,
		0xf3, 0xed, 0xc7, 0xdf, 0x19, 0x2e, 0x3c, 0xc7,
		0x43, 0xb3, 0xe1, 0xbc, 0x76, 0x37, 0x78, 0xd9,
		0x82, 0xd5, 0x2a, 0x4d, 0x1d, 0x65, 0xda, 0x5b,
		0x29, 0x83, 0x45, 0xa8, 0xf2, 0x82, 0x4b, 0xba,
		0xa0, 0xa8, 0x14, 0x62, 0xe5, 0xe5, 0xa3, 0x5b,
		0x5a, 0x2a, 0xff, 0x33, 0xf6, 0xcf, 0x98, 0xeb,
		0x18, 0xc8, 0x6f, 0xa4, 0xaf, 0x8b, 0x18, 0x72,
		0xe1, 0xfa, 0x53, 0x4b, 0x8a, 0x3d, 0x05, 0x3f,
		0x07, 0xff, 0xc7, 0x26, 0xed, 0x5a, 0x14, 0x3a,
		0x3b, 0x08, 0x1d, 0x7f, 0x9f, 0x9c, 0x85, 0x32,
		0xa6, 0x0a, 0x33, 0x24, 0x04, 0x4d, 0x10, 0x57,
		0x23, 0x45, 0x4e, 0x40, 0x22, 0x0c, 0x1c, 0x08,
		0x18, 0x81, 0x7f, 0xee, 0xb5, 0x50, 0x27, 0xbb,
		0x7e, 0x09, 0x66, 0xc8, 0x91, 0x1e, 0x86, 0x9f,
		0xcd, 0x06, 0xcc, 0x00, 0x04, 0x4d, 0x30, 0x82,
		0x04, 0x49, 0x30, 0x82, 0x03, 0x31, 0xa0, 0x03,
		0x02, 0x01, 0x02, 0x02, 0x13, 0x06, 0x7f, 0x94,
		0x57, 0x85, 0x87, 0xe8, 0xac, 0x77, 0xde, 0xb2,
		0x53, 0x32, 0x5b, 0xbc, 0x99, 0x8b, 0x56, 0x0d,
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
		0x39, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
		0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f,
		0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
		0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31,
		0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x13, 0x10, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e,
		0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41,
		0x20, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35,
		0x31, 0x30, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x31,
		0x30, 0x31, 0x39, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x5a, 0x30, 0x46, 0x31, 0x0b, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
		0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
		0x04, 0x0a, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a,
		0x6f, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
		0x55, 0x04, 0x0b, 0x13, 0x0c, 0x53, 0x65, 0x72,
		0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x20, 0x31,
		0x42, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a,
		0x6f, 0x6e, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
		0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
		0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
		0x01, 0x01, 0x00, 0xc2, 0x4e, 0x16, 0x67, 0xdd,
		0xce, 0xbc, 0x6a, 0xc8, 0x37, 0x5a, 0xec, 0x3a,
		0x30, 0xb0, 0x1d, 0xe6, 0xd1, 0x12, 0xe8, 0x12,
		0x28, 0x48, 0xcc, 0xe8, 0x29, 0xc1, 0xb9, 0x6e,
		0x53, 0xd5, 0xa3, 0xeb, 0x03, 0x39, 0x1a, 0xcc,
		0x77, 0x87, 0xf6, 0x01, 0xb9, 0xd9, 0x70, 0xcc,
		0xcf, 0x6b, 0x8d, 0xe3, 0xe3, 0x03, 0x71, 0x86,
		0x99, 0x6d, 0xcb, 0xa6, 0x94, 0x2a, 0x4e, 0x13,
		0xd6, 0xa7, 0xbd, 0x04, 0xec, 0x0a, 0x16, 0x3c,
		0x0a, 0xeb, 0x39, 0xb1, 0xc4, 0xb5, 0x58, 0xa3,
		0xb6, 0xc7, 0x56, 0x25, 0xec, 0x3e, 0x52, 0x7a,
		0xa8, 0xe3, 0x29, 0x16, 0x07, 0xb9, 0x6e, 0x50,
		0xcf, 0xfb, 0x5f, 0x31, 0xf8, 0x1d, 0xba, 0x03,
		0x4a, 0x62, 0x89, 0x03, 0xae, 0x3e, 0x47, 0xf2,
		0x0f, 0x27, 0x91, 0xe3, 0x14, 0x20, 0x85, 0xf8,
		0xfa, 0xe9, 0x8a, 0x35, 0xf5, 0x5f, 0x9e, 0x99,
		0x4d, 0xe7, 0x6b, 0x37, 0xef, 0xa4, 0x50, 0x3e,
		0x44, 0xec, 0xfa, 0x5a, 0x85, 0x66, 0x07, 0x9c,
		0x7e, 0x17, 0x6a, 0x55, 0xf3, 0x17, 0x8a, 0x35,
		0x1e, 0xee, 0xe9, 0xac, 0xc3, 0x75, 0x4e, 0x58,
		0x55, 0x7d, 0x53, 0x6b, 0x0a, 0x6b, 0x9b, 0x14,
		0x42, 0xd7, 0xe5, 0xac, 0x01, 0x89, 0xb3, 0xea,
		0xa3, 0xfe, 0xcf, 0xc0, 0x2b, 0x0c, 0x84, 0xc2,
		0xd8, 0x53, 0x15, 0xcb, 0x67, 0xf0, 0xd0, 0x88,
		0xca, 0x3a, 0xd1, 0x17, 0x73, 0xf5, 0x5f, 0x9a,
		0xd4, 0xc5, 0x72, 0x1e, 0x7e, 0x01, 0xf1, 0x98,
		0x30, 0x63, 0x2a, 0xaa, 0xf2, 0x7a, 0x2d, 0xc5,
		0xe2, 0x02, 0x1a, 0x86, 0xe5, 0x32, 0x3e, 0x0e,
		0xbd, 0x11, 0xb4, 0xcf, 0x3c, 0x93, 0xef, 0x17,
		0x50, 0x10, 0x9e, 0x43, 0xc2, 0x06, 0x2a, 0xe0,
		0x0d, 0x68, 0xbe, 0xd3, 0x88, 0x8b, 0x4a, 0x65,
		0x8c, 0x4a, 0xd4, 0xc3, 0x2e, 0x4c, 0x9b, 0x55,
		0xf4, 0x86, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01,
		0xa3, 0x82, 0x01, 0x3b, 0x30, 0x82, 0x01, 0x37,
		0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
		0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,
		0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03,
		0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
		0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06, 0x03,
		0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x59,
		0xa4, 0x66, 0x06, 0x52, 0xa0, 0x7b, 0x95, 0x92,
		0x3c, 0xa3, 0x94, 0x07, 0x27, 0x96, 0x74, 0x5b,
		0xf9, 0x3d, 0xd0, 0x30, 0x1f, 0x06, 0x03, 0x55,
		0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
		0x84, 0x18, 0xcc, 0x85, 0x34, 0xec, 0xbc, 0x0c,
		0x94, 0x94, 0x2e, 0x08, 0x59, 0x9c, 0xc7, 0xb2,
		0x10, 0x4e, 0x0a, 0x08, 0x30, 0x7b, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
		0x04, 0x6f, 0x30, 0x6d, 0x30, 0x2f, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
		0x86, 0x23, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
		0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x72, 0x6f,
		0x6f, 0x74, 0x63, 0x61, 0x31, 0x2e, 0x61, 0x6d,
		0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72, 0x75, 0x73,
		0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x3a, 0x06,
		0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
		0x02, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a,
		0x2f, 0x2f, 0x63, 0x72, 0x74, 0x2e, 0x72, 0x6f,
		0x6f, 0x74, 0x63, 0x61, 0x31, 0x2e, 0x61, 0x6d,
		0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72, 0x75, 0x73,
		0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x6f,
		0x6f, 0x74, 0x63, 0x61, 0x31, 0x2e, 0x63, 0x65,
		0x72, 0x30, 0x3f, 0x06, 0x03, 0x55, 0x1d, 0x1f,
		0x04, 0x38, 0x30, 0x36, 0x30, 0x34, 0xa0, 0x32,
		0xa0, 0x30, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x72,
		0x6f, 0x6f, 0x74, 0x63, 0x61, 0x31, 0x2e, 0x61,
		0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x74, 0x72, 0x75,
		0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x72,
		0x6f, 0x6f, 0x74, 0x63, 0x61, 0x31, 0x2e, 0x63,
		0x72, 0x6c, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d,
		0x20, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06,
		0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
		0x01, 0x01, 0x00, 0x85, 0x92, 0xbe, 0x35, 0xbb,
		0x79, 0xcf, 0xa3, 0x81, 0x42, 0x1c, 0xe4, 0xe3,
		0x63, 0x73, 0x53, 0x39, 0x52, 0x35, 0xe7, 0xd1,
		0xad, 0xfd, 0xae, 0x99, 0x8a, 0xac, 0x89, 0x12,
		0x2f, 0xbb, 0xe7, 0x6f, 0x9a, 0xd5, 0x4e, 0x72,
		0xea, 0x20, 0x30, 0x61, 0xf9, 0x97, 0xb2, 0xcd,
		0xa5, 0x27, 0x02, 0x45, 0xa8, 0xca, 0x76, 0x3e,
		0x98, 0x4a, 0x83, 0x9e, 0xb6, 0xe6, 0x45, 0xe0,
		0xf2, 0x43, 0xf6, 0x08, 0xde, 0x6d, 0xe8, 0x6e,
		0xdb, 0x31, 0x07, 0x13, 0xf0, 0x2f, 0x31, 0x0d,
		0x93, 0x6d, 0x61, 0x37, 0x7b, 0x58, 0xf0, 0xfc,
		0x51, 0x98, 0x91, 0x28, 0x02, 0x4f, 0x05, 0x76,
		0xb7, 0xd3, 0xf0, 0x1b, 0xc2, 0xe6, 0x5e, 0xd0,
		0x66, 0x85, 0x11, 0x0f, 0x2e, 0x81, 0xc6, 0x10,
		0x81, 0x29, 0xfe, 0x20, 0x60, 0x48, 0xf3, 0xf2,
		0xf0, 0x84, 0x13, 0x53, 0x65, 0x35, 0x15, 0x11,
		0x6b, 0x82, 0x51, 0x40, 0x55, 0x57, 0x5f, 0x18,
		0xb5, 0xb0, 0x22, 0x3e, 0xad, 0xf2, 0x5e, 0xa3,
		0x01, 0xe3, 0xc3, 0xb3, 0xf9, 0xcb, 0x41, 0x5a,
		0xe6, 0x52, 0x91, 0xbb, 0xe4, 0x36, 0x87, 0x4f,
		0x2d, 0xa9, 0xa4, 0x07, 0x68, 0x35, 0xba, 0x94,
		0x72, 0xcd, 0x0e, 0xea, 0x0e, 0x7d, 0x57, 0xf2,
		0x79, 0xfc, 0x37, 0xc5, 0x7b, 0x60, 0x9e, 0xb2,
		0xeb, 0xc0, 0x2d, 0x90, 0x77, 0x0d, 0x49, 0x10,
		0x27, 0xa5, 0x38, 0xad, 0xc4, 0x12, 0xa3, 0xb4,
		0xa3, 0xc8, 0x48, 0xb3, 0x15, 0x0b, 0x1e, 0xe2,
		0xe2, 0x19, 0xdc, 0xc4, 0x76, 0x52, 0xc8, 0xbc,
		0x8a, 0x41, 0x78, 0x70, 0xd9, 0x6d, 0x97, 0xb3,
		0x4a, 0x8b, 0x78, 0x2d, 0x5e, 0xb4, 0x0f, 0xa3,
		0x4c, 0x60, 0xca, 0xe1, 0x47, 0xcb, 0x78, 0x2d,
		0x12, 0x17, 0xb1, 0x52, 0x8b, 0xca, 0x39, 0x2c,
		0xbd, 0xb5, 0x2f, 0xc2, 0x33, 0x02, 0x96, 0xab,
		0xda, 0x94, 0x7f, 0x00, 0x04, 0x96, 0x30, 0x82,
		0x04, 0x92, 0x30, 0x82, 0x03, 0x7a, 0xa0, 0x03,
		0x02, 0x01, 0x02, 0x02, 0x13, 0x06, 0x7f, 0x94,
		0x4a, 0x2a, 0x27, 0xcd, 0xf3, 0xfa, 0xc2, 0xae,
		0x2b, 0x01, 0xf9, 0x08, 0xee, 0xb9, 0xc4, 0xc6,
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
		0x81, 0x98, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
		0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08,
		0x13, 0x07, 0x41, 0x72, 0x69, 0x7a, 0x6f, 0x6e,
		0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
		0x04, 0x07, 0x13, 0x0a, 0x53, 0x63, 0x6f, 0x74,
		0x74, 0x73, 0x64, 0x61, 0x6c, 0x65, 0x31, 0x25,
		0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
		0x1c, 0x53, 0x74, 0x61, 0x72, 0x66, 0x69, 0x65,
		0x6c, 0x64, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e,
		0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x2c,
		0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x3b, 0x30,
		0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32,
		0x53, 0x74, 0x61, 0x72, 0x66, 0x69, 0x65, 0x6c,
		0x64, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
		0x65, 0x73, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
		0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
		0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68,
		0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x2d, 0x20,
		0x47, 0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35,
		0x30, 0x35, 0x32, 0x35, 0x31, 0x32, 0x30, 0x30,
		0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x37, 0x31,
		0x32, 0x33, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
		0x30, 0x5a, 0x30, 0x39, 0x31, 0x0b, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
		0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
		0x04, 0x0a, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a,
		0x6f, 0x6e, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03,
		0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6d, 0x61,
		0x7a, 0x6f, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74,
		0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x82, 0x01,
		0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
		0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
		0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
		0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb2, 0x78,
		0x80, 0x71, 0xca, 0x78, 0xd5, 0xe3, 0x71, 0xaf,
		0x47, 0x80, 0x50, 0x74, 0x7d, 0x6e, 0xd8, 0xd7,
		0x88, 0x76, 0xf4, 0x99, 0x68, 0xf7, 0x58, 0x21,
		0x60, 0xf9, 0x74, 0x84, 0x01, 0x2f, 0xac, 0x02,
		0x2d, 0x86, 0xd3, 0xa0, 0x43, 0x7a, 0x4e, 0xb2,
		0xa4, 0xd0, 0x36, 0xba, 0x01, 0xbe, 0x8d, 0xdb,
		0x48, 0xc8, 0x07, 0x17, 0x36, 0x4c, 0xf4, 0xee,
		0x88, 0x23, 0xc7, 0x3e, 0xeb, 0x37, 0xf5, 0xb5,
		0x19, 0xf8, 0x49, 0x68, 0xb0, 0xde, 0xd7, 0xb9,
		0x76, 0x38, 0x1d, 0x61, 0x9e, 0xa4, 0xfe, 0x82,
		0x36, 0xa5, 0xe5, 0x4a, 0x56, 0xe4, 0x45, 0xe1,
		0xf9, 0xfd, 0xb4, 0x16, 0xfa, 0x74, 0xda, 0x9c,
		0x9b, 0x35, 0x39, 0x2f, 0xfa, 0xb0, 0x20, 0x50,
		0x06, 0x6c, 0x7a, 0xd0, 0x80, 0xb2, 0xa6, 0xf9,
		0xaf, 0xec, 0x47, 0x19, 0x8f, 0x50, 0x38, 0x07,
		0xdc, 0xa2, 0x87, 0x39, 0x58, 0xf8, 0xba, 0xd5,
		0xa9, 0xf9, 0x48, 0x67, 0x30, 0x96, 0xee, 0x94,
		0x78, 0x5e, 0x6f, 0x89, 0xa3, 0x51, 0xc0, 0x30,
		0x86, 0x66, 0xa1, 0x45, 0x66, 0xba, 0x54, 0xeb,
		0xa3, 0xc3, 0x91, 0xf9, 0x48, 0xdc, 0xff, 0xd1,
		0xe8, 0x30, 0x2d, 0x7d, 0x2d, 0x74, 0x70, 0x35,
		0xd7, 0x88, 0x24, 0xf7, 0x9e, 0xc4, 0x59, 0x6e,
		0xbb, 0x73, 0x87, 0x17, 0xf2, 0x32, 0x46, 0x28,
		0xb8, 0x43, 0xfa, 0xb7, 0x1d, 0xaa, 0xca, 0xb4,
		0xf2, 0x9f, 0x24, 0x0e, 0x2d, 0x4b, 0xf7, 0x71,
		0x5c, 0x5e, 0x69, 0xff, 0xea, 0x95, 0x02, 0xcb,
		0x38, 0x8a, 0xae, 0x50, 0x38, 0x6f, 0xdb, 0xfb,
		0x2d, 0x62, 0x1b, 0xc5, 0xc7, 0x1e, 0x54, 0xe1,
		0x77, 0xe0, 0x67, 0xc8, 0x0f, 0x9c, 0x87, 0x23,
		0xd6, 0x3f, 0x40, 0x20, 0x7f, 0x20, 0x80, 0xc4,
		0x80, 0x4c, 0x3e, 0x3b, 0x24, 0x26, 0x8e, 0x04,
		0xae, 0x6c, 0x9a, 0xc8, 0xaa, 0x0d, 0x02, 0x03,
		0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x31, 0x30,
		0x82, 0x01, 0x2d, 0x30, 0x0f, 0x06, 0x03, 0x55,
		0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
		0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03,
		0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
		0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06, 0x03,
		0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x84,
		0x18, 0xcc, 0x85, 0x34, 0xec, 0xbc, 0x0c, 0x94,
		0x94, 0x2e, 0x08, 0x59, 0x9c, 0xc7, 0xb2, 0x10,
		0x4e, 0x0a, 0x08, 0x30, 0x1f, 0x06, 0x03, 0x55,
		0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
		0x9c, 0x5f, 0x00, 0xdf, 0xaa, 0x01, 0xd7, 0x30,
		0x2b, 0x38, 0x88, 0xa2, 0xb8, 0x6d, 0x4a, 0x9c,
		0xf2, 0x11, 0x91, 0x83, 0x30, 0x78, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
		0x04, 0x6c, 0x30, 0x6a, 0x30, 0x2e, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
		0x86, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
		0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x72, 0x6f,
		0x6f, 0x74, 0x67, 0x32, 0x2e, 0x61, 0x6d, 0x61,
		0x7a, 0x6f, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74,
		0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x38, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02,
		0x86, 0x2c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
		0x2f, 0x63, 0x72, 0x74, 0x2e, 0x72, 0x6f, 0x6f,
		0x74, 0x67, 0x32, 0x2e, 0x61, 0x6d, 0x61, 0x7a,
		0x6f, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e,
		0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x6f, 0x6f, 0x74,
		0x67, 0x32, 0x2e, 0x63, 0x65, 0x72, 0x30, 0x3d,
		0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x36, 0x30,
		0x34, 0x30, 0x32, 0xa0, 0x30, 0xa0, 0x2e, 0x86,
		0x2c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
		0x63, 0x72, 0x6c, 0x2e, 0x72, 0x6f, 0x6f, 0x74,
		0x67, 0x32, 0x2e, 0x61, 0x6d, 0x61, 0x7a, 0x6f,
		0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x63,
		0x6f, 0x6d, 0x2f, 0x72, 0x6f, 0x6f, 0x74, 0x67,
		0x32, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x11, 0x06,
		0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08,
		0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00,
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,
		0x82, 0x01, 0x01, 0x00, 0x62, 0x37, 0x42, 0x5c,
		0xbc, 0x10, 0xb5, 0x3e, 0x8b, 0x2c, 0xe9, 0x0c,
		0x9b, 0x6c, 0x45, 0xe2, 0x07, 0x00, 0x7a, 0xf9,
		0xc5, 0x58, 0x0b, 0xb9, 0x08, 0x8c, 0x3e, 0xed,
		0xb3, 0x25, 0x3c, 0xb5, 0x6f, 0x50, 0xe4, 0xcd,
		0x35, 0x6a, 0xa7, 0x93, 0x34, 0x96, 0x32, 0x21,
		0xa9, 0x48, 0x44, 0xab, 0x9c, 0xed, 0x3d, 0xb4,
		0xaa, 0x73, 0x6d, 0xe4, 0x7f, 0x16, 0x80, 0x89,
		0x6c, 0xcf, 0x28, 0x03, 0x18, 0x83, 0x47, 0x79,
		0xa3, 0x10, 0x7e, 0x30, 0x5b, 0xac, 0x3b, 0xb0,
		0x60, 0xe0, 0x77, 0xd4, 0x08, 0xa6, 0xe1, 0x1d,
		0x7c, 0x5e, 0xc0, 0xbb, 0xf9, 0x9a, 0x7b, 0x22,
		0x9d, 0xa7, 0x00, 0x09, 0x7e, 0xac, 0x46, 0x17,
		0x83, 0xdc, 0x9c, 0x26, 0x57, 0x99, 0x30, 0x39,
		0x62, 0x96, 0x8f, 0xed, 0xda, 0xde, 0xaa, 0xc5,
		0xcc, 0x1b, 0x3e, 0xca, 0x43, 0x68, 0x6c, 0x57,
		0x16, 0xbc, 0xd5, 0x0e, 0x20, 0x2e, 0xfe, 0xff,
		0xc2, 0x6a, 0x5d, 0x2e, 0xa0, 0x4a, 0x6d, 0x14,
		0x58, 0x87, 0x94, 0xe6, 0x39, 0x31, 0x5f, 0x7c,
		0x73, 0xcb, 0x90, 0x88, 0x6a, 0x84, 0x11, 0x96,
		0x27, 0xa6, 0xed, 0xd9, 0x81, 0x46, 0xa6, 0x7e,
		0xa3, 0x72, 0x00, 0x0a, 0x52, 0x3e, 0x83, 0x88,
		0x07, 0x63, 0x77, 0x89, 0x69, 0x17, 0x0f, 0x39,
		0x85, 0xd2, 0xab, 0x08, 0x45, 0x4d, 0xd0, 0x51,
		0x3a, 0xfd, 0x5d, 0x5d, 0x37, 0x64, 0x4c, 0x7e,
		0x30, 0xb2, 0x55, 0x24, 0x42, 0x9d, 0x36, 0xb0,
		0x5d, 0x9c, 0x17, 0x81, 0x61, 0xf1, 0xca, 0xf9,
		0x10, 0x02, 0x24, 0xab, 0xeb, 0x0d, 0x74, 0x91,
		0x8d, 0x7b, 0x45, 0x29, 0x50, 0x39, 0x88, 0xb2,
		0xa6, 0x89, 0x35, 0x25, 0x1e, 0x14, 0x6a, 0x47,
		0x23, 0x31, 0x2f, 0x5c, 0x9a, 0xfa, 0xad, 0x9a,
		0x0e, 0x62, 0x51, 0xa4, 0x2a, 0xa9, 0xc4, 0xf9,
		0x34, 0x9d, 0x21, 0x18, 0x00, 0x04, 0x79, 0x30,
		0x82, 0x04, 0x75, 0x30, 0x82, 0x03, 0x5d, 0xa0,
		0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xa7,
		0x0e, 0x4a, 0x4c, 0x34, 0x82, 0xb7, 0x7f, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x68,
		0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
		0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x25, 0x30,
		0x23, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x1c,
		0x53, 0x74, 0x61, 0x72, 0x66, 0x69, 0x65, 0x6c,
		0x64, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f,
		0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x2c, 0x20,
		0x49, 0x6e, 0x63, 0x2e, 0x31, 0x32, 0x30, 0x30,
		0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x29, 0x53,
		0x74, 0x61, 0x72, 0x66, 0x69, 0x65, 0x6c, 0x64,
		0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x32,
		0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41,
		0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,
		0x30, 0x1e, 0x17, 0x0d, 0x30, 0x39, 0x30, 0x39,
		0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x5a, 0x17, 0x0d, 0x33, 0x34, 0x30, 0x36, 0x32,
		0x38, 0x31, 0x37, 0x33, 0x39, 0x31, 0x36, 0x5a,
		0x30, 0x81, 0x98, 0x31, 0x0b, 0x30, 0x09, 0x06,
		0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
		0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
		0x08, 0x13, 0x07, 0x41, 0x72, 0x69, 0x7a, 0x6f,
		0x6e, 0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
		0x55, 0x04, 0x07, 0x13, 0x0a, 0x53, 0x63, 0x6f,
		0x74, 0x74, 0x73, 0x64, 0x61, 0x6c, 0x65, 0x31,
		0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0a,
		0x13, 0x1c, 0x53, 0x74, 0x61, 0x72, 0x66, 0x69,
		0x65, 0x6c, 0x64, 0x20, 0x54, 0x65, 0x63, 0x68,
		0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73,
		0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x3b,
		0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
		0x32, 0x53, 0x74, 0x61, 0x72, 0x66, 0x69, 0x65,
		0x6c, 0x64, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69,
		0x63, 0x65, 0x73, 0x20, 0x52, 0x6f, 0x6f, 0x74,
		0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
		0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74,
		0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x2d,
		0x20, 0x47, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
		0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
		0x82, 0x01, 0x01, 0x00, 0xd5, 0x0c, 0x3a, 0xc4,
		0x2a, 0xf9, 0x4e, 0xe2, 0xf5, 0xbe, 0x19, 0x97,
		0x5f, 0x8e, 0x88, 0x53, 0xb1, 0x1f, 0x3f, 0xcb,
		0xcf, 0x9f, 0x20, 0x13, 0x6d, 0x29, 0x3a, 0xc8,
		0x0f, 0x7d, 0x3c, 0xf7, 0x6b, 0x76, 0x38, 0x63,
		0xd9, 0x36, 0x60, 0xa8, 0x9b, 0x5e, 0x5c, 0x00,
		0x80, 0xb2, 0x2f, 0x59, 0x7f, 0xf6, 0x87, 0xf9,
		0x25, 0x43, 0x86, 0xe7, 0x69, 0x1b, 0x52, 0x9a,
		0x90, 0xe1, 0x71, 0xe3, 0xd8, 0x2d, 0x0d, 0x4e,
		0x6f, 0xf6, 0xc8, 0x49, 0xd9, 0xb6, 0xf3, 0x1a,
		0x56, 0xae, 0x2b, 0xb6, 0x74, 0x14, 0xeb, 0xcf,
		0xfb, 0x26, 0xe3, 0x1a, 0xba, 0x1d, 0x96, 0x2e,
		0x6a, 0x3b, 0x58, 0x94, 0x89, 0x47, 0x56, 0xff,
		0x25, 0xa0, 0x93, 0x70, 0x53, 0x83, 0xda, 0x84,
		0x74, 0x14, 0xc3, 0x67, 0x9e, 0x04, 0x68, 0x3a,
		0xdf, 0x8e, 0x40, 0x5a, 0x1d, 0x4a, 0x4e, 0xcf,
		0x43, 0x91, 0x3b, 0xe7, 0x56, 0xd6, 0x00, 0x70,
		0xcb, 0x52, 0xee, 0x7b, 0x7d, 0xae, 0x3a, 0xe7,
		0xbc, 0x31, 0xf9, 0x45, 0xf6, 0xc2, 0x60, 0xcf,
		0x13, 0x59, 0x02, 0x2b, 0x80, 0xcc, 0x34, 0x47,
		0xdf, 0xb9, 0xde, 0x90, 0x65, 0x6d, 0x02, 0xcf,
		0x2c, 0x91, 0xa6, 0xa6, 0xe7, 0xde, 0x85, 0x18,
		0x49, 0x7c, 0x66, 0x4e, 0xa3, 0x3a, 0x6d, 0xa9,
		0xb5, 0xee, 0x34, 0x2e, 0xba, 0x0d, 0x03, 0xb8,
		0x33, 0xdf, 0x47, 0xeb, 0xb1, 0x6b, 0x8d, 0x25,
		0xd9, 0x9b, 0xce, 0x81, 0xd1, 0x45, 0x46, 0x32,
		0x96, 0x70, 0x87, 0xde, 0x02, 0x0e, 0x49, 0x43,
		0x85, 0xb6, 0x6c, 0x73, 0xbb, 0x64, 0xea, 0x61,
		0x41, 0xac, 0xc9, 0xd4, 0x54, 0xdf, 0x87, 0x2f,
		0xc7, 0x22, 0xb2, 0x26, 0xcc, 0x9f, 0x59, 0x54,
		0x68, 0x9f, 0xfc, 0xbe, 0x2a, 0x2f, 0xc4, 0x55,
		0x1c, 0x75, 0x40, 0x60, 0x17, 0x85, 0x02, 0x55,
		0x39, 0x8b, 0x7f, 0x05, 0x02, 0x03, 0x01, 0x00,
		0x01, 0xa3, 0x81, 0xf0, 0x30, 0x81, 0xed, 0x30,
		0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
		0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
		0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
		0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86,
		0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
		0x16, 0x04, 0x14, 0x9c, 0x5f, 0x00, 0xdf, 0xaa,
		0x01, 0xd7, 0x30, 0x2b, 0x38, 0x88, 0xa2, 0xb8,
		0x6d, 0x4a, 0x9c, 0xf2, 0x11, 0x91, 0x83, 0x30,
		0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
		0x30, 0x16, 0x80, 0x14, 0xbf, 0x5f, 0xb7, 0xd1,
		0xce, 0xdd, 0x1f, 0x86, 0xf4, 0x5b, 0x55, 0xac,
		0xdc, 0xd7, 0x10, 0xc2, 0x0e, 0xa9, 0x88, 0xe7,
		0x30, 0x4f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x01, 0x01, 0x04, 0x43, 0x30, 0x41,
		0x30, 0x1c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x30, 0x01, 0x86, 0x10, 0x68, 0x74,
		0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x2e, 0x73,
		0x73, 0x32, 0x2e, 0x75, 0x73, 0x2f, 0x30, 0x21,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x30, 0x02, 0x86, 0x15, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x78, 0x2e, 0x73, 0x73, 0x32,
		0x2e, 0x75, 0x73, 0x2f, 0x78, 0x2e, 0x63, 0x65,
		0x72, 0x30, 0x26, 0x06, 0x03, 0x55, 0x1d, 0x1f,
		0x04, 0x1f, 0x30, 0x1d, 0x30, 0x1b, 0xa0, 0x19,
		0xa0, 0x17, 0x86, 0x15, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x73, 0x2e, 0x73, 0x73, 0x32,
		0x2e, 0x75, 0x73, 0x2f, 0x72, 0x2e, 0x63, 0x72,
		0x6c, 0x30, 0x11, 0x06, 0x03, 0x55, 0x1d, 0x20,
		0x04, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04,
		0x55, 0x1d, 0x20, 0x00, 0x30, 0x0d, 0x06, 0x09,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
		0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
		0x23, 0x1d, 0xe3, 0x8a, 0x57, 0xca, 0x7d, 0xe9,
		0x17, 0x79, 0x4c, 0xf1, 0x1e, 0x55, 0xfd, 0xcc,
		0x53, 0x6e, 0x3e, 0x47, 0x0f, 0xdf, 0xc6, 0x55,
		0xf2, 0xb2, 0x04, 0x36, 0xed, 0x80, 0x1f, 0x53,
		0xc4, 0x5d, 0x34, 0x28, 0x6b, 0xbe, 0xc7, 0x55,
		0xfc, 0x67, 0xea, 0xcb, 0x3f, 0x7f, 0x90, 0xb2,
		0x33, 0xcd, 0x1b, 0x58, 0x10, 0x82, 0x02, 0xf8,
		0xf8, 0x2f, 0xf5, 0x13, 0x60, 0xd4, 0x05, 0xce,
		0xf1, 0x81, 0x08, 0xc1, 0xdd, 0xa7, 0x75, 0x97,
		0x4f, 0x18, 0xb9, 0x6d, 0xde, 0xf7, 0x93, 0x91,
		0x08, 0xba, 0x7e, 0x40, 0x2c, 0xed, 0xc1, 0xea,
		0xbb, 0x76, 0x9e, 0x33, 0x06, 0x77, 0x1d, 0x0d,
		0x08, 0x7f, 0x53, 0xdd, 0x1b, 0x64, 0xab, 0x82,
		0x27, 0xf1, 0x69, 0xd5, 0x4d, 0x5e, 0xae, 0xf4,
		0xa1, 0xc3, 0x75, 0xa7, 0x58, 0x44, 0x2d, 0xf2,
		0x3c, 0x70, 0x98, 0xac, 0xba, 0x69, 0xb6, 0x95,
		0x77, 0x7f, 0x0f, 0x31, 0x5e, 0x2c, 0xfc, 0xa0,
		0x87, 0x3a, 0x47, 0x69, 0xf0, 0x79, 0x5f, 0xf4,
		0x14, 0x54, 0xa4, 0x95, 0x5e, 0x11, 0x78, 0x12,
		0x60, 0x27, 0xce, 0x9f, 0xc2, 0x77, 0xff, 0x23,
		0x53, 0x77, 0x5d, 0xba, 0xff, 0xea, 0x59, 0xe7,
		0xdb, 0xcf, 0xaf, 0x92, 0x96, 0xef, 0x24, 0x9a,
		0x35, 0x10, 0x7a, 0x9c, 0x91, 0xc6, 0x0e, 0x7d,
		0x99, 0xf6, 0x3f, 0x19, 0xdf, 0xf5, 0x72, 0x54,
		0xe1, 0x15, 0xa9, 0x07, 0x59, 0x7b, 0x83, 0xbf,
		0x52, 0x2e, 0x46, 0x8c, 0xb2, 0x00, 0x64, 0x76,
		0x1c, 0x48, 0xd3, 0xd8, 0x79, 0xe8, 0x6e, 0x56,
		0xcc, 0xae, 0x2c, 0x03, 0x90, 0xd7, 0x19, 0x38,
		0x99, 0xe4, 0xca, 0x09, 0x19, 0x5b, 0xff, 0x07,
		0x96, 0xb0, 0xa8, 0x7f, 0x34, 0x49, 0xdf, 0x56,
		0xa9, 0xf7, 0xb0, 0x5f, 0xed, 0x33, 0xed, 0x8c,
		0x47, 0xb7, 0x30, 0x03, 0x5d, 0xf4, 0x03, 0x8c,
	}
	certsLen    = util.NewUint24(uint32(len(certsBody)))
	certsHeader = append(certsLen[:], 0)
	certMsgBody = append(certsHeader, certsBody...)
	certMsg     = newHandshake(handshakeTypeCertificate, certMsgBody)
)

func TestSignature(t *testing.T) {
	cert, err := util.LoadCertificate("../config/server.der")
	if err != nil {
		t.Fatal(err)
	}
	caKeyPair, err := tls.LoadX509KeyPair(
		"../config/ca.pem",
		"../config/ca-key.pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	cacert, err := x509.ParseCertificate(caKeyPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256(cert.RawTBSCertificate)
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		caKeyPair.PrivateKey.(*rsa.PrivateKey),
		crypto.SHA256,
		hashed[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	diff := cmp.Diff(cert.Signature, signature)
	if diff != "" {
		t.Error(diff)
	}

	err = rsa.VerifyPKCS1v15(
		cacert.PublicKey.(*rsa.PublicKey),
		crypto.SHA256,
		hashed[:],
		signature,
	)
	if err != nil {
		t.Error(err)
	}
}

func TestParseCertificates(t *testing.T) {
	certs, err := parseCertificates(certMsg)
	if err != nil {
		t.Error(certs)
	}
	if len(certs) != 4 {
		t.Error(len(certs))
	}
}

func TestVerifySignature(t *testing.T) {
	cert, err := util.LoadCertificate("../config/server.der")
	if err != nil {
		t.Fatal(err)
	}
	cacertBytes, err := os.ReadFile("../config/ca.der")
	if err != nil {
		t.Fatal(err)
	}
	cacert, err := x509.ParseCertificate(cacertBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyCertificateSignature(cert, cacert)
	if err != nil {
		t.Error(err)
	}
}

func TestVerifyChain(t *testing.T) {
	certs, err := parseCertificates(certMsg)
	if err != nil {
		t.Error(certs)
	}
	cacert, err := util.LoadCertificate(
		"../config/Starfield Services Root Certificate Authority - G2.der",
	)
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := []*x509.Certificate{cacert}
	err = verifyCertificateChain(
		"www.cybozu.com",
		certs,
		rootCAs,
	)
	if err != nil {
		t.Error(err)
	}
}
