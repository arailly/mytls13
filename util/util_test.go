package util_test

import (
	"testing"

	"github.com/arailly/mytls13/util"
	"github.com/google/go-cmp/cmp"
)

func TestUint24(t *testing.T) {
	actual := util.ToBytes(util.NewUint24(uint32(1023)))
	expected := []byte{0, 3, 255}
	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Errorf("bytes mismatch: %s", diff)
	}
}

func TestToBytes(t *testing.T) {
	var sampleByte uint8 = 0x88
	sampleStruct := struct {
		first   uint8
		second  uint16
		third   uint32
		forth   uint64
		fifth   []byte
		sixth   [3]byte
		seventh struct {
			seventh1 uint8
			seventh2 uint16
		}
		eighth *uint8
	}{
		first:  0x11,
		second: 0x2222,
		third:  0x33333333,
		forth:  0x4444444444444444,
		fifth:  []byte{0x55, 0x55},
		sixth:  [3]byte{0x66, 0x66, 0x66},
		seventh: struct {
			seventh1 uint8
			seventh2 uint16
		}{
			seventh1: 0x77,
			seventh2: 0x7777,
		},
		eighth: &sampleByte,
	}
	actual := util.ToBytes(sampleStruct)
	expected := []byte{
		0x11,
		0x22, 0x22,
		0x33, 0x33, 0x33, 0x33,
		0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		0x55, 0x55,
		0x66, 0x66, 0x66,
		0x77, 0x77, 0x77,
		0x88,
	}
	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Error(diff)
	}
}
