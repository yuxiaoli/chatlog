package model

import (
	"encoding/binary"
	"reflect"
	"strconv"
	"testing"
	"unicode/utf16"
)

func TestParseContactExtraBuf(t *testing.T) {
	raw := appendExtraBufFixed(nil, [4]byte{0x00, 0x00, 0x00, 0x01}, extraBufTypeByte, []byte{7})
	raw = appendExtraBufUTF16(raw, extraBufSignatureID, "碰巧遇到你 🌏")
	raw = appendExtraBufFixed(raw, [4]byte{0x00, 0x00, 0x00, 0x02}, extraBufTypeInt64, make([]byte, 8))
	// Unknown fields are skipped structurally; their payload encoding must not
	// invalidate profile fields that this exporter understands.
	raw = appendExtraBufLengthValue(raw, [4]byte{0x00, 0x00, 0x00, 0x03}, extraBufTypeUTF8, []byte{0xff})
	raw = appendExtraBufLengthValue(raw, [4]byte{0x00, 0x00, 0x00, 0x04}, extraBufTypeUTF16LE, []byte{0x01})
	raw = appendExtraBufFixed(raw, extraBufAddSceneID, extraBufTypeInt32, []byte{30, 0, 0, 0})
	raw = appendExtraBufUTF16(raw, extraBufCountryID, "HK")
	raw = appendExtraBufUTF16(raw, extraBufProvinceID, "Kowloon")
	raw = appendExtraBufUTF16(raw, extraBufCityID, "Yau Tsim Mong")

	got, ok := parseContactExtraBuf(raw)
	if !ok {
		t.Fatal("parseContactExtraBuf() rejected a valid stream")
	}
	if got.Signature != "碰巧遇到你 🌏" || got.Country != "HK" || got.Province != "Kowloon" || got.City != "Yau Tsim Mong" {
		t.Fatalf("parseContactExtraBuf() = %#v", got)
	}
	if got.AddScene == nil || *got.AddScene != 30 {
		t.Fatalf("AddScene = %v, want 30", got.AddScene)
	}
}

func TestParseContactExtraBufPreservesZeroAndUnknownAddSceneCodes(t *testing.T) {
	for _, want := range []int32{0, -17, 251} {
		t.Run(strconv.FormatInt(int64(want), 10), func(t *testing.T) {
			value := make([]byte, 4)
			binary.LittleEndian.PutUint32(value, uint32(want))
			raw := appendExtraBufFixed(nil, extraBufAddSceneID, extraBufTypeInt32, value)
			got, ok := parseContactExtraBuf(raw)
			if !ok || got.AddScene == nil || *got.AddScene != want {
				t.Fatalf("parseContactExtraBuf() = %#v, %v; want AddScene %d", got, ok, want)
			}
		})
	}
}

func TestParseContactExtraBufRejectsMalformedStreams(t *testing.T) {
	validSignature := appendExtraBufUTF16(nil, extraBufSignatureID, "must be discarded")
	tests := map[string][]byte{
		"truncated header":       {1, 2, 3, 4},
		"unknown type":           append(validSignature, 1, 2, 3, 4, 0xff),
		"truncated fixed value":  append(validSignature, 1, 2, 3, 4, extraBufTypeInt64, 0),
		"truncated length":       append(validSignature, 1, 2, 3, 4, extraBufTypeUTF16LE, 1),
		"oversized value":        append(validSignature, 1, 2, 3, 4, extraBufTypeUTF8, 9, 0, 0, 0, 'x'),
		"odd UTF-16 length":      appendExtraBufLengthValue(nil, extraBufCountryID, extraBufTypeUTF16LE, []byte{1}),
		"unpaired UTF-16":        appendExtraBufLengthValue(nil, extraBufCityID, extraBufTypeUTF16LE, []byte{0x00, 0xd8}),
		"wrong known field type": appendExtraBufLengthValue(nil, extraBufSignatureID, extraBufTypeUTF8, []byte("text")),
		"duplicate known field":  append(validSignature, validSignature...),
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parseContactExtraBuf(raw)
			if ok || !reflect.DeepEqual(got, contactExtraProfile{}) {
				t.Fatalf("parseContactExtraBuf() = %#v, %v; want empty, false", got, ok)
			}
			contact := (&ContactV3{UserName: "wxid_kept", ExtraBuf: raw}).Wrap()
			if contact.UserName != "wxid_kept" || contact.Signature != "" || contact.AddScene != nil || contact.Country != "" || contact.Province != "" || contact.City != "" {
				t.Fatalf("malformed ExtraBuf did not fail soft: %#v", contact)
			}
		})
	}
}

func TestParseContactExtraBufAcceptsEmptyStream(t *testing.T) {
	got, ok := parseContactExtraBuf(nil)
	if !ok || !reflect.DeepEqual(got, contactExtraProfile{}) {
		t.Fatalf("parseContactExtraBuf(nil) = %#v, %v; want empty, true", got, ok)
	}
}

func appendExtraBufUTF16(dst []byte, id [4]byte, value string) []byte {
	units := utf16.Encode([]rune(value))
	units = append(units, 0)
	payload := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(payload[i*2:i*2+2], unit)
	}
	return appendExtraBufLengthValue(dst, id, extraBufTypeUTF16LE, payload)
}

func appendExtraBufLengthValue(dst []byte, id [4]byte, fieldType byte, value []byte) []byte {
	dst = append(dst, id[:]...)
	dst = append(dst, fieldType)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(value)))
	dst = append(dst, length...)
	return append(dst, value...)
}

func appendExtraBufFixed(dst []byte, id [4]byte, fieldType byte, value []byte) []byte {
	dst = append(dst, id[:]...)
	dst = append(dst, fieldType)
	return append(dst, value...)
}
