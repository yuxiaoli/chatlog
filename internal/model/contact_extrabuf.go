package model

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	extraBufTypeByte    = 0x02
	extraBufTypeInt32   = 0x04
	extraBufTypeInt64   = 0x05
	extraBufTypeUTF8    = 0x17
	extraBufTypeUTF16LE = 0x18
)

var (
	extraBufSignatureID = [4]byte{0x46, 0xcf, 0x10, 0xc4}
	extraBufAddSceneID  = [4]byte{0x4d, 0x6c, 0x45, 0x70}
	extraBufCountryID   = [4]byte{0xa4, 0xd9, 0x02, 0x4a}
	extraBufProvinceID  = [4]byte{0xe2, 0xea, 0xa8, 0xd1}
	extraBufCityID      = [4]byte{0x1d, 0x02, 0x5b, 0xbf}
)

type contactExtraProfile struct {
	Signature string
	AddScene  *int32
	Country   string
	Province  string
	City      string
}

// parseContactExtraBuf decodes the sequential Windows v3 ExtraBuf TLV stream.
// Unknown field IDs are skipped according to their type, while an unknown type
// or any malformed record invalidates the profile. Callers deliberately treat
// that as an empty profile so a damaged blob cannot prevent contact export.
func parseContactExtraBuf(raw []byte) (contactExtraProfile, bool) {
	var profile contactExtraProfile
	seen := make(map[[4]byte]struct{}, 5)
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < 5 {
			return contactExtraProfile{}, false
		}

		var id [4]byte
		copy(id[:], raw[offset:offset+4])
		fieldType := raw[offset+4]
		offset += 5

		var value []byte
		switch fieldType {
		case extraBufTypeByte:
			if len(raw)-offset < 1 {
				return contactExtraProfile{}, false
			}
			value = raw[offset : offset+1]
			offset++
		case extraBufTypeInt32:
			if len(raw)-offset < 4 {
				return contactExtraProfile{}, false
			}
			value = raw[offset : offset+4]
			offset += 4
		case extraBufTypeInt64:
			if len(raw)-offset < 8 {
				return contactExtraProfile{}, false
			}
			value = raw[offset : offset+8]
			offset += 8
		case extraBufTypeUTF8, extraBufTypeUTF16LE:
			if len(raw)-offset < 4 {
				return contactExtraProfile{}, false
			}
			length := binary.LittleEndian.Uint32(raw[offset : offset+4])
			offset += 4
			if uint64(length) > uint64(len(raw)-offset) {
				return contactExtraProfile{}, false
			}
			value = raw[offset : offset+int(length)]
			offset += int(length)
		default:
			return contactExtraProfile{}, false
		}

		switch id {
		case extraBufSignatureID:
			if _, duplicate := seen[id]; duplicate {
				return contactExtraProfile{}, false
			}
			seen[id] = struct{}{}
			if fieldType != extraBufTypeUTF16LE {
				return contactExtraProfile{}, false
			}
			var ok bool
			profile.Signature, ok = decodeUTF16LE(value)
			if !ok {
				return contactExtraProfile{}, false
			}
		case extraBufAddSceneID:
			if _, duplicate := seen[id]; duplicate {
				return contactExtraProfile{}, false
			}
			seen[id] = struct{}{}
			if fieldType != extraBufTypeInt32 {
				return contactExtraProfile{}, false
			}
			addScene := int32(binary.LittleEndian.Uint32(value))
			profile.AddScene = &addScene
		case extraBufCountryID:
			if _, duplicate := seen[id]; duplicate {
				return contactExtraProfile{}, false
			}
			seen[id] = struct{}{}
			if fieldType != extraBufTypeUTF16LE {
				return contactExtraProfile{}, false
			}
			var ok bool
			profile.Country, ok = decodeUTF16LE(value)
			if !ok {
				return contactExtraProfile{}, false
			}
		case extraBufProvinceID:
			if _, duplicate := seen[id]; duplicate {
				return contactExtraProfile{}, false
			}
			seen[id] = struct{}{}
			if fieldType != extraBufTypeUTF16LE {
				return contactExtraProfile{}, false
			}
			var ok bool
			profile.Province, ok = decodeUTF16LE(value)
			if !ok {
				return contactExtraProfile{}, false
			}
		case extraBufCityID:
			if _, duplicate := seen[id]; duplicate {
				return contactExtraProfile{}, false
			}
			seen[id] = struct{}{}
			if fieldType != extraBufTypeUTF16LE {
				return contactExtraProfile{}, false
			}
			var ok bool
			profile.City, ok = decodeUTF16LE(value)
			if !ok {
				return contactExtraProfile{}, false
			}
		}
	}

	return profile, true
}

func decodeUTF16LE(value []byte) (string, bool) {
	if len(value)%2 != 0 {
		return "", false
	}

	codeUnits := make([]uint16, len(value)/2)
	for i := range codeUnits {
		codeUnits[i] = binary.LittleEndian.Uint16(value[i*2 : i*2+2])
	}
	for len(codeUnits) > 0 && codeUnits[len(codeUnits)-1] == 0 {
		codeUnits = codeUnits[:len(codeUnits)-1]
	}
	for i := 0; i < len(codeUnits); i++ {
		switch {
		case 0xd800 <= codeUnits[i] && codeUnits[i] <= 0xdbff:
			if i+1 >= len(codeUnits) || codeUnits[i+1] < 0xdc00 || codeUnits[i+1] > 0xdfff {
				return "", false
			}
			i++
		case 0xdc00 <= codeUnits[i] && codeUnits[i] <= 0xdfff:
			return "", false
		}
	}

	return string(utf16.Decode(codeUnits)), true
}
