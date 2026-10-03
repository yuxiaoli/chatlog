package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContactV3WrapKeepsRemarkSeparateFromDescription(t *testing.T) {
	extraBuf := appendExtraBufUTF16(nil, extraBufSignatureID, "碰巧遇到你")
	extraBuf = appendExtraBufFixed(extraBuf, extraBufAddSceneID, extraBufTypeInt32, []byte{30, 0, 0, 0})
	extraBuf = appendExtraBufUTF16(extraBuf, extraBufCountryID, "HK")
	extraBuf = appendExtraBufUTF16(extraBuf, extraBufProvinceID, "Kowloon")
	extraBuf = appendExtraBufUTF16(extraBuf, extraBufCityID, "Yau Tsim Mong")
	raw := &ContactV3{
		UserName:    "wxid_xiaorui",
		Alias:       "xiaoruizhao-",
		Remark:      "无理取闹的大瑞",
		NickName:    "晓晓",
		Reserved1:   1,
		Reserved6:   "生日：阴历1994年11月18日（冬月18）",
		LabelIDList: "3, 5,999",
		ExtraBuf:    extraBuf,
	}

	contact := raw.WrapWithLabelNames(map[string]string{
		"3": "Shanghai",
		"5": "Family",
	})
	if contact.Remark != raw.Remark {
		t.Fatalf("Remark = %q, want %q", contact.Remark, raw.Remark)
	}
	if contact.Description != raw.Reserved6 {
		t.Fatalf("Description = %q, want %q", contact.Description, raw.Reserved6)
	}
	if got := contact.DisplayName(); got != raw.Remark {
		t.Fatalf("DisplayName() = %q, want the short remark %q", got, raw.Remark)
	}
	wantTags := []ContactTag{
		{ID: "3", Name: "Shanghai"},
		{ID: "5", Name: "Family"},
		{ID: "999", Name: ""},
	}
	if !reflect.DeepEqual(contact.Tags, wantTags) {
		t.Fatalf("Tags = %#v, want %#v", contact.Tags, wantTags)
	}
	if contact.Signature != "碰巧遇到你" || contact.AddScene == nil || *contact.AddScene != 30 || contact.AddSceneEnum != "FRIENDSHIP_SCENE_TYPE_QRCODE" || contact.AddSceneString != "Scan QR Code" || contact.Country != "HK" || contact.Province != "Kowloon" || contact.City != "Yau Tsim Mong" {
		t.Fatalf("ExtraBuf profile fields = %#v", contact)
	}
}

func TestContactDescriptionMappingByDatabaseVersion(t *testing.T) {
	t.Run("darwin v3 remains empty until its storage is known", func(t *testing.T) {
		contact := (&ContactDarwinV3{
			M_nsUsrName:   "wxid_darwin",
			Nickname:      "Darwin nickname",
			M_nsRemark:    "Darwin remark",
			M_nsAliasName: "darwin-alias",
		}).Wrap()

		if contact.Description != "" {
			t.Fatalf("Description = %q, want empty", contact.Description)
		}
		if contact.Tags == nil || len(contact.Tags) != 0 {
			t.Fatalf("Tags = %#v, want an empty tag list", contact.Tags)
		}
		if contact.Signature != "" || contact.AddScene != nil || contact.AddSceneEnum != "" || contact.AddSceneString != "" || contact.Country != "" || contact.Province != "" || contact.City != "" {
			t.Fatalf("unverified Darwin profile fields must remain empty/null: %#v", contact)
		}
	})

	t.Run("v4 description", func(t *testing.T) {
		raw := &ContactV4{
			UserName:    "wxid_v4",
			Alias:       "v4-alias",
			Remark:      "V4 remark",
			NickName:    "V4 nickname",
			LocalType:   2,
			Description: "V4 profile description",
		}
		contact := raw.Wrap()

		if contact.Description != raw.Description {
			t.Fatalf("Description = %q, want %q", contact.Description, raw.Description)
		}
		if contact.Tags == nil || len(contact.Tags) != 0 {
			t.Fatalf("Tags = %#v, want an empty tag list", contact.Tags)
		}
		if contact.Signature != "" || contact.AddScene != nil || contact.AddSceneEnum != "" || contact.AddSceneString != "" || contact.Country != "" || contact.Province != "" || contact.City != "" {
			t.Fatalf("unverified v4 profile fields must remain empty/null: %#v", contact)
		}
	})
}

func TestContactJSONIncludesDescription(t *testing.T) {
	addScene := int32(30)
	contact := &Contact{
		UserName:    "wxid_xiaorui",
		Alias:       "xiaoruizhao-",
		Remark:      "无理取闹的大瑞",
		NickName:    "晓晓",
		IsFriend:    true,
		Description: "生日：阴历1994年11月18日（冬月18）",
		Tags: []ContactTag{
			{ID: "3", Name: "Shanghai"},
			{ID: "404", Name: ""},
		},
		Signature:      "碰巧遇到你",
		AddScene:       &addScene,
		AddSceneEnum:   "FRIENDSHIP_SCENE_TYPE_QRCODE",
		AddSceneString: "Scan QR Code",
		Country:        "HK",
		Province:       "Kowloon",
		City:           "Yau Tsim Mong",
	}

	got, err := json.Marshal(contact)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"userName":"wxid_xiaorui","alias":"xiaoruizhao-","remark":"无理取闹的大瑞","nickName":"晓晓","isFriend":true,"description":"生日：阴历1994年11月18日（冬月18）","tags":[{"id":"3","name":"Shanghai"},{"id":"404","name":""}],"signature":"碰巧遇到你","addScene":30,"addSceneEnum":"FRIENDSHIP_SCENE_TYPE_QRCODE","addSceneString":"Scan QR Code","country":"HK","province":"Kowloon","city":"Yau Tsim Mong"}`
	if string(got) != want {
		t.Fatalf("json.Marshal() = %s, want %s", got, want)
	}
}

func TestContactV3TagsPreserveOrderDuplicatesAndUnknownIDs(t *testing.T) {
	contact := (&ContactV3{LabelIDList: " 5, ,3,5,unknown, "}).WrapWithLabelNames(map[string]string{
		"3": "Shanghai",
		"5": "Family",
	})
	want := []ContactTag{
		{ID: "5", Name: "Family"},
		{ID: "3", Name: "Shanghai"},
		{ID: "5", Name: "Family"},
		{ID: "unknown", Name: ""},
	}
	if !reflect.DeepEqual(contact.Tags, want) {
		t.Fatalf("Tags = %#v, want %#v", contact.Tags, want)
	}
}
