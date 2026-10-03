package model

import "testing"

func TestContactAddSceneDetails(t *testing.T) {
	tests := []struct {
		code       int32
		wantEnum   string
		wantString string
	}{
		{0, "FRIENDSHIP_SCENE_TYPE_UNSPECIFIED", "Unspecified"},
		{1, "FRIENDSHIP_SCENE_TYPE_QQ", "QQ"},
		{2, "FRIENDSHIP_SCENE_TYPE_EMAIL", "Email"},
		{3, "FRIENDSHIP_SCENE_TYPE_WEIXIN", "WeChat ID"},
		{12, "FRIENDSHIP_SCENE_TYPE_QQTBD", "QQ (TBD)"},
		{14, "FRIENDSHIP_SCENE_TYPE_ROOM", "Group Chat"},
		{15, "FRIENDSHIP_SCENE_TYPE_PHONE", "Phone Contacts"},
		{17, "FRIENDSHIP_SCENE_TYPE_CARD", "Contact Card"},
		{18, "FRIENDSHIP_SCENE_TYPE_LOCATION", "Location"},
		{25, "FRIENDSHIP_SCENE_TYPE_BOTTLE", "Drift Bottle"},
		{29, "FRIENDSHIP_SCENE_TYPE_SHAKING", "Shake"},
		{30, "FRIENDSHIP_SCENE_TYPE_QRCODE", "Scan QR Code"},
		{999, "FRIENDSHIP_SCENE_TYPE_UNKNOWN_999", "Unknown (999)"},
		{-7, "FRIENDSHIP_SCENE_TYPE_UNKNOWN_-7", "Unknown (-7)"},
	}

	for _, tt := range tests {
		gotEnum, gotString := contactAddSceneDetails(&tt.code)
		if gotEnum != tt.wantEnum || gotString != tt.wantString {
			t.Errorf("contactAddSceneDetails(%d) = (%q, %q), want (%q, %q)", tt.code, gotEnum, gotString, tt.wantEnum, tt.wantString)
		}
	}
}

func TestContactAddSceneDetailsAbsent(t *testing.T) {
	gotEnum, gotString := contactAddSceneDetails(nil)
	if gotEnum != "" || gotString != "" {
		t.Fatalf("contactAddSceneDetails(nil) = (%q, %q), want empty strings", gotEnum, gotString)
	}
}

func TestContactV3WrapExportsUnknownAddSceneDetails(t *testing.T) {
	raw := appendExtraBufFixed(nil, extraBufAddSceneID, extraBufTypeInt32, []byte{231, 3, 0, 0})
	contact := (&ContactV3{ExtraBuf: raw}).Wrap()
	if contact.AddScene == nil || *contact.AddScene != 999 {
		t.Fatalf("AddScene = %v, want 999", contact.AddScene)
	}
	if contact.AddSceneEnum != "FRIENDSHIP_SCENE_TYPE_UNKNOWN_999" || contact.AddSceneString != "Unknown (999)" {
		t.Fatalf("derived add-scene fields = (%q, %q)", contact.AddSceneEnum, contact.AddSceneString)
	}
}
