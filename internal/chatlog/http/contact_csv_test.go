package http

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"

	"github.com/sjzar/chatlog/internal/model"
)

func TestWriteContactsCSVRoundTripsDescription(t *testing.T) {
	addScene := int32(30)
	contacts := []*model.Contact{
		{
			UserName:    "wxid_xiaorui",
			Alias:       "xiaoruizhao-",
			Remark:      "无理取闹的大瑞",
			NickName:    "晓晓",
			Description: "生日：阴历1994年11月18日（冬月18）, 电话 \"家人\"\n第二行备注",
			Tags: []model.ContactTag{
				{ID: "3", Name: "Shanghai, Pudong"},
				{ID: "404", Name: ""},
			},
			Signature:      "碰巧遇到你, \"世界\"\n第二行",
			AddScene:       &addScene,
			AddSceneEnum:   "FRIENDSHIP_SCENE_TYPE_QRCODE",
			AddSceneString: "Scan QR Code",
			Country:        "HK",
			Province:       "Kowloon",
			City:           "Yau Tsim Mong",
		},
	}

	var buf bytes.Buffer
	if err := writeContactsCSV(&buf, contacts); err != nil {
		t.Fatalf("writeContactsCSV() error = %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv.Reader.ReadAll() error = %v; output = %q", err, buf.String())
	}

	want := [][]string{
		{"UserName", "Alias", "Remark", "NickName", "Description", "Tags", "Signature", "AddScene", "AddSceneEnum", "AddSceneString", "Country", "Province", "City"},
		{"wxid_xiaorui", "xiaoruizhao-", "无理取闹的大瑞", "晓晓", contacts[0].Description, `[{"id":"3","name":"Shanghai, Pudong"},{"id":"404","name":""}]`, contacts[0].Signature, "30", "FRIENDSHIP_SCENE_TYPE_QRCODE", "Scan QR Code", "HK", "Kowloon", "Yau Tsim Mong"},
	}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("CSV records = %#v, want %#v", records, want)
	}
}

func TestWriteContactsCSVUsesEmptyAddSceneForUnsupportedSources(t *testing.T) {
	var buf bytes.Buffer
	if err := writeContactsCSV(&buf, []*model.Contact{{UserName: "wxid_no_profile"}}); err != nil {
		t.Fatalf("writeContactsCSV() error = %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv.Reader.ReadAll() error = %v", err)
	}
	if got := records[1][7]; got != "" {
		t.Fatalf("AddScene = %q, want empty for nil", got)
	}
	if got := records[1][8:10]; !reflect.DeepEqual(got, []string{"", ""}) {
		t.Fatalf("derived add-scene fields = %#v, want empty for nil", got)
	}
}
