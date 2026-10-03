//go:build cgo

package windowsv3

import (
	"context"
	"database/sql"
	"encoding/binary"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf16"

	"github.com/sjzar/chatlog/internal/model"
)

func TestGetContactsMapsReserved6AndHandlesNull(t *testing.T) {
	dir := t.TempDir()
	db := createContactTestDB(t, filepath.Join(dir, "MicroMsg.db"), `
		CREATE TABLE Contact (
			UserName TEXT PRIMARY KEY,
			Alias TEXT,
			Remark TEXT,
			NickName TEXT,
			Reserved1 INTEGER,
			Reserved6 TEXT,
			LabelIDList TEXT,
			ExtraBuf BLOB
		);
		CREATE TABLE ContactLabel (LabelId INTEGER, LabelName TEXT);
		INSERT INTO ContactLabel VALUES (3, 'Shanghai'), (5, 'Family');
		INSERT INTO Contact VALUES
			('wxid_null', 'null-alias', 'Null remark', 'Null nickname', 1, NULL, NULL, NULL),
			('wxid_xiaorui', 'xiaoruizhao-', '无理取闹的大瑞', '晓晓', 1,
			 '生日：阴历1994年11月18日（冬月18）', '3,5,999', NULL);
	`)
	extraBuf := appendContactExtraUTF16(nil, [4]byte{0x46, 0xcf, 0x10, 0xc4}, "碰巧遇到你")
	extraBuf = appendContactExtraInt32(extraBuf, [4]byte{0x4d, 0x6c, 0x45, 0x70}, 30)
	extraBuf = appendContactExtraUTF16(extraBuf, [4]byte{0xa4, 0xd9, 0x02, 0x4a}, "HK")
	extraBuf = appendContactExtraUTF16(extraBuf, [4]byte{0xe2, 0xea, 0xa8, 0xd1}, "Kowloon")
	extraBuf = appendContactExtraUTF16(extraBuf, [4]byte{0x1d, 0x02, 0x5b, 0xbf}, "Yau Tsim Mong")
	if _, err := db.Exec(`UPDATE Contact SET ExtraBuf = ? WHERE UserName = 'wxid_xiaorui'`, extraBuf); err != nil {
		t.Fatalf("set fixture ExtraBuf: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}

	ds, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = ds.Close() })

	contacts, err := ds.GetContacts(context.Background(), "", 0, 0)
	if err != nil {
		t.Fatalf("GetContacts() error = %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("GetContacts() returned %d contacts, want 2", len(contacts))
	}
	if contacts[0].UserName != "wxid_null" || contacts[0].Description != "" {
		t.Fatalf("NULL Reserved6 contact = %#v, want empty Description", contacts[0])
	}
	if contacts[1].Remark != "无理取闹的大瑞" {
		t.Fatalf("Remark = %q, want short display-name remark", contacts[1].Remark)
	}
	if contacts[1].Description != "生日：阴历1994年11月18日（冬月18）" {
		t.Fatalf("Description = %q, want Reserved6 value", contacts[1].Description)
	}
	wantTags := []model.ContactTag{
		{ID: "3", Name: "Shanghai"},
		{ID: "5", Name: "Family"},
		{ID: "999", Name: ""},
	}
	if !reflect.DeepEqual(contacts[1].Tags, wantTags) {
		t.Fatalf("Tags = %#v, want %#v", contacts[1].Tags, wantTags)
	}
	if contacts[1].Signature != "碰巧遇到你" || contacts[1].AddScene == nil || *contacts[1].AddScene != 30 || contacts[1].AddSceneEnum != "FRIENDSHIP_SCENE_TYPE_QRCODE" || contacts[1].AddSceneString != "Scan QR Code" || contacts[1].Country != "HK" || contacts[1].Province != "Kowloon" || contacts[1].City != "Yau Tsim Mong" {
		t.Fatalf("ExtraBuf profile fields = %#v", contacts[1])
	}

	matched, err := ds.GetContacts(context.Background(), contacts[1].Description, 0, 0)
	if err != nil {
		t.Fatalf("GetContacts(description) error = %v", err)
	}
	if len(matched) != 1 || matched[0].UserName != "wxid_xiaorui" {
		t.Fatalf("GetContacts(description) = %#v, want wxid_xiaorui", matched)
	}

	for _, key := range []string{"5", "Family", "999"} {
		matched, err := ds.GetContacts(context.Background(), key, 0, 0)
		if err != nil {
			t.Fatalf("GetContacts(%q) error = %v", key, err)
		}
		if len(matched) != 1 || matched[0].UserName != "wxid_xiaorui" {
			t.Fatalf("GetContacts(%q) = %#v, want wxid_xiaorui", key, matched)
		}
	}
}

func TestGetContactsPreservesTagIDsWithoutContactLabelTable(t *testing.T) {
	dir := t.TempDir()
	db := createContactTestDB(t, filepath.Join(dir, "MicroMsg.db"), `
		CREATE TABLE Contact (
			UserName TEXT PRIMARY KEY,
			Alias TEXT,
			Remark TEXT,
			NickName TEXT,
			Reserved1 INTEGER,
			Reserved6 TEXT,
			LabelIDList TEXT,
			ExtraBuf BLOB
		);
		INSERT INTO Contact VALUES
			('wxid_unresolved', '', '', 'Unresolved', 1, '', ' 3,,3,404 ', NULL);
	`)
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}

	ds, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = ds.Close() })

	contacts, err := ds.GetContacts(context.Background(), "404", 0, 0)
	if err != nil {
		t.Fatalf("GetContacts(tag ID) error = %v", err)
	}
	want := []model.ContactTag{
		{ID: "3", Name: ""},
		{ID: "3", Name: ""},
		{ID: "404", Name: ""},
	}
	if len(contacts) != 1 || !reflect.DeepEqual(contacts[0].Tags, want) {
		t.Fatalf("GetContacts(tag ID) = %#v, want unresolved tags %#v", contacts, want)
	}
}

func TestLoadContactLabelNamesHandlesNullAndDuplicateIDsDeterministically(t *testing.T) {
	db := createContactTestDB(t, filepath.Join(t.TempDir(), "labels.db"), `
		CREATE TABLE ContactLabel (LabelId, LabelName);
		INSERT INTO ContactLabel VALUES
			(NULL, 'ignored'),
			(3, 'old name'),
			(3, 'new name'),
			(5, NULL);
	`)
	t.Cleanup(func() { _ = db.Close() })

	got, err := loadContactLabelNames(context.Background(), db)
	if err != nil {
		t.Fatalf("loadContactLabelNames() error = %v", err)
	}
	want := map[string]string{"3": "", "5": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadContactLabelNames() = %#v, want %#v", got, want)
	}
}

func createContactTestDB(t *testing.T, path, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open(%q) error = %v", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create fixture database: %v", err)
	}
	return db
}

func appendContactExtraUTF16(dst []byte, id [4]byte, value string) []byte {
	units := utf16.Encode([]rune(value))
	units = append(units, 0)
	payload := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(payload[i*2:i*2+2], unit)
	}
	dst = append(dst, id[:]...)
	dst = append(dst, 0x18)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(payload)))
	dst = append(dst, length...)
	return append(dst, payload...)
}

func appendContactExtraInt32(dst []byte, id [4]byte, value int32) []byte {
	dst = append(dst, id[:]...)
	dst = append(dst, 0x04)
	encoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(encoded, uint32(value))
	return append(dst, encoded...)
}
