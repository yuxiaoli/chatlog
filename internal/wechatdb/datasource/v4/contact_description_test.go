//go:build cgo

package v4

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestGetContactsMapsDescriptionAndHandlesNull(t *testing.T) {
	dir := t.TempDir()
	db := createContactTestDB(t, filepath.Join(dir, "contact.db"), `
		CREATE TABLE contact (
			username TEXT PRIMARY KEY,
			local_type INTEGER,
			alias TEXT,
			remark TEXT,
			nick_name TEXT,
			description TEXT
		);
		INSERT INTO contact VALUES
			('wxid_null', 2, 'null-alias', 'Null remark', 'Null nickname', NULL),
			('wxid_v4', 2, 'v4-alias', 'V4 remark', 'V4 nickname',
			 'V4 profile description');
	`)
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
		t.Fatalf("NULL description contact = %#v, want empty Description", contacts[0])
	}
	if contacts[1].Description != "V4 profile description" {
		t.Fatalf("Description = %q, want v4 description value", contacts[1].Description)
	}

	matched, err := ds.GetContacts(context.Background(), contacts[1].Description, 0, 0)
	if err != nil {
		t.Fatalf("GetContacts(description) error = %v", err)
	}
	if len(matched) != 1 || matched[0].UserName != "wxid_v4" {
		t.Fatalf("GetContacts(description) = %#v, want wxid_v4", matched)
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
