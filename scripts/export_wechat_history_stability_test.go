package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashDatabaseSourceCanonicalizesEmptyWAL(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "xInfo.db")
	wal := source + "-wal"
	if err := os.WriteFile(source, []byte("stable database contents"), 0o600); err != nil {
		t.Fatalf("write source fixture: %v", err)
	}

	withoutWAL, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash source without WAL: %v", err)
	}
	missingSignature, err := optionalFileSignatureOf(wal)
	if err != nil {
		t.Fatalf("inspect missing WAL: %v", err)
	}

	if err := os.WriteFile(wal, nil, 0o600); err != nil {
		t.Fatalf("create empty WAL: %v", err)
	}
	withEmptyWAL, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash source with empty WAL: %v", err)
	}
	emptySignature, err := optionalFileSignatureOf(wal)
	if err != nil {
		t.Fatalf("inspect empty WAL: %v", err)
	}

	if withoutWAL != withEmptyWAL {
		t.Fatalf("empty WAL changed the source digest: missing=%s empty=%s", withoutWAL, withEmptyWAL)
	}
	if missingSignature != emptySignature || emptySignature.Exists {
		t.Fatalf("missing and empty WAL signatures differ: missing=%+v empty=%+v", missingSignature, emptySignature)
	}

	if err := os.Remove(wal); err != nil {
		t.Fatalf("remove empty WAL: %v", err)
	}
	afterRemoval, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash source after removing empty WAL: %v", err)
	}
	if withEmptyWAL != afterRemoval {
		t.Fatalf("removing empty WAL changed the source digest: empty=%s removed=%s", withEmptyWAL, afterRemoval)
	}
}

func TestHashDatabaseSourceDetectsNonEmptyWALAndMainChanges(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "xInfo.db")
	wal := source + "-wal"
	if err := os.WriteFile(source, []byte("database version one"), 0o600); err != nil {
		t.Fatalf("write source fixture: %v", err)
	}

	initial, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash initial source: %v", err)
	}
	if err := os.WriteFile(wal, []byte("one WAL frame"), 0o600); err != nil {
		t.Fatalf("write non-empty WAL: %v", err)
	}
	withWAL, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash source with non-empty WAL: %v", err)
	}
	walSignature, err := optionalFileSignatureOf(wal)
	if err != nil {
		t.Fatalf("inspect non-empty WAL: %v", err)
	}
	if initial == withWAL {
		t.Fatalf("non-empty WAL did not change source digest: %s", initial)
	}
	if !walSignature.Exists || walSignature.Size == 0 {
		t.Fatalf("non-empty WAL was canonicalized away: %+v", walSignature)
	}

	if err := os.Remove(wal); err != nil {
		t.Fatalf("remove non-empty WAL: %v", err)
	}
	if err := os.WriteFile(source, []byte("database version two"), 0o600); err != nil {
		t.Fatalf("change source fixture: %v", err)
	}
	changedMain, err := hashDatabaseSource(source)
	if err != nil {
		t.Fatalf("hash changed source: %v", err)
	}
	if initial == changedMain {
		t.Fatalf("main database change did not change source digest: %s", initial)
	}
}
