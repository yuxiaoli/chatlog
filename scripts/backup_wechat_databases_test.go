//go:build windows

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func createSQLiteBackupFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture SQLite database: %v", err)
	}
	statements := []string{
		"PRAGMA user_version=42",
		"PRAGMA application_id=112233",
		"CREATE TABLE contacts(id INTEGER PRIMARY KEY, name TEXT, note BLOB, nullable TEXT)",
		"CREATE TABLE audit(contact_id INTEGER NOT NULL, name TEXT NOT NULL)",
		"CREATE TABLE settings(section TEXT, name TEXT, value TEXT, PRIMARY KEY(section, name)) WITHOUT ROWID",
		"CREATE INDEX contacts_name_idx ON contacts(name)",
		"CREATE VIEW contact_names AS SELECT id, name FROM contacts",
		"CREATE TRIGGER contacts_audit AFTER INSERT ON contacts BEGIN INSERT INTO audit(contact_id, name) VALUES (new.id, new.name); END",
		"INSERT INTO contacts(id, name, note, nullable) VALUES (1, '联系人', X'000102FF', NULL)",
		"INSERT INTO settings(section, name, value) VALUES ('profile', 'city', '上海')",
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			_ = database.Close()
			t.Fatalf("execute fixture statement %q: %v", statement, err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close fixture SQLite database: %v", err)
	}
}

func sqliteSchemaNames(t *testing.T, path string) []string {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatalf("open SQLite schema fixture: %v", err)
	}
	defer database.Close()
	rows, err := database.Query("SELECT type || ':' || name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
	if err != nil {
		t.Fatalf("query SQLite schema: %v", err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan SQLite schema: %v", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read SQLite schema: %v", err)
	}
	return result
}

const (
	testWechatPageSize     = 4096
	testWechatReserveBytes = 48
	testWALHeaderSize      = 32
	testWALFrameHeaderSize = 24
)

type encryptedWALFixture struct {
	source       string
	key          []byte
	keyHex       string
	salt         []byte
	plaintextWAL []byte
}

func createEncryptedWALFixture(t *testing.T, directory string) encryptedWALFixture {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create encrypted WAL fixture directory: %v", err)
	}
	plaintextPath := filepath.Join(directory, "plaintext.db")
	database, err := sql.Open("sqlite", plaintextPath)
	if err != nil {
		t.Fatalf("open plaintext WAL fixture: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = database.Close()
		}
	}()
	for _, statement := range []string{
		"PRAGMA page_size=4096",
		"PRAGMA journal_mode=DELETE",
		"CREATE TABLE events(id INTEGER PRIMARY KEY, value TEXT NOT NULL, payload BLOB)",
		"INSERT INTO events VALUES (1, 'BASE_VALUE', X'000102FF')",
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("initialize plaintext WAL fixture with %q: %v", statement, err)
		}
	}
	var journalMode string
	if err := database.QueryRow("PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil || !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("enable WAL fixture mode: mode=%q err=%v", journalMode, err)
	}
	if _, err := database.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatalf("disable fixture auto-checkpoint: %v", err)
	}
	if _, err := database.Exec("INSERT INTO events VALUES (2, 'COMMITTED_VALUE', X'10203040')"); err != nil {
		t.Fatalf("commit WAL-only fixture row: %v", err)
	}

	mainBytes, err := os.ReadFile(plaintextPath)
	if err != nil {
		t.Fatalf("read plaintext fixture main database: %v", err)
	}
	walBytes, err := os.ReadFile(plaintextPath + "-wal")
	if err != nil {
		t.Fatalf("read plaintext fixture WAL: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close plaintext fixture database: %v", err)
	}
	closed = true

	reservedMain := reserveSQLiteDatabaseForEncryption(t, mainBytes)
	reservedWAL := rewriteTestWAL(t, walBytes, func(page []byte, pageNumber uint32, _ int) []byte {
		return reserveSQLitePageForEncryption(t, page, int(pageNumber))
	})
	validatePlaintextWALFixture(t, directory, reservedMain, reservedWAL)

	key := bytes.Repeat([]byte{0x42}, 32)
	salt := []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	encryptedMain := encryptTestWechatDatabase(t, reservedMain, key, salt)
	encryptedWAL := encryptTestWechatWAL(t, reservedWAL, key, salt)
	source := filepath.Join(directory, "encrypted.db")
	if err := os.WriteFile(source, encryptedMain, 0o600); err != nil {
		t.Fatalf("write encrypted fixture main database: %v", err)
	}
	if err := os.WriteFile(source+"-wal", encryptedWAL, 0o600); err != nil {
		t.Fatalf("write encrypted fixture WAL: %v", err)
	}
	account := candidate{Platform: "windows", Version: 3, DataKey: hex.EncodeToString(key)}
	if !validDataKey(account, source) {
		t.Fatal("generated encrypted main database does not validate with its fixture key")
	}
	return encryptedWALFixture{
		source:       source,
		key:          key,
		keyHex:       hex.EncodeToString(key),
		salt:         salt,
		plaintextWAL: reservedWAL,
	}
}

func reserveSQLiteDatabaseForEncryption(t *testing.T, database []byte) []byte {
	t.Helper()
	if len(database) == 0 || len(database)%testWechatPageSize != 0 {
		t.Fatalf("plaintext fixture database size %d is not page-aligned", len(database))
	}
	result := make([]byte, 0, len(database))
	for offset, pageNumber := 0, 1; offset < len(database); offset, pageNumber = offset+testWechatPageSize, pageNumber+1 {
		result = append(result, reserveSQLitePageForEncryption(t, database[offset:offset+testWechatPageSize], pageNumber)...)
	}
	return result
}

func reserveSQLitePageForEncryption(t *testing.T, page []byte, pageNumber int) []byte {
	t.Helper()
	if len(page) != testWechatPageSize {
		t.Fatalf("fixture SQLite page %d has size %d", pageNumber, len(page))
	}
	result := append([]byte(nil), page...)
	headerOffset := 0
	if pageNumber == 1 {
		if !bytes.Equal(page[:len(sqliteHeader)], []byte(sqliteHeader)) {
			t.Fatalf("fixture database page 1 lacks the SQLite header")
		}
		headerOffset = 100
		result[20] = testWechatReserveBytes
	}
	pageType := page[headerOffset]
	if pageType != 0x02 && pageType != 0x05 && pageType != 0x0a && pageType != 0x0d {
		t.Fatalf("fixture page %d has unsupported b-tree page type 0x%02x", pageNumber, pageType)
	}
	if binary.BigEndian.Uint16(page[headerOffset+1:headerOffset+3]) != 0 || page[headerOffset+7] != 0 {
		t.Fatalf("fixture page %d unexpectedly uses freeblocks or fragmented bytes", pageNumber)
	}
	cellCount := int(binary.BigEndian.Uint16(page[headerOffset+3 : headerOffset+5]))
	cellStart := int(binary.BigEndian.Uint16(page[headerOffset+5 : headerOffset+7]))
	if cellStart == 0 || cellStart < headerOffset+8+cellCount*2+testWechatReserveBytes {
		t.Fatalf("fixture page %d has unsafe cell-content offset %d", pageNumber, cellStart)
	}
	newCellStart := cellStart - testWechatReserveBytes
	content := append([]byte(nil), page[cellStart:]...)
	for index := newCellStart; index < len(result); index++ {
		result[index] = 0
	}
	copy(result[newCellStart:testWechatPageSize-testWechatReserveBytes], content)
	binary.BigEndian.PutUint16(result[headerOffset+5:headerOffset+7], uint16(newCellStart))
	for index := 0; index < cellCount; index++ {
		pointerOffset := headerOffset + 8 + index*2
		pointer := int(binary.BigEndian.Uint16(page[pointerOffset : pointerOffset+2]))
		if pointer < cellStart {
			t.Fatalf("fixture page %d cell %d points outside its content area", pageNumber, index)
		}
		binary.BigEndian.PutUint16(result[pointerOffset:pointerOffset+2], uint16(pointer-testWechatReserveBytes))
	}
	return result
}

func validatePlaintextWALFixture(t *testing.T, directory string, mainBytes, walBytes []byte) {
	t.Helper()
	validationPath := filepath.Join(directory, "reserved-validation.db")
	if err := os.WriteFile(validationPath, mainBytes, 0o600); err != nil {
		t.Fatalf("write reserved fixture main database: %v", err)
	}
	if err := os.WriteFile(validationPath+"-wal", walBytes, 0o600); err != nil {
		t.Fatalf("write reserved fixture WAL: %v", err)
	}
	database, err := sql.Open("sqlite", validationPath)
	if err != nil {
		t.Fatalf("open reserved fixture with WAL: %v", err)
	}
	defer database.Close()
	rows, err := database.Query("SELECT id, value, hex(payload) FROM events ORDER BY id")
	if err != nil {
		t.Fatalf("query reserved fixture with WAL: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id int
		var value, payload string
		if err := rows.Scan(&id, &value, &payload); err != nil {
			t.Fatalf("scan reserved fixture row: %v", err)
		}
		got = append(got, fmt.Sprintf("%d:%s:%s", id, value, payload))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read reserved fixture rows: %v", err)
	}
	want := []string{"1:BASE_VALUE:000102FF", "2:COMMITTED_VALUE:10203040"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reserved fixture WAL did not reproduce committed rows: got=%v want=%v", got, want)
	}
}

func testWALChecksum(t *testing.T, order binary.ByteOrder, data []byte, first, second uint32) (uint32, uint32) {
	t.Helper()
	if len(data)%8 != 0 {
		t.Fatalf("fixture WAL checksum input has non-8-byte size %d", len(data))
	}
	for offset := 0; offset < len(data); offset += 8 {
		first += order.Uint32(data[offset:offset+4]) + second
		second += order.Uint32(data[offset+4:offset+8]) + first
	}
	return first, second
}

func testWALChecksumByteOrder(t *testing.T, wal []byte) binary.ByteOrder {
	t.Helper()
	if len(wal) < testWALHeaderSize {
		t.Fatalf("fixture WAL is shorter than its header: %d", len(wal))
	}
	wantFirst := binary.BigEndian.Uint32(wal[24:28])
	wantSecond := binary.BigEndian.Uint32(wal[28:32])
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		first, second := testWALChecksum(t, order, wal[:24], 0, 0)
		if first == wantFirst && second == wantSecond {
			return order
		}
	}
	t.Fatal("fixture WAL header checksum is invalid")
	return binary.LittleEndian
}

func rewriteTestWAL(t *testing.T, wal []byte, rewrite func([]byte, uint32, int) []byte) []byte {
	t.Helper()
	if len(wal) < testWALHeaderSize {
		t.Fatalf("fixture WAL is shorter than its header: %d", len(wal))
	}
	pageSize := int(binary.BigEndian.Uint32(wal[8:12]))
	if pageSize != testWechatPageSize {
		t.Fatalf("fixture WAL page size is %d, want %d", pageSize, testWechatPageSize)
	}
	frameSize := testWALFrameHeaderSize + pageSize
	if (len(wal)-testWALHeaderSize)%frameSize != 0 {
		t.Fatalf("fixture WAL size %d does not contain whole frames", len(wal))
	}
	result := append([]byte(nil), wal...)
	order := testWALChecksumByteOrder(t, wal)
	first := binary.BigEndian.Uint32(wal[24:28])
	second := binary.BigEndian.Uint32(wal[28:32])
	headerSalt := wal[16:24]
	frameCount := (len(wal) - testWALHeaderSize) / frameSize
	for frameIndex := 0; frameIndex < frameCount; frameIndex++ {
		offset := testWALHeaderSize + frameIndex*frameSize
		header := result[offset : offset+testWALFrameHeaderSize]
		pageNumber := binary.BigEndian.Uint32(header[:4])
		if pageNumber == 0 {
			t.Fatalf("fixture WAL frame %d has page number zero", frameIndex+1)
		}
		if !bytes.Equal(header[8:16], headerSalt) {
			t.Fatalf("fixture WAL frame %d has mismatched salts", frameIndex+1)
		}
		page := append([]byte(nil), wal[offset+testWALFrameHeaderSize:offset+frameSize]...)
		page = rewrite(page, pageNumber, frameIndex)
		if len(page) != pageSize {
			t.Fatalf("fixture WAL rewrite returned a %d-byte page", len(page))
		}
		copy(result[offset+testWALFrameHeaderSize:offset+frameSize], page)
		first, second = testWALChecksum(t, order, header[:8], first, second)
		first, second = testWALChecksum(t, order, page, first, second)
		binary.BigEndian.PutUint32(header[16:20], first)
		binary.BigEndian.PutUint32(header[20:24], second)
	}
	return result
}

func encryptTestWechatDatabase(t *testing.T, database, key, salt []byte) []byte {
	t.Helper()
	if len(database)%testWechatPageSize != 0 {
		t.Fatalf("reserved fixture database size %d is not page-aligned", len(database))
	}
	result := make([]byte, 0, len(database))
	for offset, pageNumber := 0, 1; offset < len(database); offset, pageNumber = offset+testWechatPageSize, pageNumber+1 {
		result = append(result, encryptTestWechatPage(t, database[offset:offset+testWechatPageSize], key, salt, uint32(pageNumber), pageNumber)...)
	}
	return result
}

func encryptTestWechatWAL(t *testing.T, wal, key, salt []byte) []byte {
	t.Helper()
	return rewriteTestWAL(t, wal, func(page []byte, pageNumber uint32, frameIndex int) []byte {
		return encryptTestWechatPage(t, page, key, salt, pageNumber, 10_000+frameIndex)
	})
}

func encryptTestWechatPage(t *testing.T, plaintext, key, salt []byte, pageNumber uint32, nonce int) []byte {
	t.Helper()
	if len(plaintext) != testWechatPageSize || len(key) != 32 || len(salt) != 16 || pageNumber == 0 {
		t.Fatalf("invalid encrypted-page fixture inputs")
	}
	encKey := pbkdf2.Key(key, salt, 64_000, 32, sha1.New)
	macSalt := append([]byte(nil), salt...)
	for index := range macSalt {
		macSalt[index] ^= 0x3a
	}
	macKey := pbkdf2.Key(encKey, macSalt, 2, 32, sha1.New)
	result := append([]byte(nil), plaintext...)
	offset := 0
	if pageNumber == 1 {
		offset = 16
		copy(result[:16], salt)
	}
	ivSeed := sha256.Sum256([]byte(fmt.Sprintf("wechat-wal-fixture:%d:%d", pageNumber, nonce)))
	iv := ivSeed[:aes.BlockSize]
	copy(result[testWechatPageSize-testWechatReserveBytes:testWechatPageSize-testWechatReserveBytes+aes.BlockSize], iv)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("create fixture AES cipher: %v", err)
	}
	plainBody := append([]byte(nil), plaintext[offset:testWechatPageSize-testWechatReserveBytes]...)
	if len(plainBody)%aes.BlockSize != 0 {
		t.Fatalf("fixture encrypted page body has non-block size %d", len(plainBody))
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(result[offset:testWechatPageSize-testWechatReserveBytes], plainBody)
	macEnd := testWechatPageSize - testWechatReserveBytes + aes.BlockSize
	digest := hmac.New(sha1.New, macKey)
	_, _ = digest.Write(result[offset:macEnd])
	pageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pageBytes, pageNumber)
	_, _ = digest.Write(pageBytes)
	copy(result[macEnd:macEnd+sha1.Size], digest.Sum(nil))
	for index := macEnd + sha1.Size; index < len(result); index++ {
		result[index] = 0
	}
	return result
}

func appendUncommittedTestWALFrame(t *testing.T, wal []byte) []byte {
	t.Helper()
	frameSize := testWALFrameHeaderSize + testWechatPageSize
	frameCount := (len(wal) - testWALHeaderSize) / frameSize
	committedMarker := []byte("COMMITTED_VALUE")
	uncommittedMarker := []byte("UNCOMMITTED_VAL")
	if len(committedMarker) != len(uncommittedMarker) {
		t.Fatal("fixture committed and uncommitted markers differ in length")
	}
	for frameIndex := frameCount - 1; frameIndex >= 0; frameIndex-- {
		offset := testWALHeaderSize + frameIndex*frameSize
		page := append([]byte(nil), wal[offset+testWALFrameHeaderSize:offset+frameSize]...)
		markerOffset := bytes.Index(page, committedMarker)
		if markerOffset < 0 {
			continue
		}
		copy(page[markerOffset:markerOffset+len(uncommittedMarker)], uncommittedMarker)
		header := append([]byte(nil), wal[offset:offset+testWALFrameHeaderSize]...)
		binary.BigEndian.PutUint32(header[4:8], 0)
		result := append([]byte(nil), wal...)
		result = append(result, header...)
		result = append(result, page...)
		return rewriteTestWAL(t, result, func(page []byte, _ uint32, _ int) []byte { return page })
	}
	t.Fatal("could not find the committed marker in any fixture WAL frame")
	return nil
}

func rechecksumTestWAL(t *testing.T, wal []byte) []byte {
	t.Helper()
	result := append([]byte(nil), wal...)
	order := testWALChecksumByteOrder(t, result)
	first := binary.BigEndian.Uint32(result[24:28])
	second := binary.BigEndian.Uint32(result[28:32])
	frameSize := testWALFrameHeaderSize + testWechatPageSize
	for offset := testWALHeaderSize; offset < len(result); offset += frameSize {
		header := result[offset : offset+testWALFrameHeaderSize]
		page := result[offset+testWALFrameHeaderSize : offset+frameSize]
		first, second = testWALChecksum(t, order, header[:8], first, second)
		first, second = testWALChecksum(t, order, page, first, second)
		binary.BigEndian.PutUint32(header[16:20], first)
		binary.BigEndian.PutUint32(header[20:24], second)
	}
	return result
}

func assertNoDatabaseOutput(t *testing.T, destination string) {
	t.Helper()
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed encrypted-WAL staging left destination output: %v", err)
	}
	temporary, err := filepath.Glob(destination + ".tmp*")
	if err != nil {
		t.Fatalf("list encrypted-WAL temporary outputs: %v", err)
	}
	if len(temporary) != 0 {
		t.Fatalf("failed encrypted-WAL staging left temporary output: %v", temporary)
	}
}

func TestVerifySQLiteIntegrityAcceptsValidDatabaseAndRejectsHeaderOnlyCorruption(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.db")
	createSQLiteBackupFixture(t, valid)
	if err := verifySQLiteIntegrity(valid); err != nil {
		t.Fatalf("valid SQLite database failed integrity verification: %v", err)
	}

	corrupt := filepath.Join(directory, "corrupt.db")
	contents := append([]byte(sqliteHeader), bytes.Repeat([]byte{0}, 496)...)
	if err := os.WriteFile(corrupt, contents, 0o600); err != nil {
		t.Fatalf("write corrupt SQLite fixture: %v", err)
	}
	if err := verifySQLiteIntegrity(corrupt); err == nil {
		t.Fatal("header-only corrupt database unexpectedly passed integrity verification")
	}
}

func TestStrictSQLiteBackupUsesOnlyCentralConfigAndPreservesSQLiteSchema(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "configured-account")
	primarySource := filepath.Join(dataDir, "Msg", "MicroMsg.db")
	backupSource := filepath.Join(dataDir, "BackupFiles", "device", "Backup.db")
	createSQLiteBackupFixture(t, primarySource)
	createSQLiteBackupFixture(t, backupSource)

	localConfig := storedAccount{
		Account:  "LOCAL_MUST_NOT_OVERRIDE",
		Platform: "windows",
		Version:  4,
		DataDir:  dataDir,
		DataKey:  strings.Repeat("ab", 32),
	}
	localJSON, err := json.Marshal(localConfig)
	if err != nil {
		t.Fatalf("marshal local config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "chatlog.json"), localJSON, 0o600); err != nil {
		t.Fatalf("write local config: %v", err)
	}

	centralDataKey := strings.Repeat("cd", 32)
	centralImageKey := "central-image-key-must-not-leak"
	centralConfig := storedConfig{History: []storedAccount{{
		Account:     "CENTRAL_ACCOUNT",
		Platform:    "windows",
		Version:     3,
		FullVersion: "3.9.fixture",
		DataDir:     dataDir,
		DataKey:     centralDataKey,
		ImgKey:      centralImageKey,
	}}}
	centralJSON, err := json.Marshal(centralConfig)
	if err != nil {
		t.Fatalf("marshal central config: %v", err)
	}
	configPath := filepath.Join(root, "chatlog.json")
	if err := os.WriteFile(configPath, centralJSON, 0o600); err != nil {
		t.Fatalf("write central config: %v", err)
	}
	beforeConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read central config before backup: %v", err)
	}

	stage := filepath.Join(root, "private-stage")
	destinationRoot := filepath.Join(root, "published-backup")
	manifest, err := prepare(stage, configPath, "", nil, prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        destinationRoot,
	})
	if err != nil {
		t.Fatalf("prepare strict SQLite backup: %v", err)
	}
	if manifest.Status != "complete" || len(manifest.Unresolved) != 0 {
		t.Fatalf("unexpected manifest status: status=%s unresolved=%+v", manifest.Status, manifest.Unresolved)
	}
	if len(manifest.Accounts) != 1 {
		t.Fatalf("expected one central account, got %d", len(manifest.Accounts))
	}
	account := manifest.Accounts[0]
	if account.Account != "CENTRAL_ACCOUNT" || account.Version != 3 || account.KeySource != "chatlog_config" {
		t.Fatalf("local config leaked into strict backup account: %+v", account)
	}
	if len(account.Databases) != 2 {
		t.Fatalf("expected both recursively discovered databases, got %d", len(account.Databases))
	}

	for _, database := range account.Databases {
		if database.Status != "ok" || !hasSQLiteHeader(database.StagedPath) {
			t.Fatalf("database was not published as SQLite: %+v", database)
		}
		stagedBytes, err := os.ReadFile(database.StagedPath)
		if err != nil {
			t.Fatalf("read staged database for ordinary digest: %v", err)
		}
		stagedDigest := sha256.Sum256(stagedBytes)
		if database.FileSHA256 != hex.EncodeToString(stagedDigest[:]) {
			t.Fatalf("ordinary staged-file digest is not bound to SQLite bytes: %s", database.RelativePath)
		}
		if err := verifySQLiteIntegrity(database.StagedPath); err != nil {
			t.Fatalf("staged database failed a second integrity check: %v", err)
		}
		if !reflect.DeepEqual(sqliteSchemaNames(t, database.SourcePath), sqliteSchemaNames(t, database.StagedPath)) {
			t.Fatalf("SQLite schema objects changed for %s", database.RelativePath)
		}
	}

	primaryDestination := filepath.Join(stage, account.ID, "Msg", "MicroMsg.db")
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(primaryDestination)+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatalf("open staged fixture: %v", err)
	}
	defer database.Close()
	var userVersion, applicationID, auditCount int
	var name string
	var note []byte
	var nullable any
	if err := database.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if err := database.QueryRow("PRAGMA application_id").Scan(&applicationID); err != nil {
		t.Fatalf("read application_id: %v", err)
	}
	if err := database.QueryRow("SELECT name, note, nullable FROM contacts WHERE id=1").Scan(&name, &note, &nullable); err != nil {
		t.Fatalf("read staged row: %v", err)
	}
	if err := database.QueryRow("SELECT count(*) FROM audit").Scan(&auditCount); err != nil {
		t.Fatalf("read trigger result: %v", err)
	}
	if userVersion != 42 || applicationID != 112233 || name != "联系人" ||
		!bytes.Equal(note, []byte{0, 1, 2, 255}) || nullable != nil || auditCount != 1 {
		t.Fatalf("staged SQLite content changed: user_version=%d application_id=%d name=%q note=%x nullable=%v audit=%d",
			userVersion, applicationID, name, note, nullable, auditCount)
	}

	afterConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read central config after backup: %v", err)
	}
	if !bytes.Equal(beforeConfig, afterConfig) {
		t.Fatal("strict SQLite backup modified chatlog.json")
	}
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal preparation manifest: %v", err)
	}
	for _, secret := range []string{localConfig.DataKey, centralDataKey, centralImageKey, "data_key", "img_key"} {
		if bytes.Contains(encodedManifest, []byte(secret)) {
			t.Fatalf("a cached key or key field leaked into the preparation manifest: %q", secret)
		}
	}
}

func baselineFromStrictSQLiteManifest(t *testing.T, manifest *exportManifest) baselineIndex {
	t.Helper()
	baseline := make(baselineIndex, len(manifest.Accounts))
	for _, account := range manifest.Accounts {
		databases := make(map[string]baselineDatabase, len(account.Databases))
		for _, database := range account.Databases {
			if database.Status != "ok" {
				t.Fatalf("cannot build strict backup baseline from database status %q: %s", database.Status, database.RelativePath)
			}
			databases[baselineRelativePath(database.RelativePath)] = baselineDatabase{
				RelativePath:         database.RelativePath,
				OutputPath:           account.ID + "/" + strings.TrimLeft(filepath.ToSlash(database.RelativePath), "/"),
				SourceSHA256:         database.SourceSHA256,
				SnapshotSize:         database.SnapshotSize,
				SnapshotSHA256:       database.SnapshotSHA256,
				FileSHA256:           database.FileSHA256,
				AuxiliarySHA256:      database.AuxiliarySHA256,
				LegacyPhoneBootstrap: database.LegacyPhoneBootstrap,
			}
		}
		baseline[canonicalPath(account.DataDir)] = baselineAccountIndex{
			ID:        account.ID,
			Version:   account.Version,
			Databases: databases,
		}
	}
	return baseline
}

func TestReuseBaselineSQLiteCopiesVerifiedFileAndRejectsUnsafeOrTamperedInput(t *testing.T) {
	root := t.TempDir()
	accountID := "account_fixture"
	relativePath := "Msg/MicroMsg.db"
	baselinePath := filepath.Join(root, accountID, filepath.FromSlash(relativePath))
	createSQLiteBackupFixture(t, baselinePath)
	size, snapshotSHA256, fileSHA256, err := hashSnapshot(baselinePath)
	if err != nil {
		t.Fatalf("fingerprint reusable baseline fixture: %v", err)
	}
	prior := baselineDatabase{
		RelativePath:   relativePath,
		OutputPath:     accountID + "/" + relativePath,
		SnapshotSize:   size,
		SnapshotSHA256: snapshotSHA256,
		FileSHA256:     fileSHA256,
	}
	destination := filepath.Join(t.TempDir(), accountID, filepath.FromSlash(relativePath))
	copiedSize, copiedSnapshotSHA256, copiedFileSHA256, err := reuseBaselineSQLite(
		root,
		accountID,
		relativePath,
		destination,
		prior,
	)
	if err != nil {
		t.Fatalf("reuse verified baseline SQLite database: %v", err)
	}
	if copiedSize != size || copiedSnapshotSHA256 != snapshotSHA256 || copiedFileSHA256 != fileSHA256 {
		t.Fatalf("copied baseline proof changed: size=%d snapshot=%s file=%s", copiedSize, copiedSnapshotSHA256, copiedFileSHA256)
	}
	baselineBytes, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read reusable baseline fixture: %v", err)
	}
	copiedBytes, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read copied baseline fixture: %v", err)
	}
	if !bytes.Equal(baselineBytes, copiedBytes) || !hasSQLiteHeader(destination) {
		t.Fatal("reused baseline copy is not byte-identical standalone SQLite")
	}

	for name, test := range map[string]struct {
		accountID    string
		relativePath string
		prior        baselineDatabase
	}{
		"parent traversal": {
			accountID:    accountID,
			relativePath: "../escape.db",
			prior:        prior,
		},
		"alternate data stream": {
			accountID:    accountID,
			relativePath: "Msg/MicroMsg.db:stream",
			prior:        prior,
		},
		"mismatched output path": {
			accountID:    accountID,
			relativePath: relativePath,
			prior: func() baselineDatabase {
				changed := prior
				changed.OutputPath = accountID + "/Msg/Other.db"
				return changed
			}(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalidDestination := filepath.Join(t.TempDir(), "output.db")
			if _, _, _, err := reuseBaselineSQLite(
				root,
				test.accountID,
				test.relativePath,
				invalidDestination,
				test.prior,
			); err == nil {
				t.Fatal("unsafe reusable baseline path unexpectedly succeeded")
			}
			if _, err := os.Stat(invalidDestination); !os.IsNotExist(err) {
				t.Fatalf("unsafe reusable baseline path created output: %v", err)
			}
		})
	}

	insertSQLiteBackupContact(t, baselinePath, 2, "TAMPERED_BASELINE")
	tamperedDestination := filepath.Join(t.TempDir(), "tampered.db")
	if _, _, _, err := reuseBaselineSQLite(root, accountID, relativePath, tamperedDestination, prior); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "manifest") {
		t.Fatalf("tampered reusable baseline did not fail against its manifest proof: %v", err)
	}
	if _, err := os.Stat(tamperedDestination); !os.IsNotExist(err) {
		t.Fatalf("tampered reusable baseline created output: %v", err)
	}
}

func insertSQLiteBackupContact(t *testing.T, path string, id int, name string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open SQLite fixture for mutation: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO contacts(id, name, note, nullable) VALUES (?, ?, X'010203', NULL)",
		id,
		name,
	); err != nil {
		_ = database.Close()
		t.Fatalf("mutate SQLite fixture: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close mutated SQLite fixture: %v", err)
	}
}

func TestStrictSQLiteBackupDeltaStagesOnlyChangedAndAddedDatabases(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	unchangedSource := filepath.Join(dataDir, "Msg", "Unchanged.db")
	changedSource := filepath.Join(dataDir, "Msg", "Changed.db")
	removedSource := filepath.Join(dataDir, "Msg", "Removed.db")
	for _, path := range []string{unchangedSource, changedSource, removedSource} {
		createSQLiteBackupFixture(t, path)
	}

	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account:  "delta-fixture",
		Platform: "windows",
		Version:  3,
		DataDir:  dataDir,
	}}})
	if err != nil {
		t.Fatalf("marshal strict delta config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write strict delta config: %v", err)
	}
	options := prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        filepath.Join(root, "published-backup"),
	}
	fullManifest, err := prepare(filepath.Join(root, "full-stage"), configPath, "", nil, options)
	if err != nil {
		t.Fatalf("prepare full strict backup baseline: %v", err)
	}
	baseline := baselineFromStrictSQLiteManifest(t, fullManifest)
	prior := baseline[canonicalPath(dataDir)]

	insertSQLiteBackupContact(t, changedSource, 2, "CHANGED")
	if err := os.Remove(removedSource); err != nil {
		t.Fatalf("remove baseline database fixture: %v", err)
	}
	addedSource := filepath.Join(dataDir, "Msg", "Added.db")
	createSQLiteBackupFixture(t, addedSource)

	deltaStage := filepath.Join(root, "delta-stage")
	deltaManifest, err := prepare(deltaStage, configPath, "", baseline, options)
	if err != nil {
		t.Fatalf("prepare strict delta backup: %v", err)
	}
	if deltaManifest.Status != "complete" || len(deltaManifest.Unresolved) != 0 || len(deltaManifest.Accounts) != 1 {
		t.Fatalf("unexpected strict delta manifest: %+v", deltaManifest)
	}
	account := deltaManifest.Accounts[0]
	if account.ID != prior.ID {
		t.Fatalf("delta changed the stable account output ID: got=%q want=%q", account.ID, prior.ID)
	}
	byPath := make(map[string]manifestDatabase, len(account.Databases))
	for _, database := range account.Databases {
		byPath[baselineRelativePath(database.RelativePath)] = database
	}
	if len(byPath) != 3 {
		t.Fatalf("delta database inventory has %d entries, want 3: %+v", len(byPath), account.Databases)
	}
	if _, exists := byPath[baselineRelativePath("Msg/Removed.db")]; exists {
		t.Fatal("removed database remained in the strict delta inventory")
	}

	unchanged := byPath[baselineRelativePath("Msg/Unchanged.db")]
	priorUnchanged := prior.Databases[baselineRelativePath("Msg/Unchanged.db")]
	if unchanged.Status != "unchanged" || unchanged.StagedPath != "" ||
		unchanged.SourceSHA256 != priorUnchanged.SourceSHA256 ||
		unchanged.SnapshotSize != priorUnchanged.SnapshotSize ||
		unchanged.SnapshotSHA256 != priorUnchanged.SnapshotSHA256 {
		t.Fatalf("unchanged database was not safely reused from its proof: %+v", unchanged)
	}
	if _, err := os.Stat(filepath.Join(deltaStage, account.ID, "Msg", "Unchanged.db")); !os.IsNotExist(err) {
		t.Fatalf("unchanged database was unnecessarily staged: %v", err)
	}

	changed := byPath[baselineRelativePath("Msg/Changed.db")]
	priorChanged := prior.Databases[baselineRelativePath("Msg/Changed.db")]
	if changed.Status != "ok" || changed.StagedPath == "" || changed.SourceSHA256 == priorChanged.SourceSHA256 ||
		changed.SnapshotSHA256 == priorChanged.SnapshotSHA256 {
		t.Fatalf("changed database was not restaged with new proofs: %+v", changed)
	}
	if err := verifySQLiteIntegrity(changed.StagedPath); err != nil {
		t.Fatalf("changed delta snapshot failed SQLite integrity verification: %v", err)
	}
	added := byPath[baselineRelativePath("Msg/Added.db")]
	if added.Status != "ok" || added.StagedPath == "" || !validSHA256(added.SourceSHA256) ||
		!validSHA256(added.SnapshotSHA256) || !validSHA256(added.FileSHA256) {
		t.Fatalf("added database was not staged with complete proofs: %+v", added)
	}
	if err := verifySQLiteIntegrity(added.StagedPath); err != nil {
		t.Fatalf("added delta snapshot failed SQLite integrity verification: %v", err)
	}
}

func TestStrictSQLiteBackupDeltaRevalidatesUnchangedSourceBeforePublication(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	source := filepath.Join(dataDir, "Msg", "MicroMsg.db")
	createSQLiteBackupFixture(t, source)
	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account:  "delta-race-fixture",
		Platform: "windows",
		Version:  3,
		DataDir:  dataDir,
	}}})
	if err != nil {
		t.Fatalf("marshal strict delta race config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write strict delta race config: %v", err)
	}
	options := prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        filepath.Join(root, "published-backup"),
	}
	fullManifest, err := prepare(filepath.Join(root, "full-stage"), configPath, "", nil, options)
	if err != nil {
		t.Fatalf("prepare strict delta race baseline: %v", err)
	}
	baseline := baselineFromStrictSQLiteManifest(t, fullManifest)
	options.beforeFinalSourceCheck = func() {
		insertSQLiteBackupContact(t, source, 2, "LATE_DELTA_CHANGE")
	}
	deltaManifest, err := prepare(filepath.Join(root, "delta-stage"), configPath, "", baseline, options)
	if err == nil || deltaManifest == nil || deltaManifest.Status != "partial" {
		t.Fatalf("late change to unchanged delta source unexpectedly passed: manifest=%+v err=%v", deltaManifest, err)
	}
	found := false
	for _, problem := range deltaManifest.Unresolved {
		if strings.Contains(strings.ToLower(problem.Reason), "source") &&
			strings.Contains(strings.ToLower(problem.Reason), "changed") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("late change to unchanged delta source was not reported clearly: %+v", deltaManifest.Unresolved)
	}
}

func TestStrictSQLiteBackupRejectsMissingEmptyConfigAndSourceOverlapBeforeStaging(t *testing.T) {
	root := t.TempDir()
	options := prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        filepath.Join(root, "destination"),
	}
	stage := filepath.Join(root, "stage")
	if _, err := prepare(stage, filepath.Join(root, "missing.json"), "", nil, options); err == nil {
		t.Fatal("missing central config unexpectedly succeeded")
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage was created before config validation: %v", err)
	}

	emptyConfig := filepath.Join(root, "empty.json")
	if err := os.WriteFile(emptyConfig, []byte(`{"history":[]}`), 0o600); err != nil {
		t.Fatalf("write empty config: %v", err)
	}
	if _, err := prepare(stage, emptyConfig, "", nil, options); err == nil || !strings.Contains(err.Error(), "no account history") {
		t.Fatalf("empty central config error is not actionable: %v", err)
	}

	dataDir := filepath.Join(root, "source")
	createSQLiteBackupFixture(t, filepath.Join(dataDir, "Msg", "MicroMsg.db"))
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account: "overlap",
		Version: 3,
		DataDir: dataDir,
	}}})
	if err != nil {
		t.Fatalf("marshal overlap config: %v", err)
	}
	if err := os.WriteFile(emptyConfig, configJSON, 0o600); err != nil {
		t.Fatalf("write overlap config: %v", err)
	}
	options.DestinationRoot = filepath.Join(dataDir, "backup-inside-source")
	manifest, err := prepare(stage, emptyConfig, "", nil, options)
	if err == nil || manifest == nil || len(manifest.Unresolved) == 0 ||
		!strings.Contains(manifest.Unresolved[0].Reason, "must not contain") {
		t.Fatalf("source/destination overlap was not rejected clearly: manifest=%+v err=%v", manifest, err)
	}
	if _, statErr := os.Stat(stage); !os.IsNotExist(statErr) {
		t.Fatalf("stage was created despite source overlap: %v", statErr)
	}
}

func TestSameDatabaseInventoryDetectsAddedRemovedAndRenamedFiles(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "A.db")
	b := filepath.Join(root, "nested", "B.DB")
	c := filepath.Join(root, "C.db")
	if !sameDatabaseInventory([]string{a, b}, []string{b, a}) {
		t.Fatal("ordering alone changed the database inventory")
	}
	for name, right := range map[string][]string{
		"added":   {a, b, c},
		"removed": {a},
		"renamed": {a, c},
	} {
		if sameDatabaseInventory([]string{a, b}, right) {
			t.Fatalf("%s database inventory change was not detected", name)
		}
	}
}

func TestStrictSQLiteBackupFinalSourcePassRejectsLateContentAndInventoryChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "earlier database content changed",
			mutate: func(t *testing.T, dataDir string) {
				t.Helper()
				path := filepath.Join(dataDir, "Msg", "MicroMsg.db")
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read source for late mutation: %v", err)
				}
				if err := os.WriteFile(path, append(contents, 0x7f), 0o600); err != nil {
					t.Fatalf("mutate source after staging: %v", err)
				}
			},
		},
		{
			name: "database added after account staging",
			mutate: func(t *testing.T, dataDir string) {
				t.Helper()
				createSQLiteBackupFixture(t, filepath.Join(dataDir, "Msg", "late-added.DB"))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "account")
			createSQLiteBackupFixture(t, filepath.Join(dataDir, "Msg", "MicroMsg.db"))
			configPath := filepath.Join(root, "chatlog.json")
			configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
				Account:  "late-change",
				Platform: "windows",
				Version:  3,
				DataDir:  dataDir,
			}}})
			if err != nil {
				t.Fatalf("marshal late-change config: %v", err)
			}
			if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
				t.Fatalf("write late-change config: %v", err)
			}
			stage := filepath.Join(root, "stage")
			manifest, err := prepare(stage, configPath, "", nil, prepareOptions{
				ConfiguredAccountsOnly: true,
				CentralConfigOnly:      true,
				VerifySQLite:           true,
				DestinationRoot:        filepath.Join(root, "destination"),
				beforeFinalSourceCheck: func() { test.mutate(t, dataDir) },
			})
			if err == nil || manifest == nil || manifest.Status != "partial" || len(manifest.Unresolved) == 0 {
				t.Fatalf("late source change unexpectedly passed: manifest=%+v err=%v", manifest, err)
			}
			found := false
			for _, problem := range manifest.Unresolved {
				if strings.Contains(problem.Reason, "changed") || strings.Contains(problem.Reason, "sources") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("late source change was not reported clearly: %+v", manifest.Unresolved)
			}
		})
	}
}

func TestPrepareDatabaseRejectsTruncatedEncryptedPage(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "truncated.db")
	if err := os.WriteFile(source, bytes.Repeat([]byte{0x7f}, 4097), 0o600); err != nil {
		t.Fatalf("write truncated encrypted fixture: %v", err)
	}
	err := prepareDatabase(source, filepath.Join(directory, "out.db"), candidate{
		Platform: "windows",
		Version:  3,
		DataKey:  strings.Repeat("00", 32),
	})
	if err == nil || !strings.Contains(err.Error(), "positive multiple") {
		t.Fatalf("truncated encrypted source was not rejected before decryption: %v", err)
	}
}

func TestStrictSQLiteBackupRequiresSeparateKeyForEncryptedBackupDatabase(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	backupDatabase := filepath.Join(dataDir, "BackupFiles", "device", "Backup.db")
	if err := os.MkdirAll(filepath.Dir(backupDatabase), 0o700); err != nil {
		t.Fatalf("create encrypted backup fixture directory: %v", err)
	}
	if err := os.WriteFile(backupDatabase, bytes.Repeat([]byte{0x5a}, 4096), 0o600); err != nil {
		t.Fatalf("write encrypted backup fixture: %v", err)
	}
	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account:  "phone-backup",
		Platform: "windows",
		Version:  3,
		DataDir:  dataDir,
	}}})
	if err != nil {
		t.Fatalf("marshal encrypted backup config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write encrypted backup config: %v", err)
	}
	stage := filepath.Join(root, "stage")
	manifest, err := prepare(stage, configPath, "", nil, prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        filepath.Join(root, "destination"),
	})
	if err == nil || manifest == nil {
		t.Fatalf("encrypted Backup.db unexpectedly succeeded without its separate key: %v", err)
	}
	found := false
	for _, problem := range manifest.Unresolved {
		if strings.Contains(problem.Reason, "separate phone-backup key") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing phone-backup key error is not actionable: %+v", manifest.Unresolved)
	}
	if _, statErr := os.Stat(stage); !os.IsNotExist(statErr) {
		t.Fatalf("stage was created before phone-backup key preflight completed: %v", statErr)
	}
}

func TestResolveBackupKeyUsesValidatedConfigFallbackAndExplicitOverride(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "chatlog.json")
	cachedKeyUpper := strings.Repeat("AB", 32)
	configJSON := []byte(`{
  "sentinel": {"keep": true},
  "backup_key": "` + cachedKeyUpper + `",
  "history": []
}`)
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write cached backup key config: %v", err)
	}

	resolved, err := resolveBackupKey("", configPath)
	if err != nil {
		t.Fatalf("resolve cached backup key: %v", err)
	}
	if resolved != strings.ToLower(cachedKeyUpper) {
		t.Fatalf("cached backup key was not normalized: %q", resolved)
	}

	explicitKeyUpper := strings.Repeat("CD", 32)
	explicitPath := filepath.Join(root, "explicit-backup-key.txt")
	if err := os.WriteFile(explicitPath, []byte(" \r\n"+explicitKeyUpper+"\r\n"), 0o600); err != nil {
		t.Fatalf("write explicit backup key: %v", err)
	}
	// An explicit key must win without consulting chatlog.json. Making the
	// config malformed catches accidental fallback parsing on this path.
	if err := os.WriteFile(configPath, []byte(`{"backup_key":`), 0o600); err != nil {
		t.Fatalf("write malformed config for explicit precedence: %v", err)
	}
	resolved, err = resolveBackupKey(explicitPath, configPath)
	if err != nil {
		t.Fatalf("resolve explicit backup key without consulting config: %v", err)
	}
	if resolved != strings.ToLower(explicitKeyUpper) {
		t.Fatalf("explicit backup key did not override the cache: %q", resolved)
	}
}

func TestResolveBackupKeyUsesDefaultCentralCache(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CHATLOG_DIR", root)
	cachedKeyUpper := strings.Repeat("9A", 32)
	configJSON, err := json.Marshal(storedConfig{BackupKey: cachedKeyUpper})
	if err != nil {
		t.Fatalf("marshal default cached backup key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "chatlog.json"), configJSON, 0o600); err != nil {
		t.Fatalf("write default cached backup key: %v", err)
	}

	resolved, err := resolveBackupKey("", "")
	if err != nil {
		t.Fatalf("resolve backup key from default central cache: %v", err)
	}
	if resolved != strings.ToLower(cachedKeyUpper) {
		t.Fatalf("default cached backup key was not normalized: %q", resolved)
	}
}

func TestResolveBackupKeyValidatesCachedField(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "chatlog.json")
	invalidSecret := "LEAK-ME-NEVER-" + strings.Repeat("z", 64)
	tests := []struct {
		name        string
		content     string
		wantEmpty   bool
		wantProblem string
		secret      string
	}{
		{name: "field absent permits recovery", content: `{"history":[]}`, wantEmpty: true},
		{name: "empty field permits recovery", content: `{"backup_key":"", "history":[]}`, wantEmpty: true},
		{name: "wrong type", content: `{"backup_key":42}`, wantProblem: "backup_key"},
		{name: "short hexadecimal value", content: `{"backup_key":"abcd"}`, wantProblem: "32-byte hexadecimal"},
		{name: "non hexadecimal value", content: `{"backup_key":"` + invalidSecret + `"}`, wantProblem: "32-byte hexadecimal", secret: invalidSecret},
		{name: "malformed config", content: `{"backup_key":`, wantProblem: "parse"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(configPath, []byte(test.content), 0o600); err != nil {
				t.Fatalf("write config fixture: %v", err)
			}
			resolved, err := resolveBackupKey("", configPath)
			if test.wantProblem != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantProblem)) {
					t.Fatalf("cached backup key validation error = %v, want text %q", err, test.wantProblem)
				}
				if test.secret != "" && strings.Contains(err.Error(), test.secret) {
					t.Fatalf("cached backup key validation error disclosed the rejected value: %v", err)
				}
				if resolved != "" {
					t.Fatalf("invalid cached backup key was returned: %q", resolved)
				}
				return
			}
			if err != nil || !test.wantEmpty || resolved != "" {
				t.Fatalf("optional cached backup key = %q, %v; want empty success", resolved, err)
			}
		})
	}
}

func TestMergeBackupKeyJSONPreservesConfigAndIsIdempotent(t *testing.T) {
	firstKeyUpper := strings.Repeat("EF", 32)
	secondKeyUpper := strings.Repeat("A1", 32)
	existing := []byte(`{
  "first_unknown": {"nested": [1, 2]},
  "backup_key": "` + firstKeyUpper + `",
  "BackupFiles": {"mode": "external", "sentinel": "keep"},
  "history": [{"account":"fixture","data_dir":"C:\\\\fixture","data_key":"keep-account-key","custom":true}],
  "last_unknown": "keep-tail"
}`)

	updated, err := mergeBackupKeyJSON(existing, secondKeyUpper)
	if err != nil {
		t.Fatalf("merge cached backup key: %v", err)
	}
	text := string(updated)
	for _, field := range []string{"first_unknown", "backup_key", "BackupFiles", "history", "last_unknown"} {
		if !strings.Contains(text, `"`+field+`"`) {
			t.Fatalf("config field %q was removed", field)
		}
	}
	if !(strings.Index(text, `"first_unknown"`) < strings.Index(text, `"backup_key"`) &&
		strings.Index(text, `"backup_key"`) < strings.Index(text, `"BackupFiles"`) &&
		strings.Index(text, `"BackupFiles"`) < strings.Index(text, `"history"`) &&
		strings.Index(text, `"history"`) < strings.Index(text, `"last_unknown"`)) {
		t.Fatalf("top-level field order changed:\n%s", text)
	}

	var decoded struct {
		BackupKey   string                   `json:"backup_key"`
		BackupFiles map[string]string        `json:"BackupFiles"`
		History     []map[string]interface{} `json:"history"`
		LastUnknown string                   `json:"last_unknown"`
	}
	if err := json.Unmarshal(updated, &decoded); err != nil {
		t.Fatalf("decode merged backup key config: %v", err)
	}
	if decoded.BackupKey != strings.ToLower(secondKeyUpper) ||
		decoded.BackupFiles["sentinel"] != "keep" || decoded.LastUnknown != "keep-tail" ||
		len(decoded.History) != 1 || decoded.History[0]["data_key"] != "keep-account-key" || decoded.History[0]["custom"] != true {
		t.Fatalf("backup key merge changed unrelated configuration: %#v", decoded)
	}

	repeated, err := mergeBackupKeyJSON(updated, strings.ToLower(secondKeyUpper))
	if err != nil {
		t.Fatalf("repeat cached backup key merge: %v", err)
	}
	if !bytes.Equal(updated, repeated) {
		t.Fatal("repeating the same backup key merge was not idempotent")
	}

	added, err := mergeBackupKeyJSON([]byte(`{"before":1,"history":[],"after":2}`), firstKeyUpper)
	if err != nil {
		t.Fatalf("add missing cached backup key: %v", err)
	}
	var addedConfig storedConfig
	if err := json.Unmarshal(added, &addedConfig); err != nil || addedConfig.BackupKey != strings.ToLower(firstKeyUpper) {
		t.Fatalf("missing top-level backup_key was not added: %s", added)
	}
	if _, err := mergeBackupKeyJSON(existing, "not-a-key"); err == nil || !strings.Contains(err.Error(), "32-byte hexadecimal") {
		t.Fatalf("invalid backup key was accepted for persistence: %v", err)
	}
}

func TestPrepareDatabaseIncorporatesCommittedEncryptedWALLosslessly(t *testing.T) {
	directory := t.TempDir()
	fixture := createEncryptedWALFixture(t, directory)
	destination := filepath.Join(directory, "standalone.db")
	sourceBefore, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatalf("read encrypted source before staging: %v", err)
	}
	walBefore, err := os.ReadFile(fixture.source + "-wal")
	if err != nil {
		t.Fatalf("read encrypted WAL before staging: %v", err)
	}

	err = prepareDatabase(fixture.source, destination, candidate{
		Platform: "windows",
		Version:  3,
		DataKey:  fixture.keyHex,
	})
	if err != nil {
		t.Fatalf("stage encrypted database with committed WAL: %v", err)
	}
	if err := verifySQLiteIntegrity(destination); err != nil {
		t.Fatalf("committed encrypted WAL output failed integrity_check: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if info, statErr := os.Stat(destination + suffix); !os.IsNotExist(statErr) {
			t.Fatalf("standalone encrypted WAL output retained %s sidecar: info=%v err=%v", suffix, info, statErr)
		}
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(destination)+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatalf("open standalone encrypted WAL output: %v", err)
	}
	defer database.Close()
	rows, err := database.Query("SELECT id, value, hex(payload) FROM events ORDER BY id")
	if err != nil {
		t.Fatalf("query standalone encrypted WAL output: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id int
		var value, payload string
		if err := rows.Scan(&id, &value, &payload); err != nil {
			t.Fatalf("scan standalone encrypted WAL row: %v", err)
		}
		got = append(got, fmt.Sprintf("%d:%s:%s", id, value, payload))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read standalone encrypted WAL rows: %v", err)
	}
	want := []string{"1:BASE_VALUE:000102FF", "2:COMMITTED_VALUE:10203040"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("committed encrypted WAL content changed: got=%v want=%v", got, want)
	}
	sourceAfter, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatalf("read encrypted source after staging: %v", err)
	}
	walAfter, err := os.ReadFile(fixture.source + "-wal")
	if err != nil {
		t.Fatalf("read encrypted WAL after staging: %v", err)
	}
	if !bytes.Equal(sourceBefore, sourceAfter) || !bytes.Equal(walBefore, walAfter) {
		t.Fatal("encrypted WAL staging modified its source database or WAL")
	}
}

func TestPrepareDatabaseIgnoresValidTrailingUncommittedEncryptedWALFrames(t *testing.T) {
	directory := t.TempDir()
	fixture := createEncryptedWALFixture(t, directory)
	withUncommitted := appendUncommittedTestWALFrame(t, fixture.plaintextWAL)
	encryptedWAL := encryptTestWechatWAL(t, withUncommitted, fixture.key, fixture.salt)
	if err := os.WriteFile(fixture.source+"-wal", encryptedWAL, 0o600); err != nil {
		t.Fatalf("write encrypted WAL with trailing uncommitted frame: %v", err)
	}
	destination := filepath.Join(directory, "standalone.db")
	if err := prepareDatabase(fixture.source, destination, candidate{
		Platform: "windows",
		Version:  3,
		DataKey:  fixture.keyHex,
	}); err != nil {
		t.Fatalf("stage encrypted WAL with valid uncommitted tail: %v", err)
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(destination)+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatalf("open uncommitted-tail output: %v", err)
	}
	defer database.Close()
	var value string
	if err := database.QueryRow("SELECT value FROM events WHERE id=2").Scan(&value); err != nil {
		t.Fatalf("read committed value after ignoring WAL tail: %v", err)
	}
	if value != "COMMITTED_VALUE" || strings.Contains(value, "UNCOMMITTED") {
		t.Fatalf("uncommitted encrypted WAL frame leaked into output: %q", value)
	}
}

func TestPrepareDatabaseRejectsMalformedEncryptedWALWithoutPartialOutput(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*testing.T, []byte) []byte
		wantProblem string
	}{
		{
			name: "truncated frame",
			mutate: func(_ *testing.T, wal []byte) []byte {
				return wal[:len(wal)-1]
			},
			wantProblem: "wal",
		},
		{
			name: "invalid header magic",
			mutate: func(_ *testing.T, wal []byte) []byte {
				result := append([]byte(nil), wal...)
				result[0] ^= 0xff
				return result
			},
			wantProblem: "magic",
		},
		{
			name: "frame salt mismatch",
			mutate: func(_ *testing.T, wal []byte) []byte {
				result := append([]byte(nil), wal...)
				result[testWALHeaderSize+8] ^= 0xff
				return result
			},
			wantProblem: "salt",
		},
		{
			name: "frame checksum mismatch",
			mutate: func(_ *testing.T, wal []byte) []byte {
				result := append([]byte(nil), wal...)
				result[testWALHeaderSize+16] ^= 0xff
				return result
			},
			wantProblem: "checksum",
		},
		{
			name: "zero page number with valid rolling checksum",
			mutate: func(t *testing.T, wal []byte) []byte {
				result := append([]byte(nil), wal...)
				binary.BigEndian.PutUint32(result[testWALHeaderSize:testWALHeaderSize+4], 0)
				return rechecksumTestWAL(t, result)
			},
			wantProblem: "page",
		},
		{
			name: "encrypted page HMAC mismatch with valid rolling checksum",
			mutate: func(t *testing.T, wal []byte) []byte {
				result := append([]byte(nil), wal...)
				payloadOffset := testWALHeaderSize + testWALFrameHeaderSize
				result[payloadOffset+100] ^= 0xff
				return rechecksumTestWAL(t, result)
			},
			wantProblem: "verification",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			fixture := createEncryptedWALFixture(t, directory)
			wal, err := os.ReadFile(fixture.source + "-wal")
			if err != nil {
				t.Fatalf("read valid encrypted WAL fixture: %v", err)
			}
			if err := os.WriteFile(fixture.source+"-wal", test.mutate(t, wal), 0o600); err != nil {
				t.Fatalf("write malformed encrypted WAL fixture: %v", err)
			}
			destination := filepath.Join(directory, "must-not-exist.db")
			err = prepareDatabase(fixture.source, destination, candidate{
				Platform: "windows",
				Version:  3,
				DataKey:  fixture.keyHex,
			})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.wantProblem) {
				t.Fatalf("malformed encrypted WAL error = %v, want text %q", err, test.wantProblem)
			}
			assertNoDatabaseOutput(t, destination)
		})
	}
}

func TestStrictSQLiteBackupStagingFailureDoesNotClaimFinalSourceChanged(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	fixture := createEncryptedWALFixture(t, filepath.Join(dataDir, "Msg"))
	wal, err := os.ReadFile(fixture.source + "-wal")
	if err != nil {
		t.Fatalf("read encrypted WAL fixture: %v", err)
	}
	wal[testWALHeaderSize+8] ^= 0xff
	if err := os.WriteFile(fixture.source+"-wal", wal, 0o600); err != nil {
		t.Fatalf("write malformed encrypted WAL fixture: %v", err)
	}

	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account:  "wal-failure",
		Platform: "windows",
		Version:  3,
		DataDir:  dataDir,
		DataKey:  fixture.keyHex,
	}}})
	if err != nil {
		t.Fatalf("marshal strict backup config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write strict backup config: %v", err)
	}

	manifest, err := prepare(filepath.Join(root, "stage"), configPath, "", nil, prepareOptions{
		ConfiguredAccountsOnly: true,
		CentralConfigOnly:      true,
		VerifySQLite:           true,
		DestinationRoot:        filepath.Join(root, "destination"),
	})
	if err == nil || manifest == nil || manifest.Status != "partial" {
		t.Fatalf("malformed WAL unexpectedly passed strict backup: manifest=%+v err=%v", manifest, err)
	}
	foundStagingFailure := false
	for _, problem := range manifest.Unresolved {
		if problem.Reason == "one or more database paths could not be staged" {
			foundStagingFailure = true
		}
		if problem.Reason == "one or more sources changed before final SQLite backup validation" {
			t.Fatalf("staging failure was mislabeled as a final source change: %+v", manifest.Unresolved)
		}
	}
	if !foundStagingFailure {
		t.Fatalf("strict backup did not report its staging failure: %+v", manifest.Unresolved)
	}
}

func backupPowerShellTestPaths(t *testing.T) (string, string) {
	t.Helper()
	powerShell, err := exec.LookPath("pwsh.exe")
	if err != nil {
		powerShell, err = exec.LookPath("powershell.exe")
	}
	if err != nil {
		t.Skip("PowerShell is unavailable")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	for _, candidate := range []string{
		filepath.Join(workingDirectory, "backup_wechat_databases.ps1"),
		filepath.Join(workingDirectory, "scripts", "backup_wechat_databases.ps1"),
	} {
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			return powerShell, candidate
		}
	}
	t.Fatal("could not locate backup_wechat_databases.ps1")
	return "", ""
}

type portableBackupDatabaseTest struct {
	RelativePath         string `json:"relative_path"`
	OutputPath           string `json:"output_path"`
	ByteSize             int64  `json:"byte_size"`
	SHA256               string `json:"sha256"`
	IntegrityCheck       string `json:"integrity_check"`
	SourceSHA256         string `json:"source_sha256"`
	SnapshotSize         int64  `json:"snapshot_size"`
	SnapshotSHA256       string `json:"snapshot_sha256"`
	AuxiliarySHA256      string `json:"auxiliary_sha256"`
	LegacyPhoneBootstrap bool   `json:"legacy_phone_bootstrap"`
	DeltaStatus          string `json:"delta_status"`
}

type portableBackupManifestTest struct {
	FormatVersion      int    `json:"format_version"`
	Kind               string `json:"kind"`
	Mode               string `json:"mode"`
	DatabaseEncryption string `json:"database_encryption"`
	AccountCount       int    `json:"account_count"`
	DatabaseCount      int    `json:"database_count"`
	ReusedCount        int    `json:"reused_count"`
	ChangedCount       int    `json:"changed_count"`
	AddedCount         int    `json:"added_count"`
	RemovedCount       int    `json:"removed_count"`
	Accounts           []struct {
		ID        string                       `json:"id"`
		SourceID  string                       `json:"source_id"`
		Version   int                          `json:"version"`
		Databases []portableBackupDatabaseTest `json:"databases"`
	} `json:"accounts"`
}

func readPortableBackupManifest(t *testing.T, outputPath string) ([]byte, portableBackupManifestTest) {
	t.Helper()
	path := filepath.Join(outputPath, ".chatlog-sqlite-backup.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read portable backup manifest: %v", err)
	}
	var manifest portableBackupManifestTest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("parse portable backup manifest: %v", err)
	}
	return contents, manifest
}

func portableBackupDatabasesByPath(t *testing.T, manifest portableBackupManifestTest) map[string]portableBackupDatabaseTest {
	t.Helper()
	result := make(map[string]portableBackupDatabaseTest)
	for _, account := range manifest.Accounts {
		for _, database := range account.Databases {
			key := baselineRelativePath(database.RelativePath)
			if key == "" {
				t.Fatal("portable backup contains an empty database relative path")
			}
			if _, exists := result[key]; exists {
				t.Fatalf("portable backup contains duplicate database path: %s", database.RelativePath)
			}
			result[key] = database
		}
	}
	return result
}

func readBackupTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = contents
		return nil
	})
	if err != nil {
		t.Fatalf("read backup tree: %v", err)
	}
	return result
}

func assertNoBackupWorkArtifacts(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("list backup parent: %v", err)
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if strings.HasPrefix(name, ".chatlog-sqlite-backup-staging-") ||
			strings.HasPrefix(name, ".chatlog-sqlite-backup-rollback-") ||
			(strings.HasPrefix(name, ".chatlog-sqlite-backup-") && strings.HasSuffix(name, ".lock")) {
			t.Fatalf("backup wrapper left a staging, rollback, or lock artifact: %s", entry.Name())
		}
	}
}

func TestBackupPowerShellDeltaReusesAndReplacesCompleteKeyFreeTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PowerShell delta-backup subprocess test in short mode")
	}
	running, err := probeAllWeChatClients()
	if err != nil {
		t.Skipf("cannot safely verify WeChat process state: %v", err)
	}
	if len(running) != 0 {
		t.Skip("cannot run non-interactive delta-backup test while WeChat is running")
	}
	powerShell, scriptPath := backupPowerShellTestPaths(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "source-account")
	for _, relative := range []string{"Msg/Unchanged.db", "Msg/Changed.db", "Msg/Removed.db"} {
		createSQLiteBackupFixture(t, filepath.Join(dataDir, filepath.FromSlash(relative)))
	}
	dataKey := strings.Repeat("a3", 32)
	imageKey := "delta-image-key-must-not-leak"
	backupKey := strings.Repeat("b4", 32)
	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{
		BackupKey: backupKey,
		History: []storedAccount{{
			Account:  "delta-wrapper-fixture",
			Platform: "windows",
			Version:  3,
			DataDir:  dataDir,
			DataKey:  dataKey,
			ImgKey:   imageKey,
		}},
	})
	if err != nil {
		t.Fatalf("marshal delta wrapper config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write delta wrapper config: %v", err)
	}
	outputPath := filepath.Join(root, "published-delta-sqlite")
	run := func(extra ...string) ([]byte, error) {
		arguments := []string{
			"-NoProfile",
			"-NonInteractive",
			"-File", scriptPath,
			outputPath,
			"-ConfigPath", configPath,
		}
		arguments = append(arguments, extra...)
		command := exec.Command(powerShell, arguments...)
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		return command.CombinedOutput()
	}

	missingOutput, missingErr := run("-Delta")
	if missingErr == nil || !bytes.Contains(bytes.ToLower(missingOutput), []byte("delta")) ||
		!bytes.Contains(bytes.ToLower(missingOutput), []byte("existing")) {
		t.Fatalf("delta with a missing destination did not fail clearly: err=%v\n%s", missingErr, missingOutput)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("failed missing-destination delta created output: %v", err)
	}
	assertNoBackupWorkArtifacts(t, root)

	fullOutput, err := run()
	if err != nil {
		t.Fatalf("initial PowerShell SQLite backup failed: %v\n%s", err, fullOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(fullOutput, []byte(secret)) {
			t.Fatalf("initial backup output leaked a cached key: %q", secret)
		}
	}
	fullManifestJSON, fullManifest := readPortableBackupManifest(t, outputPath)
	if fullManifest.FormatVersion != 2 || fullManifest.Kind != "chatlog-decrypted-sqlite-backup" ||
		fullManifest.DatabaseEncryption != "none" || fullManifest.AccountCount != 1 ||
		fullManifest.DatabaseCount != 3 || len(fullManifest.Accounts) != 1 ||
		!validSHA256(fullManifest.Accounts[0].SourceID) {
		t.Fatalf("initial backup did not publish a reusable v2 manifest: %+v", fullManifest)
	}
	if bytes.Contains(bytes.ToLower(fullManifestJSON), bytes.ToLower([]byte(dataDir))) ||
		bytes.Contains(fullManifestJSON, []byte(`"data_dir"`)) {
		t.Fatal("public backup manifest disclosed an absolute source data directory")
	}
	var legacyDocument map[string]any
	if err := json.Unmarshal(fullManifestJSON, &legacyDocument); err != nil {
		t.Fatalf("decode v2 manifest for legacy refresh fixture: %v", err)
	}
	legacyDocument["format_version"] = 1
	legacyJSON, err := json.MarshalIndent(legacyDocument, "", "  ")
	if err != nil {
		t.Fatalf("encode legacy refresh fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputPath, ".chatlog-sqlite-backup.json"), append(legacyJSON, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy refresh fixture: %v", err)
	}
	legacyRefreshOutput, err := run("-Delta")
	if err != nil {
		t.Fatalf("legacy v1 one-time delta refresh failed: %v\n%s", err, legacyRefreshOutput)
	}
	lowerLegacyOutput := bytes.ToLower(legacyRefreshOutput)
	if !bytes.Contains(lowerLegacyOutput, []byte("legacy")) ||
		!bytes.Contains(lowerLegacyOutput, []byte("full refresh")) {
		t.Fatalf("legacy v1 refresh did not explain its no-reuse upgrade:\n%s", legacyRefreshOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(legacyRefreshOutput, []byte(secret)) {
			t.Fatalf("legacy refresh output leaked a cached key: %q", secret)
		}
	}
	fullManifestJSON, fullManifest = readPortableBackupManifest(t, outputPath)
	if fullManifest.FormatVersion != 2 || fullManifest.Mode != "delta" ||
		fullManifest.DatabaseCount != 3 || fullManifest.ReusedCount != 0 {
		t.Fatalf("legacy v1 delta did not publish a no-reuse v2 replacement: %+v", fullManifest)
	}
	if bytes.Contains(bytes.ToLower(fullManifestJSON), bytes.ToLower([]byte(dataDir))) ||
		bytes.Contains(fullManifestJSON, []byte(`"data_dir"`)) {
		t.Fatal("v1 refresh disclosed an absolute source data directory")
	}
	assertNoBackupWorkArtifacts(t, root)

	fullByPath := portableBackupDatabasesByPath(t, fullManifest)
	unchangedEntry := fullByPath[baselineRelativePath("Msg/Unchanged.db")]
	unchangedOutputPath := filepath.Join(outputPath, filepath.FromSlash(unchangedEntry.OutputPath))
	unchangedBefore, err := os.ReadFile(unchangedOutputPath)
	if err != nil {
		t.Fatalf("read initial unchanged backup: %v", err)
	}

	insertSQLiteBackupContact(t, filepath.Join(dataDir, "Msg", "Changed.db"), 2, "DELTA_CHANGED")
	if err := os.Remove(filepath.Join(dataDir, "Msg", "Removed.db")); err != nil {
		t.Fatalf("remove source database before delta: %v", err)
	}
	createSQLiteBackupFixture(t, filepath.Join(dataDir, "Msg", "Added.db"))

	deltaOutput, err := run("-Delta")
	if err != nil {
		t.Fatalf("PowerShell SQLite delta backup failed: %v\n%s", err, deltaOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(deltaOutput, []byte(secret)) {
			t.Fatalf("delta backup output leaked a cached key: %q", secret)
		}
	}
	portableJSON, deltaManifest := readPortableBackupManifest(t, outputPath)
	if deltaManifest.FormatVersion != 2 || deltaManifest.DatabaseCount != 3 ||
		deltaManifest.AccountCount != 1 || len(deltaManifest.Accounts) != 1 || deltaManifest.Mode != "delta" ||
		deltaManifest.ReusedCount != 1 || deltaManifest.ChangedCount != 1 ||
		deltaManifest.AddedCount != 1 || deltaManifest.RemovedCount != 1 {
		t.Fatalf("unexpected delta portable inventory: %+v; baseline=%+v", deltaManifest, fullManifest)
	}
	deltaByPath := portableBackupDatabasesByPath(t, deltaManifest)
	if len(deltaByPath) != 3 {
		t.Fatalf("delta portable inventory has %d database entries, want 3", len(deltaByPath))
	}
	if _, exists := deltaByPath[baselineRelativePath("Msg/Removed.db")]; exists {
		t.Fatal("removed source database remained in the published delta backup")
	}
	if deltaByPath[baselineRelativePath("Msg/Unchanged.db")].DeltaStatus != "reused" ||
		deltaByPath[baselineRelativePath("Msg/Changed.db")].DeltaStatus != "changed" ||
		deltaByPath[baselineRelativePath("Msg/Added.db")].DeltaStatus != "added" {
		t.Fatalf("delta status classification is incorrect: %+v", deltaByPath)
	}
	for _, relative := range []string{"Msg/Unchanged.db", "Msg/Changed.db", "Msg/Added.db"} {
		entry, exists := deltaByPath[baselineRelativePath(relative)]
		if !exists {
			t.Fatalf("published delta backup is missing %s", relative)
		}
		publishedPath := filepath.Join(outputPath, filepath.FromSlash(entry.OutputPath))
		contents, err := os.ReadFile(publishedPath)
		if err != nil {
			t.Fatalf("read published delta database %s: %v", relative, err)
		}
		digest := sha256.Sum256(contents)
		if entry.ByteSize != int64(len(contents)) || entry.SnapshotSize != int64(len(contents)) ||
			entry.SHA256 != hex.EncodeToString(digest[:]) || entry.IntegrityCheck != "ok" ||
			!validSHA256(entry.SourceSHA256) || !validSHA256(entry.SnapshotSHA256) {
			t.Fatalf("delta manifest proof is incomplete for %s: %+v", relative, entry)
		}
		if err := verifySQLiteIntegrity(publishedPath); err != nil {
			t.Fatalf("published delta database %s failed integrity verification: %v", relative, err)
		}
	}
	unchangedAfter, err := os.ReadFile(filepath.Join(
		outputPath,
		filepath.FromSlash(deltaByPath[baselineRelativePath("Msg/Unchanged.db")].OutputPath),
	))
	if err != nil {
		t.Fatalf("read unchanged database after delta: %v", err)
	}
	if !bytes.Equal(unchangedBefore, unchangedAfter) {
		t.Fatal("delta changed the bytes of an unchanged SQLite backup")
	}
	changedDatabase, err := sql.Open(
		"sqlite",
		"file:"+filepath.ToSlash(filepath.Join(outputPath, filepath.FromSlash(deltaByPath[baselineRelativePath("Msg/Changed.db")].OutputPath)))+"?mode=ro&immutable=1",
	)
	if err != nil {
		t.Fatalf("open changed published delta database: %v", err)
	}
	var changedRows int
	queryErr := changedDatabase.QueryRow("SELECT count(*) FROM contacts").Scan(&changedRows)
	closeErr := changedDatabase.Close()
	if queryErr != nil || closeErr != nil || changedRows != 2 {
		t.Fatalf("changed database contents were not refreshed: rows=%d query=%v close=%v", changedRows, queryErr, closeErr)
	}
	for relative, contents := range readBackupTree(t, outputPath) {
		lower := strings.ToLower(relative)
		if strings.HasSuffix(lower, ".db-wal") || strings.HasSuffix(lower, ".db-shm") || strings.HasSuffix(lower, ".db-journal") {
			t.Fatalf("published delta backup contains a SQLite sidecar: %s", relative)
		}
		for _, secret := range []string{dataKey, imageKey, backupKey, `"data_key"`, `"img_key"`, `"backup_key"`} {
			if bytes.Contains(contents, []byte(secret)) {
				t.Fatalf("published delta tree leaks key marker %q in %s", secret, relative)
			}
		}
	}

	changedEntry := deltaByPath[baselineRelativePath("Msg/Changed.db")]
	tamperedJSON := bytes.Replace(
		portableJSON,
		[]byte(changedEntry.SHA256),
		[]byte(strings.Repeat("0", sha256.Size*2)),
		1,
	)
	if bytes.Equal(tamperedJSON, portableJSON) {
		t.Fatal("could not tamper portable manifest digest fixture")
	}
	portableManifestPath := filepath.Join(outputPath, ".chatlog-sqlite-backup.json")
	if err := os.WriteFile(portableManifestPath, tamperedJSON, 0o600); err != nil {
		t.Fatalf("tamper portable manifest: %v", err)
	}
	tamperedTree := readBackupTree(t, outputPath)
	rejectedOutput, rejectedErr := run("-Delta")
	if rejectedErr == nil {
		t.Fatalf("delta unexpectedly accepted a tampered backup manifest:\n%s", rejectedOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(rejectedOutput, []byte(secret)) {
			t.Fatalf("rejected delta output leaked a cached key: %q", secret)
		}
	}
	if afterRejected := readBackupTree(t, outputPath); !reflect.DeepEqual(tamperedTree, afterRejected) {
		t.Fatal("failed delta modified the existing backup tree")
	}
	assertNoBackupWorkArtifacts(t, root)
}

func TestBackupPowerShellAclLessFilesystemRequiresAcknowledgementAndSkipsImpossibleAcl(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PowerShell filesystem-policy subprocess test in short mode")
	}
	powerShell, scriptPath := backupPowerShellTestPaths(t)
	query := `$drive = [IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveFormat -in @('exFAT','FAT','FAT32') } | Select-Object -First 1; if ($null -ne $drive) { $drive.RootDirectory.FullName }`
	rootOutput, err := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", query).CombinedOutput()
	if err != nil {
		t.Skipf("could not enumerate ACL-less filesystems: %v", err)
	}
	aclLessRoot := strings.TrimSpace(string(rootOutput))
	if aclLessRoot == "" {
		t.Skip("no ready FAT/exFAT filesystem is available")
	}

	fixtureRoot := t.TempDir()
	dataDir := filepath.Join(fixtureRoot, "empty-account")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("create empty configured account: %v", err)
	}
	configPath := filepath.Join(fixtureRoot, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{History: []storedAccount{{
		Account:  "acl-less-fixture",
		Platform: "windows",
		Version:  3,
		DataDir:  dataDir,
	}}})
	if err != nil {
		t.Fatalf("marshal ACL-less filesystem config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write ACL-less filesystem config: %v", err)
	}
	targetName := ".chatlog-acl-policy-test-" + shortHash(fixtureRoot)
	outputPath := filepath.Join(aclLessRoot, targetName)
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("ACL-less policy target unexpectedly exists before test: %s", outputPath)
	}
	t.Cleanup(func() {
		if filepath.Dir(outputPath) == filepath.Clean(aclLessRoot) && strings.HasPrefix(filepath.Base(outputPath), ".chatlog-acl-policy-test-") {
			_ = os.RemoveAll(outputPath)
		}
	})

	run := func(extra ...string) ([]byte, error) {
		arguments := []string{"-NoProfile", "-NonInteractive", "-File", scriptPath, outputPath, "-ConfigPath", configPath}
		arguments = append(arguments, extra...)
		command := exec.Command(powerShell, arguments...)
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		return command.CombinedOutput()
	}

	withoutAcknowledgement, withoutErr := run()
	if withoutErr == nil || !bytes.Contains(withoutAcknowledgement, []byte("-AllowUnprotectedFileSystem")) ||
		!bytes.Contains(bytes.ToLower(withoutAcknowledgement), []byte("cannot enforce private windows acls")) {
		t.Fatalf("ACL-less destination did not fail with actionable acknowledgement instructions: err=%v\n%s", withoutErr, withoutAcknowledgement)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("unacknowledged ACL-less run created output: %v", err)
	}

	acknowledgedOutput, acknowledgedErr := run("-AllowUnprotectedFileSystem")
	if acknowledgedErr == nil {
		t.Fatal("empty database fixture unexpectedly completed a backup")
	}
	lowerOutput := bytes.ToLower(acknowledgedOutput)
	if bytes.Contains(lowerOutput, []byte("still inherits permissions")) ||
		!bytes.Contains(lowerOutput, []byte("cannot enforce private windows acls")) ||
		!bytes.Contains(lowerOutput, []byte("no database files")) {
		t.Fatalf("acknowledged ACL-less run did not bypass only the impossible ACL check: err=%v\n%s", acknowledgedErr, acknowledgedOutput)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("failed acknowledged ACL-less run published output: %v", err)
	}
}

func TestBackupPowerShellPublishesKeyFreeTreeAndRefusesExistingTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PowerShell subprocess backup in short mode")
	}
	running, err := probeAllWeChatClients()
	if err != nil {
		t.Skipf("cannot safely verify WeChat process state: %v", err)
	}
	if len(running) != 0 {
		t.Skip("cannot run non-interactive backup wrapper test while WeChat is running")
	}
	powerShell, scriptPath := backupPowerShellTestPaths(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "source-account")
	source := filepath.Join(dataDir, "Msg", "MicroMsg.db")
	createSQLiteBackupFixture(t, source)
	sourceBefore, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source before wrapper backup: %v", err)
	}
	dataKey := strings.Repeat("e1", 32)
	imageKey := "wrapper-image-key-must-not-leak"
	backupKey := strings.Repeat("f2", 32)
	configPath := filepath.Join(root, "chatlog.json")
	configJSON, err := json.Marshal(storedConfig{
		BackupKey: backupKey,
		History: []storedAccount{{
			Account:  "wrapper-fixture",
			Platform: "windows",
			Version:  3,
			DataDir:  dataDir,
			DataKey:  dataKey,
			ImgKey:   imageKey,
		}},
	})
	if err != nil {
		t.Fatalf("marshal wrapper config: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write wrapper config: %v", err)
	}
	outputPath := filepath.Join(root, "published-sqlite")

	run := func() ([]byte, error) {
		command := exec.Command(
			powerShell,
			"-NoProfile",
			"-NonInteractive",
			"-File", scriptPath,
			outputPath,
			"-ConfigPath", configPath,
		)
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		return command.CombinedOutput()
	}
	firstOutput, err := run()
	if err != nil {
		t.Fatalf("PowerShell SQLite backup failed: %v\n%s", err, firstOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(firstOutput, []byte(secret)) {
			t.Fatalf("backup subprocess output leaked a cached key: %q", secret)
		}
	}

	portableManifestPath := filepath.Join(outputPath, ".chatlog-sqlite-backup.json")
	portableJSON, err := os.ReadFile(portableManifestPath)
	if err != nil {
		t.Fatalf("read portable backup manifest: %v", err)
	}
	var portable struct {
		Kind               string `json:"kind"`
		DatabaseEncryption string `json:"database_encryption"`
		DatabaseCount      int    `json:"database_count"`
		Accounts           []struct {
			Databases []struct {
				OutputPath     string `json:"output_path"`
				ByteSize       int64  `json:"byte_size"`
				SHA256         string `json:"sha256"`
				IntegrityCheck string `json:"integrity_check"`
			} `json:"databases"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(portableJSON, &portable); err != nil {
		t.Fatalf("parse portable backup manifest: %v", err)
	}
	if portable.Kind != "chatlog-decrypted-sqlite-backup" || portable.DatabaseEncryption != "none" ||
		portable.DatabaseCount != 1 || len(portable.Accounts) != 1 || len(portable.Accounts[0].Databases) != 1 {
		t.Fatalf("unexpected portable backup inventory: %+v", portable)
	}
	fileEntry := portable.Accounts[0].Databases[0]
	publishedDatabase := filepath.Join(outputPath, filepath.FromSlash(fileEntry.OutputPath))
	publishedBytes, err := os.ReadFile(publishedDatabase)
	if err != nil {
		t.Fatalf("read published SQLite database: %v", err)
	}
	publishedDigest := sha256.Sum256(publishedBytes)
	if fileEntry.ByteSize != int64(len(publishedBytes)) ||
		fileEntry.SHA256 != hex.EncodeToString(publishedDigest[:]) ||
		fileEntry.IntegrityCheck != "ok" || !hasSQLiteHeader(publishedDatabase) {
		t.Fatalf("portable manifest is not bound to the published SQLite bytes: %+v", fileEntry)
	}
	if err := verifySQLiteIntegrity(publishedDatabase); err != nil {
		t.Fatalf("published wrapper database failed integrity verification: %v", err)
	}

	finalFiles := 0
	err = filepath.WalkDir(outputPath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		finalFiles++
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, secret := range []string{dataKey, imageKey, backupKey, `"data_key"`, `"img_key"`, `"backup_key"`} {
			if bytes.Contains(contents, []byte(secret)) {
				return &keyLeakTestError{path: path, marker: secret}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan final key-free tree: %v", err)
	}
	if finalFiles != 2 {
		t.Fatalf("final backup contains unexpected files: %d", finalFiles)
	}

	configAfter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after wrapper backup: %v", err)
	}
	sourceAfter, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source after wrapper backup: %v", err)
	}
	if !bytes.Equal(configJSON, configAfter) || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("wrapper modified its config or source database")
	}

	secondOutput, secondErr := run()
	if secondErr == nil || !bytes.Contains(secondOutput, []byte("already exists")) {
		t.Fatalf("rerun did not refuse the existing destination: err=%v\n%s", secondErr, secondOutput)
	}
	for _, secret := range []string{dataKey, imageKey, backupKey} {
		if bytes.Contains(secondOutput, []byte(secret)) {
			t.Fatalf("failed rerun output leaked a cached key: %q", secret)
		}
	}
	portableAfter, err := os.ReadFile(portableManifestPath)
	if err != nil {
		t.Fatalf("read portable manifest after refused rerun: %v", err)
	}
	publishedAfter, err := os.ReadFile(publishedDatabase)
	if err != nil {
		t.Fatalf("read published database after refused rerun: %v", err)
	}
	if !bytes.Equal(portableJSON, portableAfter) || !bytes.Equal(publishedBytes, publishedAfter) {
		t.Fatal("refused rerun modified the existing destination")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("list wrapper test parent: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".chatlog-sqlite-backup-staging-") ||
			(strings.HasPrefix(entry.Name(), ".chatlog-sqlite-backup-") && strings.HasSuffix(entry.Name(), ".lock")) {
			t.Fatalf("wrapper left a staging or lock artifact: %s", entry.Name())
		}
	}
}

type keyLeakTestError struct {
	path   string
	marker string
}

func (err *keyLeakTestError) Error() string {
	return "key marker " + err.marker + " found in " + err.path
}
