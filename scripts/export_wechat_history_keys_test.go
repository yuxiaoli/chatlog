package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sjzar/chatlog/internal/wechat"
)

const (
	testDataKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testImgKey  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestCaptureValidatedLiveKeysSupportsOptionalV4ImageKeyAndDeduplicatesDataDir(t *testing.T) {
	root := t.TempDir()
	v3Dir := filepath.Join(root, "v3")
	v4Dir := filepath.Join(root, "v4")
	v3DB := writeEncryptedKeyFixture(t, v3Dir)
	v4DB := writeEncryptedKeyFixture(t, v4Dir)

	accounts := []*wechat.Account{
		{Name: "v4 duplicate", Platform: "windows", Version: 4, DataDir: v4Dir, PID: 20, Status: "online"},
		{Name: "offline", Platform: "windows", Version: 4, DataDir: filepath.Join(root, "offline"), Status: "offline"},
		{Name: "v3", Platform: "windows", Version: 3, DataDir: v3Dir, PID: 10, Status: "online"},
		{Name: "v4", Platform: "windows", Version: 4, DataDir: v4Dir, PID: 10, Status: "online"},
	}
	getKeyCalls := 0
	dependencies := keyCaptureDependencies{
		getKey: func(_ context.Context, account *wechat.Account) (string, string, error) {
			getKeyCalls++
			if account.Version == 3 {
				return testDataKey, testImgKey, nil
			}
			return testDataKey, "", nil
		},
		listDatabases: func(dataDir string, _ bool) ([]string, []string) {
			if canonicalPath(dataDir) == canonicalPath(v3Dir) {
				return []string{v3DB}, nil
			}
			return []string{v4DB}, nil
		},
		validateKey: func(account candidate, databasePath string) bool {
			if account.DataKey != strings.ToLower(testDataKey) {
				t.Fatalf("data key was not normalized before validation")
			}
			return databasePath == v3DB || databasePath == v4DB
		},
	}

	captured, err := captureValidatedLiveKeys(context.Background(), accounts, dependencies)
	if err != nil {
		t.Fatalf("capture keys: %v", err)
	}
	if len(captured) != 2 || getKeyCalls != 2 {
		t.Fatalf("captured=%d getKeyCalls=%d, want two unique online data directories", len(captured), getKeyCalls)
	}
	for _, account := range captured {
		if account.DataKey != strings.ToLower(testDataKey) {
			t.Fatalf("data key was not normalized")
		}
		if account.ImgKey != "" {
			t.Fatalf("version %d image key = %q, want empty (v3 unsupported; v4 unavailable)", account.Version, account.ImgKey)
		}
	}
}

func TestValidatePrivateKeyConfigPathRequiresProtectedStage(t *testing.T) {
	stage := t.TempDir()
	config := filepath.Join(stage, "chatlog.json")
	validated, err := validatePrivateKeyConfigPath(config, stage)
	if err != nil {
		t.Fatalf("validate protected config: %v", err)
	}
	if canonicalPath(validated) != canonicalPath(config) {
		t.Fatalf("validated path = %q, want %q", validated, config)
	}
	for _, test := range []struct {
		name   string
		config string
		stage  string
	}{
		{name: "missing config", stage: stage},
		{name: "missing stage", config: config},
		{name: "config outside stage", config: filepath.Join(t.TempDir(), "chatlog.json"), stage: stage},
		{name: "stage is a file", config: filepath.Join(stage, "chatlog.json"), stage: writeEncryptedKeyFixture(t, t.TempDir())},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validatePrivateKeyConfigPath(test.config, test.stage); err == nil {
				t.Fatalf("unsafe helper invocation was accepted")
			}
		})
	}
}

func TestValidatePrivateStageFilePathRequiresDirectRegularFile(t *testing.T) {
	stage := t.TempDir()
	keyPath := filepath.Join(stage, "backup-key.txt")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatalf("write protected key fixture: %v", err)
	}
	validated, err := validatePrivateStageFilePath(keyPath, stage, "the phone-backup key file")
	if err != nil {
		t.Fatalf("validate protected key file: %v", err)
	}
	if canonicalPath(validated) != canonicalPath(keyPath) {
		t.Fatalf("validated path = %q, want %q", validated, keyPath)
	}

	nested := filepath.Join(stage, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("create nested fixture: %v", err)
	}
	nestedKey := filepath.Join(nested, "backup-key.txt")
	if err := os.WriteFile(nestedKey, []byte(strings.Repeat("cd", 32)), 0o600); err != nil {
		t.Fatalf("write nested key fixture: %v", err)
	}
	outsideKey := filepath.Join(t.TempDir(), "backup-key.txt")
	if err := os.WriteFile(outsideKey, []byte(strings.Repeat("ef", 32)), 0o600); err != nil {
		t.Fatalf("write outside key fixture: %v", err)
	}
	for _, test := range []struct {
		name  string
		path  string
		stage string
	}{
		{name: "missing key path", stage: stage},
		{name: "missing stage", path: keyPath},
		{name: "key outside stage", path: outsideKey, stage: stage},
		{name: "nested key path", path: nestedKey, stage: stage},
		{name: "key path is directory", path: nested, stage: stage},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validatePrivateStageFilePath(test.path, test.stage, "the phone-backup key file"); err == nil {
				t.Fatalf("unsafe cache-key input was accepted")
			}
		})
	}
}

func TestCaptureValidatedLiveKeysStoresAvailableV4ImageKey(t *testing.T) {
	dataDir := t.TempDir()
	database := writeEncryptedKeyFixture(t, dataDir)
	dependencies := successfulKeyCaptureDependencies(database, testDataKey, testImgKey)
	accounts := []*wechat.Account{{
		Name: "v4", Platform: "windows", Version: 4, DataDir: dataDir, Status: "online",
	}}

	captured, err := captureValidatedLiveKeys(context.Background(), accounts, dependencies)
	if err != nil {
		t.Fatalf("capture keys: %v", err)
	}
	if len(captured) != 1 || captured[0].ImgKey != strings.ToLower(testImgKey) {
		t.Fatalf("available v4 image key was not normalized and retained")
	}
}

func TestCaptureAndPersistLiveKeysIsStrictAndDoesNotLeakExtractorError(t *testing.T) {
	root := t.TempDir()
	goodDir := filepath.Join(root, "good")
	badDir := filepath.Join(root, "bad")
	goodDB := writeEncryptedKeyFixture(t, goodDir)
	badDB := writeEncryptedKeyFixture(t, badDir)
	configPath := filepath.Join(root, "chatlog.json")
	original := []byte("{\"last_account\":\"unchanged\",\"history\":[]}\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatalf("write original config: %v", err)
	}
	secretInError := strings.Repeat("c", 64)
	accounts := []*wechat.Account{
		{Name: "good", Platform: "windows", Version: 3, DataDir: goodDir, Status: "online"},
		{Name: "bad", Platform: "windows", Version: 3, DataDir: badDir, Status: "online"},
	}
	dependencies := keyCaptureDependencies{
		getKey: func(_ context.Context, account *wechat.Account) (string, string, error) {
			if account.Name == "bad" {
				return "", "", errors.New("extractor accidentally included " + secretInError)
			}
			return testDataKey, "", nil
		},
		listDatabases: func(dataDir string, _ bool) ([]string, []string) {
			if canonicalPath(dataDir) == canonicalPath(goodDir) {
				return []string{goodDB}, nil
			}
			return []string{badDB}, nil
		},
		validateKey: func(candidate, string) bool { return true },
	}

	count, err := captureAndPersistLiveKeys(context.Background(), configPath, accounts, dependencies)
	if err == nil || count != 0 {
		t.Fatalf("strict capture count=%d err=%v, want failure before write", count, err)
	}
	if strings.Contains(err.Error(), secretInError) {
		t.Fatalf("extractor error leaked key material")
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config after failure: %v", readErr)
	}
	if string(after) != string(original) {
		t.Fatalf("strict capture modified chatlog.json after one account failed")
	}
}

func TestCaptureAndPersistLiveKeysFailureDoesNotCreateConfigOrTemporaryFile(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	database := writeEncryptedKeyFixture(t, dataDir)
	configPath := filepath.Join(root, "chatlog.json")
	account := []*wechat.Account{{
		Name: "fixture", Platform: "windows", Version: 3, DataDir: dataDir, Status: "online",
	}}
	dependencies := successfulKeyCaptureDependencies(database, "invalid", "")

	if count, err := captureAndPersistLiveKeys(context.Background(), configPath, account, dependencies); err == nil || count != 0 {
		t.Fatalf("strict capture count=%d err=%v, want failure", count, err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("failed all-or-nothing capture created chatlog.json: %v", err)
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(root, ".chatlog.json.tmp-*"))
	if err != nil || len(temporaryFiles) != 0 {
		t.Fatalf("failed all-or-nothing capture left temporary files: %v (%v)", temporaryFiles, err)
	}
}

func TestCaptureValidatedLiveKeysRejectsInvalidKeys(t *testing.T) {
	dataDir := t.TempDir()
	database := writeEncryptedKeyFixture(t, dataDir)
	account := []*wechat.Account{{
		Name: "fixture", Platform: "windows", Version: 4, DataDir: dataDir, Status: "online",
	}}
	tests := []struct {
		name       string
		dataKey    string
		imageKey   string
		validation bool
	}{
		{name: "missing data key", imageKey: testImgKey, validation: true},
		{name: "short data key", dataKey: "aa", imageKey: testImgKey, validation: true},
		{name: "invalid available image key", dataKey: testDataKey, imageKey: "bb", validation: true},
		{name: "failed representative validation", dataKey: testDataKey, imageKey: testImgKey, validation: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := successfulKeyCaptureDependencies(database, test.dataKey, test.imageKey)
			dependencies.validateKey = func(candidate, string) bool { return test.validation }
			if _, err := captureValidatedLiveKeys(context.Background(), account, dependencies); err == nil {
				t.Fatalf("capture accepted invalid keys")
			}
		})
	}
}

func TestMergeAccountKeysJSONPreservesUnknownFieldsAndHistoryOrder(t *testing.T) {
	root := t.TempDir()
	firstDir := filepath.Join(root, "first")
	secondDir := filepath.Join(root, "second")
	firstPath, _ := json.Marshal(firstDir)
	secondPath, _ := json.Marshal(secondDir)
	existing := []byte(`{
  "first_unknown": {"nested": [1, 2]},
  "BackupFiles": {"mode":"external","sentinel":"do-not-interpret"},
  "last_account": "keep-me",
  "history": [
    {"work_dir":"keep-work","data_dir":` + string(firstPath) + `,"data_key":"old","img_key":"keep-image","custom":{"x":1},"account":"old-name"},
    {"data_dir":` + string(secondPath) + `,"data_key":"untouched","sentinel":true}
  ],
  "last_unknown": "keep-tail"
}`)
	account := savedAccountKeys{
		Account: "new-name", Platform: "windows", Version: 3, FullVersion: "3.9", DataDir: firstDir,
		DataKey: strings.ToLower(testDataKey),
	}

	updated, err := mergeAccountKeysJSON(existing, []savedAccountKeys{account})
	if err != nil {
		t.Fatalf("merge keys: %v", err)
	}
	text := string(updated)
	for _, field := range []string{"first_unknown", "BackupFiles", "last_account", "history", "last_unknown"} {
		if !strings.Contains(text, `"`+field+`"`) {
			t.Fatalf("unknown/config field %q was removed", field)
		}
	}
	if !(strings.Index(text, `"first_unknown"`) < strings.Index(text, `"BackupFiles"`) &&
		strings.Index(text, `"BackupFiles"`) < strings.Index(text, `"last_account"`) &&
		strings.Index(text, `"last_account"`) < strings.Index(text, `"history"`) &&
		strings.Index(text, `"history"`) < strings.Index(text, `"last_unknown"`)) {
		t.Fatalf("top-level field order changed:\n%s", text)
	}

	var decoded struct {
		LastAccount string                   `json:"last_account"`
		BackupFiles map[string]string        `json:"BackupFiles"`
		History     []map[string]interface{} `json:"history"`
	}
	if err := json.Unmarshal(updated, &decoded); err != nil {
		t.Fatalf("decode merged config: %v", err)
	}
	if decoded.LastAccount != "keep-me" || decoded.BackupFiles["mode"] != "external" ||
		decoded.BackupFiles["sentinel"] != "do-not-interpret" || len(decoded.History) != 2 {
		t.Fatalf("central config shape changed: %#v", decoded)
	}
	first := decoded.History[0]
	second := decoded.History[1]
	if first["account"] != "new-name" || first["data_key"] != strings.ToLower(testDataKey) ||
		first["img_key"] != "keep-image" || first["work_dir"] != "keep-work" || first["custom"] == nil {
		t.Fatalf("matching history entry was not merged safely: %#v", first)
	}
	if second["data_key"] != "untouched" || second["sentinel"] != true {
		t.Fatalf("unmatched history entry or its order changed: %#v", second)
	}
}

func TestSaveAccountKeysKeepsSameAccountNameInDifferentDataDirsAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "chatlog.json")
	firstDir := filepath.Join(root, "first")
	secondDir := filepath.Join(root, "second")
	accounts := []savedAccountKeys{
		{Account: "same-name", Platform: "windows", Version: 3, DataDir: firstDir, DataKey: strings.Repeat("1", 64)},
		{Account: "same-name", Platform: "windows", Version: 4, DataDir: secondDir, DataKey: strings.Repeat("2", 64)},
	}
	if err := saveAccountKeys(configPath, accounts); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	firstBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read initial config: %v", err)
	}
	if err := saveAccountKeys(configPath, []savedAccountKeys{accounts[1], accounts[0]}); err != nil {
		t.Fatalf("repeat save: %v", err)
	}
	secondBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read repeated config: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatalf("repeated save was not idempotent or changed history order")
	}

	var config storedConfig
	if err := json.Unmarshal(secondBytes, &config); err != nil {
		t.Fatalf("decode repeated config: %v", err)
	}
	if len(config.History) != 2 {
		t.Fatalf("history has %d entries, want two different canonical data directories", len(config.History))
	}
	if config.History[0].Account != "same-name" || config.History[1].Account != "same-name" ||
		canonicalPath(config.History[0].DataDir) == canonicalPath(config.History[1].DataDir) {
		t.Fatalf("same-name accounts were merged by name instead of data directory: %#v", config.History)
	}
}

func TestSaveAccountKeysCreatesCentralConfigAndDirectlyReplacesIt(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "nested", "chatlog.json")
	dataDir := filepath.Join(root, "account")
	first := savedAccountKeys{
		Account: "fixture", Platform: "windows", Version: 4, FullVersion: "4.0", DataDir: dataDir,
		DataKey: strings.ToLower(testDataKey), ImgKey: strings.ToLower(testImgKey),
	}
	if err := saveAccountKeys(configPath, []savedAccountKeys{first}); err != nil {
		t.Fatalf("create config: %v", err)
	}
	secondDataKey := strings.Repeat("d", 64)
	first.DataKey = secondDataKey
	first.ImgKey = ""
	if err := saveAccountKeys(configPath, []savedAccountKeys{first}); err != nil {
		t.Fatalf("replace existing config: %v", err)
	}

	stored, err := loadStoredAccounts(configPath)
	if err != nil {
		t.Fatalf("existing exporter cannot read saved config: %v", err)
	}
	if len(stored) != 1 || stored[0].DataKey != secondDataKey || stored[0].ImgKey != strings.ToLower(testImgKey) {
		t.Fatalf("saved config = %#v, want updated data key and preserved available image key", stored)
	}
	temporaryFiles, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), ".chatlog.json.tmp-*"))
	if err != nil || len(temporaryFiles) != 0 {
		t.Fatalf("temporary key files remain after direct replacement: %v (%v)", temporaryFiles, err)
	}
	backupFiles, err := filepath.Glob(configPath + ".bak*")
	if err != nil || len(backupFiles) != 0 {
		t.Fatalf("key-bearing backup files were created: %v (%v)", backupFiles, err)
	}
}

func TestSaveAccountKeysRefusesMalformedConfigWithoutChangingIt(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "invalid JSON", content: []byte(`{"history":`)},
		{name: "empty JSON", content: []byte{}},
		{name: "wrong history type", content: []byte(`{"history":{}}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "chatlog.json")
			if err := os.WriteFile(configPath, test.content, 0o600); err != nil {
				t.Fatalf("write malformed config: %v", err)
			}
			account := savedAccountKeys{DataDir: filepath.Join(root, "account"), DataKey: strings.ToLower(testDataKey)}
			if err := saveAccountKeys(configPath, []savedAccountKeys{account}); err == nil {
				t.Fatalf("malformed config was overwritten")
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("read malformed config: %v", err)
			}
			if string(after) != string(test.content) {
				t.Fatalf("malformed config changed after rejected update")
			}
		})
	}
}

func TestMergeAccountKeysJSONFlatConfigRequiresOneMatchingDataDir(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account")
	rawDataDir, _ := json.Marshal(dataDir)
	existing := []byte(`{"type":"wechat","data_dir":` + string(rawDataDir) + `,"data_key":"old","img_key":"keep","unknown":17}`)
	matching := savedAccountKeys{DataDir: dataDir, DataKey: strings.ToLower(testDataKey)}
	updated, err := mergeAccountKeysJSON(existing, []savedAccountKeys{matching})
	if err != nil {
		t.Fatalf("merge matching flat config: %v", err)
	}
	var flat map[string]interface{}
	if err := json.Unmarshal(updated, &flat); err != nil {
		t.Fatalf("decode flat config: %v", err)
	}
	if flat["data_key"] != strings.ToLower(testDataKey) || flat["img_key"] != "keep" || flat["unknown"] != float64(17) {
		t.Fatalf("flat config was not safely merged: %#v", flat)
	}

	mismatch := matching
	mismatch.DataDir = filepath.Join(root, "other")
	if _, err := mergeAccountKeysJSON(existing, []savedAccountKeys{mismatch}); err == nil {
		t.Fatalf("flat config accepted a mismatched data directory")
	}
	if _, err := mergeAccountKeysJSON(existing, []savedAccountKeys{matching, mismatch}); err == nil {
		t.Fatalf("flat config accepted multiple captured accounts")
	}
}

func successfulKeyCaptureDependencies(database, dataKey, imageKey string) keyCaptureDependencies {
	return keyCaptureDependencies{
		getKey: func(context.Context, *wechat.Account) (string, string, error) {
			return dataKey, imageKey, nil
		},
		listDatabases: func(string, bool) ([]string, []string) {
			return []string{database}, nil
		},
		validateKey: func(candidate, string) bool { return true },
	}
}

func writeEncryptedKeyFixture(t *testing.T, directory string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create database directory: %v", err)
	}
	path := filepath.Join(directory, "fixture.db")
	if err := os.WriteFile(path, []byte("not a plaintext SQLite database header"), 0o600); err != nil {
		t.Fatalf("write encrypted database fixture: %v", err)
	}
	return path
}
