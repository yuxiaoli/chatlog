package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
	"github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	_ "modernc.org/sqlite"
)

const sqliteHeader = "SQLite format 3\x00"

type storedConfig struct {
	History   []storedAccount `json:"history"`
	BackupKey string          `json:"backup_key"`
}

type storedAccount struct {
	Account     string `json:"account"`
	Platform    string `json:"platform"`
	Version     int    `json:"version"`
	FullVersion string `json:"full_version"`
	DataDir     string `json:"data_dir"`
	DataKey     string `json:"data_key"`
	ImgKey      string `json:"img_key"`
}

type savedAccountKeys struct {
	Account     string
	Platform    string
	Version     int
	FullVersion string
	DataDir     string
	DataKey     string
	ImgKey      string
}

type keyCaptureDependencies struct {
	getKey        func(context.Context, *wechat.Account) (string, string, error)
	listDatabases func(string, bool) ([]string, []string)
	validateKey   func(candidate, string) bool
}

type rawJSONField struct {
	name  string
	value json.RawMessage
}

// rawJSONObject retains field order and unknown fields while the key cache
// updater changes only the documented chatlog account properties.
type rawJSONObject struct {
	fields []rawJSONField
}

type cachedKey struct {
	Value  string
	Source string
}

type candidate struct {
	Account       string
	Platform      string
	Version       int
	FullVersion   string
	DataDir       string
	DataKey       string
	KeySource     string
	AlternateKeys []cachedKey
	Running       bool
}

type exportManifest struct {
	FormatVersion int               `json:"format_version"`
	GeneratedAt   string            `json:"generated_at"`
	Status        string            `json:"status"`
	AllowPartial  bool              `json:"allow_partial"`
	Accounts      []manifestAccount `json:"accounts"`
	Unresolved    []manifestProblem `json:"unresolved"`
	Warnings      []string          `json:"warnings"`
}

type manifestAccount struct {
	ID          string             `json:"id"`
	Account     string             `json:"account"`
	Platform    string             `json:"platform"`
	Version     int                `json:"version"`
	FullVersion string             `json:"full_version,omitempty"`
	DataDir     string             `json:"data_dir"`
	StageDir    string             `json:"stage_dir"`
	Running     bool               `json:"running"`
	KeySource   string             `json:"key_source,omitempty"`
	Resolved    bool               `json:"resolved"`
	Status      string             `json:"status"`
	Errors      []string           `json:"errors"`
	Databases   []manifestDatabase `json:"files"`
}

type manifestDatabase struct {
	SourcePath           string `json:"source_path"`
	RelativePath         string `json:"relative_path"`
	StagedPath           string `json:"staged_path,omitempty"`
	Size                 int64  `json:"source_size"`
	ModifiedAt           string `json:"source_modified_at,omitempty"`
	SourceSHA256         string `json:"source_sha256"`
	SnapshotSize         int64  `json:"snapshot_size"`
	SnapshotSHA256       string `json:"snapshot_sha256"`
	FileSHA256           string `json:"file_sha256,omitempty"`
	AuxiliarySHA256      string `json:"auxiliary_sha256"`
	LegacyPhoneBootstrap bool   `json:"legacy_phone_bootstrap,omitempty"`
	Mode                 string `json:"mode,omitempty"`
	Status               string `json:"status"`
	Error                string `json:"error,omitempty"`
}

type baselineManifest struct {
	FormatVersion int               `json:"format_version"`
	Accounts      []baselineAccount `json:"accounts"`
}

type baselineAccount struct {
	ID        string             `json:"id"`
	DataDir   string             `json:"data_dir"`
	Version   int                `json:"version"`
	Databases []baselineDatabase `json:"files"`
}

type baselineDatabase struct {
	RelativePath         string `json:"relative_path"`
	OutputPath           string `json:"output_path,omitempty"`
	SourceSHA256         string `json:"source_sha256"`
	SnapshotSize         int64  `json:"snapshot_size"`
	SnapshotSHA256       string `json:"snapshot_sha256"`
	FileSHA256           string `json:"file_sha256,omitempty"`
	AuxiliarySHA256      string `json:"auxiliary_sha256"`
	LegacyPhoneBootstrap bool   `json:"legacy_phone_bootstrap,omitempty"`
}

type baselineAccountIndex struct {
	ID        string
	Version   int
	Databases map[string]baselineDatabase
}

type baselineIndex map[string]baselineAccountIndex

type manifestProblem struct {
	Account string `json:"account,omitempty"`
	DataDir string `json:"data_dir,omitempty"`
	Reason  string `json:"reason"`
}

type prepareOptions struct {
	ConfiguredAccountsOnly bool
	CentralConfigOnly      bool
	PromptExitWeChat       bool
	AllowPartial           bool
	VerifySQLite           bool
	DestinationRoot        string
	BaselineRoot           string
	RejectWeChatRestart    bool
	IncludeBackup          bool
	beforeFinalSourceCheck func()
}

func main() {
	// Key extractors contain useful key-level diagnostics at Debug level. This
	// exporter must never print a recovered key, even when another package left
	// zerolog at its default Debug level.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	stage := flag.String("stage", "", "directory for decrypted SQLite databases")
	manifestPath := flag.String("manifest", "", "path for the key-free export manifest")
	configPath := flag.String("config", "", "optional chatlog.json path")
	baselinePath := flag.String("baseline", "", "optional version 2 JSON baseline for delta staging")
	baselineRoot := flag.String("sqlite-backup-baseline-root", "", "existing verified SQLite backup root used to copy unchanged delta files")
	backupKeyPath := flag.String("backup-key-file", "", "optional file containing a 32-byte BackupFiles key as hexadecimal text")
	cacheBackupKeyPath := flag.String("cache-backup-key-file", "", "private-staging-only file containing a BackupFiles key to cache in chatlog.json")
	configuredOnly := flag.Bool("configured-accounts-only", false, "use only accounts from --config (for deterministic diagnostics)")
	promptExitWeChat := flag.Bool("prompt-exit-wechat", true, "noninteractively require WeChat to exit before staging (ordinary exports capture live keys first)")
	allowPartial := flag.Bool("allow-partial", false, "continue when accounts or databases cannot be exported")
	saveKeysOnly := flag.Bool("save-keys-only", false, "capture validated database keys and available v4 image keys into chatlog.json without exporting databases")
	sqliteBackup := flag.Bool("sqlite-backup", false, "strictly back up configured databases as verified, decrypted SQLite files")
	includeBackup := flag.Bool("include-backup", false, "include encrypted phone-backup archives in the output")
	destinationRoot := flag.String("destination-root", "", "final SQLite backup directory (required with --sqlite-backup for source-overlap checks)")
	flag.Parse()

	if *saveKeysOnly {
		if conflicts := saveKeysOnlyFlagConflicts(); len(conflicts) != 0 {
			fmt.Fprintf(os.Stderr, "--save-keys-only cannot be combined with: %s\n", strings.Join(conflicts, ", "))
			os.Exit(2)
		}
		path, err := validatePrivateKeyConfigPath(*configPath, os.Getenv("CHATLOG_KEY_CACHE_PRIVATE_STAGE"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "--save-keys-only must be run through export_wechat_history.ps1 -SaveKeysOnly: %v\n", err)
			os.Exit(1)
		}
		count, err := captureAndSaveLiveKeys(context.Background(), path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "save WeChat keys: %v\n", err)
			os.Exit(1)
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			absolutePath = path
		}
		fmt.Printf("Saved validated database keys and available v4 image keys for %d WeChat account(s) to %s.\n", count, absolutePath)
		return
	}
	if strings.TrimSpace(*cacheBackupKeyPath) != "" {
		if conflicts := cacheBackupKeyFlagConflicts(); len(conflicts) != 0 {
			fmt.Fprintf(os.Stderr, "--cache-backup-key-file cannot be combined with: %s\n", strings.Join(conflicts, ", "))
			os.Exit(2)
		}
		privateStage := os.Getenv("CHATLOG_KEY_CACHE_PRIVATE_STAGE")
		path, err := validatePrivateKeyConfigPath(*configPath, privateStage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--cache-backup-key-file must be run through backup_wechat_databases.ps1: %v\n", err)
			os.Exit(1)
		}
		keyPath, err := validatePrivateStageFilePath(*cacheBackupKeyPath, privateStage, "the phone-backup key file")
		if err != nil {
			fmt.Fprintf(os.Stderr, "--cache-backup-key-file must be run through backup_wechat_databases.ps1: %v\n", err)
			os.Exit(1)
		}
		if canonicalPath(path) == canonicalPath(keyPath) {
			fmt.Fprintln(os.Stderr, "chatlog.json and the phone-backup key file must be different files")
			os.Exit(1)
		}
		backupKey, err := loadBackupKey(keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := saveBackupKey(path, backupKey); err != nil {
			fmt.Fprintf(os.Stderr, "cache phone-backup key: %v\n", err)
			os.Exit(1)
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			absolutePath = path
		}
		fmt.Printf("Saved the phone-backup key to %s.\n", absolutePath)
		return
	}

	if *stage == "" || *manifestPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *configuredOnly && strings.TrimSpace(*configPath) == "" {
		fmt.Fprintln(os.Stderr, "--configured-accounts-only requires --config")
		os.Exit(2)
	}
	if *sqliteBackup {
		var conflicts []string
		if strings.TrimSpace(*configPath) == "" {
			fmt.Fprintln(os.Stderr, "--sqlite-backup requires --config")
			os.Exit(2)
		}
		if strings.TrimSpace(*destinationRoot) == "" {
			fmt.Fprintln(os.Stderr, "--sqlite-backup requires --destination-root")
			os.Exit(2)
		}
		if *allowPartial {
			conflicts = append(conflicts, "--allow-partial")
		}
		if !*promptExitWeChat {
			conflicts = append(conflicts, "--prompt-exit-wechat=false")
		}
		if len(conflicts) != 0 {
			fmt.Fprintf(os.Stderr, "--sqlite-backup cannot be combined with: %s\n", strings.Join(conflicts, ", "))
			os.Exit(2)
		}
		if (strings.TrimSpace(*baselinePath) == "") != (strings.TrimSpace(*baselineRoot) == "") {
			fmt.Fprintln(os.Stderr, "--sqlite-backup delta staging requires both --baseline and --sqlite-backup-baseline-root")
			os.Exit(2)
		}
	} else if strings.TrimSpace(*destinationRoot) != "" {
		fmt.Fprintln(os.Stderr, "--destination-root is only valid with --sqlite-backup")
		os.Exit(2)
	} else if strings.TrimSpace(*baselineRoot) != "" {
		fmt.Fprintln(os.Stderr, "--sqlite-backup-baseline-root is only valid with --sqlite-backup")
		os.Exit(2)
	}

	backupKey, backupKeyErr := resolveBackupKey(*backupKeyPath, *configPath)
	if backupKeyErr != nil {
		fmt.Fprintln(os.Stderr, backupKeyErr)
		os.Exit(1)
	}
	baseline, baselineErr := loadBaseline(*baselinePath)
	if baselineErr != nil {
		fmt.Fprintln(os.Stderr, baselineErr)
		os.Exit(1)
	}
	options := prepareOptions{
		ConfiguredAccountsOnly: *configuredOnly || *sqliteBackup,
		CentralConfigOnly:      *sqliteBackup,
		PromptExitWeChat:       *promptExitWeChat && (!*configuredOnly || *sqliteBackup),
		AllowPartial:           *allowPartial,
		VerifySQLite:           *sqliteBackup,
		DestinationRoot:        *destinationRoot,
		BaselineRoot:           *baselineRoot,
		RejectWeChatRestart:    *sqliteBackup,
		IncludeBackup:          *includeBackup,
	}
	manifest, err := prepare(*stage, *configPath, backupKey, baseline, options)
	if manifest == nil {
		manifest = &exportManifest{
			FormatVersion: 2,
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			AllowPartial:  options.AllowPartial,
		}
	}
	if err != nil && manifest.Status == "" {
		manifest.Status = "partial"
	}
	if writeErr := writeManifest(*manifestPath, manifest); writeErr != nil {
		fmt.Fprintf(os.Stderr, "write manifest: %v\n", writeErr)
		os.Exit(1)
	}
	if err != nil {
		printManifestProblems(manifest)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if manifest.Status == "partial" {
		printManifestProblems(manifest)
	}

	var databaseCount, unchangedCount int
	for _, account := range manifest.Accounts {
		for _, database := range account.Databases {
			if database.Status == "ok" || database.Status == "unchanged" {
				databaseCount++
			}
			if database.Status == "unchanged" {
				unchangedCount++
			}
		}
	}
	fmt.Printf("Prepared %d database(s) from %d account(s); %d unchanged.\n", databaseCount, len(manifest.Accounts), unchangedCount)
}

func saveKeysOnlyFlagConflicts() []string {
	var conflicts []string
	flag.CommandLine.Visit(func(item *flag.Flag) {
		if item.Name == "save-keys-only" || item.Name == "config" {
			return
		}
		conflicts = append(conflicts, "--"+item.Name)
	})
	sort.Strings(conflicts)
	return conflicts
}

func cacheBackupKeyFlagConflicts() []string {
	var conflicts []string
	flag.CommandLine.Visit(func(item *flag.Flag) {
		if item.Name == "cache-backup-key-file" || item.Name == "config" {
			return
		}
		conflicts = append(conflicts, "--"+item.Name)
	})
	sort.Strings(conflicts)
	return conflicts
}

func validatePrivateKeyConfigPath(configPath, privateStage string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	privateStage = strings.TrimSpace(privateStage)
	if configPath == "" {
		return "", fmt.Errorf("--config is required")
	}
	if privateStage == "" {
		return "", fmt.Errorf("the ACL-protected staging directory was not provided")
	}
	absoluteConfig, err := filepath.Abs(filepath.Clean(configPath))
	if err != nil {
		return "", fmt.Errorf("resolve --config: %w", err)
	}
	absoluteStage, err := filepath.Abs(filepath.Clean(privateStage))
	if err != nil {
		return "", fmt.Errorf("resolve protected staging directory: %w", err)
	}
	stageInfo, err := os.Lstat(absoluteStage)
	if err != nil {
		return "", fmt.Errorf("inspect protected staging directory: %w", err)
	}
	if !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("the protected staging path is not a real directory")
	}
	if canonicalPath(filepath.Dir(absoluteConfig)) != canonicalPath(absoluteStage) {
		return "", fmt.Errorf("--config is outside the protected staging directory")
	}
	configInfo, err := os.Lstat(absoluteConfig)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect --config: %w", err)
	}
	if err == nil && (!configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0) {
		return "", fmt.Errorf("--config is not a regular non-symlink file")
	}
	return absoluteConfig, nil
}

func validatePrivateStageFilePath(path, privateStage, description string) (string, error) {
	path = strings.TrimSpace(path)
	privateStage = strings.TrimSpace(privateStage)
	if path == "" {
		return "", fmt.Errorf("%s path is empty", description)
	}
	if privateStage == "" {
		return "", fmt.Errorf("the ACL-protected staging directory was not provided")
	}
	absolutePath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", description, err)
	}
	absoluteStage, err := filepath.Abs(filepath.Clean(privateStage))
	if err != nil {
		return "", fmt.Errorf("resolve protected staging directory: %w", err)
	}
	stageInfo, err := os.Lstat(absoluteStage)
	if err != nil {
		return "", fmt.Errorf("inspect protected staging directory: %w", err)
	}
	if !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("the protected staging path is not a real directory")
	}
	if canonicalPath(filepath.Dir(absolutePath)) != canonicalPath(absoluteStage) {
		return "", fmt.Errorf("%s is outside the protected staging directory", description)
	}
	info, err := os.Lstat(absolutePath)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", description, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a regular non-symlink file", description)
	}
	return absolutePath, nil
}

func captureAndSaveLiveKeys(ctx context.Context, configPath string) (int, error) {
	if err := wechat.Load(); err != nil {
		return 0, fmt.Errorf("discover running WeChat accounts: %w", err)
	}
	dependencies := keyCaptureDependencies{
		getKey: func(ctx context.Context, account *wechat.Account) (string, string, error) {
			return account.GetKey(ctx)
		},
		listDatabases: listDatabaseFiles,
		validateKey:   validDataKey,
	}
	return captureAndPersistLiveKeys(ctx, configPath, wechat.GetAccounts(), dependencies)
}

func captureAndPersistLiveKeys(
	ctx context.Context,
	configPath string,
	accounts []*wechat.Account,
	dependencies keyCaptureDependencies,
) (int, error) {
	captured, err := captureValidatedLiveKeys(ctx, accounts, dependencies)
	if err != nil {
		return 0, err
	}
	if err := saveAccountKeys(configPath, captured); err != nil {
		return 0, err
	}
	return len(captured), nil
}

func captureValidatedLiveKeys(
	ctx context.Context,
	accounts []*wechat.Account,
	dependencies keyCaptureDependencies,
) ([]savedAccountKeys, error) {
	if dependencies.getKey == nil || dependencies.listDatabases == nil || dependencies.validateKey == nil {
		return nil, fmt.Errorf("key capture dependencies are incomplete")
	}

	online := make([]*wechat.Account, 0, len(accounts))
	for _, account := range accounts {
		if account != nil && strings.EqualFold(strings.TrimSpace(account.Status), "online") {
			online = append(online, account)
		}
	}
	sort.SliceStable(online, func(i, j int) bool {
		leftDir := canonicalPath(strings.TrimSpace(online[i].DataDir))
		rightDir := canonicalPath(strings.TrimSpace(online[j].DataDir))
		if leftDir != rightDir {
			return leftDir < rightDir
		}
		if online[i].PID != online[j].PID {
			return online[i].PID < online[j].PID
		}
		return strings.ToLower(online[i].Name) < strings.ToLower(online[j].Name)
	})
	if len(online) == 0 {
		return nil, fmt.Errorf("no online WeChat account was found; sign in and keep WeChat running")
	}

	seenDirectories := make(map[string]bool)
	captured := make([]savedAccountKeys, 0, len(online))
	failures := make([]string, 0)
	for _, original := range online {
		account := *original
		account.DataDir = strings.TrimSpace(account.DataDir)
		label := strings.TrimSpace(account.Name)
		if label == "" {
			label = "unknown account"
		}
		if account.DataDir == "" {
			failures = append(failures, label+": running process did not expose a data directory")
			continue
		}
		absoluteDataDir, err := filepath.Abs(filepath.Clean(account.DataDir))
		if err != nil {
			failures = append(failures, label+": could not resolve the data directory")
			continue
		}
		account.DataDir = absoluteDataDir
		canonicalDirectory := canonicalPath(account.DataDir)
		if seenDirectories[canonicalDirectory] {
			continue
		}
		seenDirectories[canonicalDirectory] = true

		if account.Platform == "" {
			account.Platform = runtime.GOOS
		}
		if account.Version == 0 {
			account.Version = inferVersion(account.DataDir)
		}
		if account.Version != 3 && account.Version != 4 {
			failures = append(failures, label+": database version is neither v3 nor v4")
			continue
		}
		expectedPlatform := account.Platform
		expectedVersion := account.Version

		databasePaths, _ := dependencies.listDatabases(account.DataDir, false)
		validationPaths := make([]string, 0, len(databasePaths))
		for _, databasePath := range databasePaths {
			relative, relativeErr := filepath.Rel(account.DataDir, databasePath)
			if relativeErr == nil && isBackupDatabase(relative) {
				continue
			}
			if !hasSQLiteHeader(databasePath) {
				validationPaths = append(validationPaths, databasePath)
			}
		}
		validationDatabase := selectValidationDatabase(candidate{
			Account:  account.Name,
			Platform: account.Platform,
			Version:  account.Version,
			DataDir:  account.DataDir,
		}, validationPaths)
		if validationDatabase == "" {
			failures = append(failures, label+": no encrypted database is available for key validation")
			continue
		}

		dataKey, imageKey, keyErr := dependencies.getKey(ctx, &account)
		if keyErr != nil {
			// Extractor errors must not be included verbatim: a future extractor
			// could accidentally put recovered key material in its error text.
			failures = append(failures, label+": key extraction failed")
			continue
		}
		if canonicalPath(account.DataDir) != canonicalDirectory ||
			!strings.EqualFold(account.Platform, expectedPlatform) || account.Version != expectedVersion {
			failures = append(failures, label+": account identity changed during key extraction")
			continue
		}
		normalizedDataKey, ok := normalizeHexKey(dataKey, 32)
		if !ok {
			failures = append(failures, label+": extractor did not return a 32-byte database key")
			continue
		}
		normalizedImageKey := ""
		if account.Version == 4 && strings.TrimSpace(imageKey) != "" {
			normalizedImageKey, ok = normalizeHexKey(imageKey, 16)
			if !ok {
				failures = append(failures, label+": extractor returned an invalid image key")
				continue
			}
		}

		validationCandidate := candidate{
			Account:  account.Name,
			Platform: account.Platform,
			Version:  account.Version,
			DataDir:  account.DataDir,
			DataKey:  normalizedDataKey,
		}
		if !dependencies.validateKey(validationCandidate, validationDatabase) {
			failures = append(failures, label+": extracted database key did not validate")
			continue
		}

		captured = append(captured, savedAccountKeys{
			Account:     account.Name,
			Platform:    account.Platform,
			Version:     account.Version,
			FullVersion: account.FullVersion,
			DataDir:     account.DataDir,
			DataKey:     normalizedDataKey,
			ImgKey:      normalizedImageKey,
		})
	}
	if len(failures) != 0 {
		sort.Strings(failures)
		return nil, fmt.Errorf("could not capture every online account: %s", strings.Join(failures, "; "))
	}
	if len(captured) == 0 {
		return nil, fmt.Errorf("no validated WeChat database key was captured")
	}
	return captured, nil
}

func normalizeHexKey(value string, byteLength int) (string, bool) {
	value = strings.TrimSpace(value)
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != byteLength {
		return "", false
	}
	return strings.ToLower(value), true
}

func saveAccountKeys(configPath string, accounts []savedAccountKeys) error {
	if len(accounts) == 0 {
		return fmt.Errorf("no account keys were supplied")
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return fmt.Errorf("chatlog.json path is empty")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve chatlog.json path: %w", err)
	}

	existing, err := os.ReadFile(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read chatlog.json: %w", err)
	}
	if os.IsNotExist(err) {
		existing = nil
	}
	updated, err := mergeAccountKeysJSON(existing, accounts)
	if err != nil {
		return err
	}
	if err := writePrivateFileAtomically(absolutePath, updated); err != nil {
		return fmt.Errorf("write chatlog.json: %w", err)
	}
	return nil
}

func saveBackupKey(configPath, backupKey string) error {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return fmt.Errorf("chatlog.json path is empty")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve chatlog.json path: %w", err)
	}

	existing, err := os.ReadFile(absolutePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read chatlog.json: %w", err)
	}
	if os.IsNotExist(err) {
		existing = nil
	}
	updated, err := mergeBackupKeyJSON(existing, backupKey)
	if err != nil {
		return err
	}
	if err := writePrivateFileAtomically(absolutePath, updated); err != nil {
		return fmt.Errorf("write chatlog.json: %w", err)
	}
	return nil
}

func mergeBackupKeyJSON(existing []byte, backupKey string) ([]byte, error) {
	normalized, ok := normalizeHexKey(backupKey, 32)
	if !ok {
		return nil, fmt.Errorf("phone-backup key must contain exactly one 32-byte hexadecimal key")
	}

	var root rawJSONObject
	var err error
	if existing != nil {
		if len(bytes.TrimSpace(existing)) == 0 {
			return nil, fmt.Errorf("parse chatlog.json: JSON document is empty")
		}
		root, err = parseRawJSONObject(existing)
		if err != nil {
			return nil, fmt.Errorf("parse chatlog.json: %w", err)
		}
	}
	if err := root.setJSON("backup_key", normalized); err != nil {
		return nil, fmt.Errorf("encode backup_key: %w", err)
	}
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode chatlog.json: %w", err)
	}
	return append(updated, '\n'), nil
}

func mergeAccountKeysJSON(existing []byte, accounts []savedAccountKeys) ([]byte, error) {
	var root rawJSONObject
	var err error
	if existing != nil {
		if len(bytes.TrimSpace(existing)) == 0 {
			return nil, fmt.Errorf("parse chatlog.json: JSON document is empty")
		}
		root, err = parseRawJSONObject(existing)
		if err != nil {
			return nil, fmt.Errorf("parse chatlog.json: %w", err)
		}
	}

	seen := make(map[string]bool)
	for _, account := range accounts {
		canonical := canonicalPath(strings.TrimSpace(account.DataDir))
		if strings.TrimSpace(account.DataDir) == "" || canonical == "" {
			return nil, fmt.Errorf("captured account has no data directory")
		}
		if seen[canonical] {
			return nil, fmt.Errorf("captured accounts contain a duplicate data directory")
		}
		seen[canonical] = true
	}

	historyValue, hasHistory := root.getRaw("history")
	flatDataDirValue, hasFlatDataDir := root.getRaw("data_dir")
	if !hasHistory && hasFlatDataDir {
		flatDataDir, stringErr := decodeJSONString(flatDataDirValue)
		if stringErr != nil {
			return nil, fmt.Errorf("flat chatlog.json data_dir must be a string")
		}
		if len(accounts) != 1 || canonicalPath(flatDataDir) != canonicalPath(accounts[0].DataDir) {
			return nil, fmt.Errorf("flat chatlog.json can only be updated by one account with the same data directory")
		}
		if err := updateRawAccount(&root, accounts[0]); err != nil {
			return nil, err
		}
	} else {
		history := []rawJSONObject{}
		if hasHistory && !bytes.Equal(bytes.TrimSpace(historyValue), []byte("null")) {
			var rawEntries []json.RawMessage
			if err := json.Unmarshal(historyValue, &rawEntries); err != nil {
				return nil, fmt.Errorf("chatlog.json history must be an array")
			}
			for index, rawEntry := range rawEntries {
				entry, parseErr := parseRawJSONObject(rawEntry)
				if parseErr != nil {
					return nil, fmt.Errorf("chatlog.json history entry %d must be an object", index+1)
				}
				history = append(history, entry)
			}
		}

		for _, account := range accounts {
			matched := false
			for index := range history {
				rawDataDir, exists := history[index].getRaw("data_dir")
				if !exists {
					continue
				}
				dataDir, stringErr := decodeJSONString(rawDataDir)
				if stringErr != nil {
					return nil, fmt.Errorf("chatlog.json history entry %d data_dir must be a string", index+1)
				}
				if canonicalPath(dataDir) != canonicalPath(account.DataDir) {
					continue
				}
				if err := updateRawAccount(&history[index], account); err != nil {
					return nil, err
				}
				matched = true
			}
			if !matched {
				entry := rawJSONObject{}
				if err := updateRawAccount(&entry, account); err != nil {
					return nil, err
				}
				history = append(history, entry)
			}
		}
		if err := root.setJSON("history", history); err != nil {
			return nil, err
		}
	}

	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode chatlog.json: %w", err)
	}
	return append(updated, '\n'), nil
}

func updateRawAccount(object *rawJSONObject, account savedAccountKeys) error {
	properties := []struct {
		name  string
		value any
		set   bool
	}{
		{name: "account", value: account.Account, set: strings.TrimSpace(account.Account) != ""},
		{name: "platform", value: account.Platform, set: strings.TrimSpace(account.Platform) != ""},
		{name: "version", value: account.Version, set: account.Version != 0},
		{name: "full_version", value: account.FullVersion, set: strings.TrimSpace(account.FullVersion) != ""},
		{name: "data_dir", value: account.DataDir, set: true},
		{name: "data_key", value: account.DataKey, set: true},
		{name: "img_key", value: account.ImgKey, set: strings.TrimSpace(account.ImgKey) != ""},
	}
	for _, property := range properties {
		if property.set {
			if err := object.setJSON(property.name, property.value); err != nil {
				return fmt.Errorf("encode account property %s: %w", property.name, err)
			}
		}
	}
	return nil
}

func parseRawJSONObject(data []byte) (rawJSONObject, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return rawJSONObject{}, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return rawJSONObject{}, fmt.Errorf("JSON value is not an object")
	}
	object := rawJSONObject{}
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return rawJSONObject{}, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return rawJSONObject{}, fmt.Errorf("JSON object property name is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return rawJSONObject{}, err
		}
		object.fields = append(object.fields, rawJSONField{name: name, value: append(json.RawMessage(nil), value...)})
	}
	closing, err := decoder.Token()
	if err != nil {
		return rawJSONObject{}, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return rawJSONObject{}, fmt.Errorf("JSON object is not closed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return rawJSONObject{}, fmt.Errorf("JSON object has trailing content")
		}
		return rawJSONObject{}, err
	}
	return object, nil
}

func (object rawJSONObject) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, field := range object.fields {
		if index != 0 {
			buffer.WriteByte(',')
		}
		name, err := json.Marshal(field.name)
		if err != nil {
			return nil, err
		}
		if !json.Valid(field.value) {
			return nil, fmt.Errorf("property %s contains invalid JSON", field.name)
		}
		buffer.Write(name)
		buffer.WriteByte(':')
		buffer.Write(field.value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

func (object rawJSONObject) getRaw(name string) (json.RawMessage, bool) {
	for index := len(object.fields) - 1; index >= 0; index-- {
		if object.fields[index].name == name {
			return append(json.RawMessage(nil), object.fields[index].value...), true
		}
	}
	return nil, false
}

func (object *rawJSONObject) setJSON(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	found := false
	for index := range object.fields {
		if object.fields[index].name == name {
			object.fields[index].value = append(json.RawMessage(nil), raw...)
			found = true
		}
	}
	if !found {
		object.fields = append(object.fields, rawJSONField{name: name, value: raw})
	}
	return nil
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func writePrivateFileAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func printManifestProblems(manifest *exportManifest) {
	for _, problem := range manifest.Unresolved {
		name := problem.Account
		if name == "" {
			name = problem.DataDir
		}
		fmt.Fprintf(os.Stderr, "Unresolved %s: %s\n", name, problem.Reason)
	}
	for _, account := range manifest.Accounts {
		for _, database := range account.Databases {
			if database.Status != "ok" && database.Status != "unchanged" {
				fmt.Fprintf(os.Stderr, "Database failed [%s] %s: %s\n", account.Account, database.RelativePath, database.Error)
			}
		}
	}
}

func prepare(stage, configPath, backupKey string, baseline baselineIndex, options prepareOptions) (*exportManifest, error) {
	stage, err := filepath.Abs(stage)
	if err != nil {
		return nil, fmt.Errorf("resolve stage directory: %w", err)
	}
	destinationRoot := strings.TrimSpace(options.DestinationRoot)
	if destinationRoot != "" {
		destinationRoot, err = filepath.Abs(filepath.Clean(destinationRoot))
		if err != nil {
			return nil, fmt.Errorf("resolve final destination directory: %w", err)
		}
	}
	baselineRoot := strings.TrimSpace(options.BaselineRoot)
	if baselineRoot != "" {
		baselineRoot, err = filepath.Abs(filepath.Clean(baselineRoot))
		if err != nil {
			return nil, fmt.Errorf("resolve SQLite backup baseline directory: %w", err)
		}
		baselineInfo, baselineErr := os.Lstat(baselineRoot)
		if baselineErr != nil {
			return nil, fmt.Errorf("inspect SQLite backup baseline directory: %w", baselineErr)
		}
		if !baselineInfo.IsDir() || baselineInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("SQLite backup baseline is not a regular non-symlink directory: %s", baselineRoot)
		}
		if pathsOverlap(stage, baselineRoot) {
			return nil, fmt.Errorf("SQLite backup baseline directory must not overlap the staging directory")
		}
	}

	manifest := &exportManifest{
		FormatVersion: 2,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "preparing",
		AllowPartial:  options.AllowPartial,
		Accounts:      []manifestAccount{},
		Unresolved:    []manifestProblem{},
		Warnings:      []string{},
	}

	candidates := make(map[string]candidate)
	liveAccounts := make(map[string]*wechat.Account)
	discoveredLivePIDs := make(map[uint32]bool)
	runningClientDetected := false
	discoveryProblem := false
	if configPath == "" && !options.CentralConfigOnly {
		configPath = defaultConfigPath()
	}
	if options.CentralConfigOnly {
		configPath = strings.TrimSpace(configPath)
		if configPath == "" {
			return manifest, fmt.Errorf("strict SQLite backup requires an explicit chatlog.json path")
		}
		configInfo, configErr := os.Lstat(configPath)
		if configErr != nil {
			return manifest, fmt.Errorf("inspect central chatlog config %s: %w", configPath, configErr)
		}
		if !configInfo.Mode().IsRegular() || configInfo.Mode()&os.ModeSymlink != 0 {
			return manifest, fmt.Errorf("central chatlog config is not a regular non-symlink file: %s", configPath)
		}
		if destinationRoot != "" && pathWithin(destinationRoot, configPath) {
			return manifest, fmt.Errorf("final backup directory must not contain chatlog.json")
		}
	}
	if configPath != "" {
		stored, loadErr := loadStoredAccounts(configPath)
		if loadErr != nil {
			return manifest, loadErr
		}
		if options.CentralConfigOnly && len(stored) == 0 {
			return manifest, fmt.Errorf("central chatlog config contains no account history: %s", configPath)
		}
		for _, account := range stored {
			if strings.TrimSpace(account.DataDir) == "" {
				manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
					Account: account.Account,
					Reason:  "cached account has no data directory",
				})
				discoveryProblem = true
				continue
			}
			mergeCandidate(candidates, candidateFromStored(account), false)
		}
	}

	if !options.ConfiguredAccountsOnly {
		if err := wechat.Load(); err != nil {
			manifest.Warnings = append(manifest.Warnings, "WeChat process discovery failed: "+err.Error())
		}
		for _, account := range wechat.GetAccounts() {
			if account.Status != "online" {
				continue
			}
			runningClientDetected = true
			discoveredLivePIDs[account.PID] = true
			if strings.TrimSpace(account.DataDir) == "" {
				manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
					Account: account.Name,
					Reason:  "running WeChat process did not expose its data directory",
				})
				discoveryProblem = true
				continue
			}

			current := candidate{
				Account:     account.Name,
				Platform:    account.Platform,
				Version:     account.Version,
				FullVersion: account.FullVersion,
				DataDir:     account.DataDir,
				Running:     true,
			}
			liveAccounts[canonicalPath(account.DataDir)] = account
			mergeCandidate(candidates, current, true)
		}
	}

	if !options.CentralConfigOnly {
		// A data-directory-local chatlog.json can outlive the user's central
		// configuration and is the project's fallback for offline accounts.
		for _, known := range candidates {
			local, localErr := loadLocalAccount(known.DataDir)
			if localErr != nil {
				manifest.Warnings = append(manifest.Warnings, localErr.Error())
				continue
			}
			mergeCandidate(candidates, local, true)
		}
	}

	discoveredDirs := []string{}
	rootProblems := []manifestProblem{}
	if !options.ConfiguredAccountsOnly {
		discoverRoots := candidateRoots(candidates)
		discoveredDirs, rootProblems = discoverAccountDirs(discoverRoots)
	}
	for _, rootProblem := range rootProblems {
		manifest.Unresolved = append(manifest.Unresolved, rootProblem)
		discoveryProblem = true
	}
	for _, dataDir := range discoveredDirs {
		key := canonicalPath(dataDir)
		if _, ok := candidates[key]; ok {
			continue
		}

		local, localErr := loadLocalAccount(dataDir)
		if localErr != nil {
			manifest.Warnings = append(manifest.Warnings, localErr.Error())
		}
		if local.DataDir == "" {
			local.DataDir = dataDir
		}
		if local.Account == "" {
			local.Account = filepath.Base(dataDir)
		}
		if local.Platform == "" {
			local.Platform = runtime.GOOS
		}
		if local.Version == 0 {
			local.Version = inferVersion(dataDir)
		}
		mergeCandidate(candidates, local, false)
	}

	ordered := make([]candidate, 0, len(candidates))
	for _, account := range candidates {
		if account.DataDir == "" {
			continue
		}
		info, statErr := os.Stat(account.DataDir)
		if statErr != nil || !info.IsDir() {
			reason := "configured data directory is unavailable"
			if statErr == nil {
				reason = "configured data path is not a directory"
			}
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  reason,
			})
			discoveryProblem = true
			continue
		}
		if account.Account == "" {
			account.Account = filepath.Base(account.DataDir)
		}
		if account.Platform == "" {
			account.Platform = runtime.GOOS
		}
		if account.Version == 0 {
			account.Version = inferVersion(account.DataDir)
		}
		if destinationRoot != "" && pathsOverlap(account.DataDir, destinationRoot) {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "final backup directory must not contain, equal, or be inside a configured WeChat data directory",
			})
			discoveryProblem = true
			continue
		}
		if baselineRoot != "" && pathsOverlap(account.DataDir, baselineRoot) {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "SQLite backup baseline directory must not overlap a configured WeChat data directory",
			})
			discoveryProblem = true
			continue
		}
		ordered = append(ordered, account)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return strings.ToLower(ordered[i].DataDir) < strings.ToLower(ordered[j].DataDir)
	})

	if len(ordered) == 0 {
		manifest.Status = "partial"
		if options.CentralConfigOnly {
			return manifest, fmt.Errorf("no usable WeChat account data directories were found in the central chatlog config")
		}
		return manifest, fmt.Errorf("no WeChat account data was found; sign in to WeChat and leave it running while the export starts")
	}
	if options.CentralConfigOnly {
		var preflightProblem bool
		ordered, preflightProblem = preflightConfiguredBackup(ordered, backupKey, manifest, options.IncludeBackup)
		if discoveryProblem || preflightProblem {
			manifest.Status = "partial"
			return manifest, fmt.Errorf("strict SQLite backup preflight failed; chatlog.json must describe every available account and contain a valid key for each encrypted account database")
		}
	}
	if options.PromptExitWeChat {
		keyFailures := []string{}
		if runningClientDetected && !options.CentralConfigOnly {
			ordered, keyFailures = captureLiveDataKeys(ordered, liveAccounts, manifest)
		}
		if len(keyFailures) != 0 && !options.AllowPartial {
			manifest.Status = "partial"
			return manifest, fmt.Errorf(
				"could not capture every required database key before checking WeChat exit: %s; use chatlog's get key action and rerun",
				strings.Join(keyFailures, "; "),
			)
		}
		if len(keyFailures) != 0 {
			manifest.Warnings = append(manifest.Warnings,
				"Some live account keys could not be captured before the exit check: "+strings.Join(keyFailures, "; "))
		}
		capturedPIDs := discoveredLivePIDs
		if options.CentralConfigOnly {
			// Config-only backup mode uses process discovery solely to obtain a
			// stable snapshot. It must never associate or extract a live key.
			capturedPIDs = nil
		}
		var waitErr error
		if options.CentralConfigOnly {
			waitErr = waitForAllWeChatExit()
		} else {
			waitErr = waitForWeChatExit(capturedPIDs)
		}
		if waitErr != nil {
			manifest.Status = "partial"
			return manifest, waitErr
		}
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return manifest, fmt.Errorf("create stage directory: %w", err)
	}

	strictProblem := discoveryProblem
	readyDatabases := 0
	for _, account := range ordered {
		if pathWithin(account.DataDir, stage) {
			problem := manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "output staging directory is inside the WeChat data directory",
			}
			manifest.Unresolved = append(manifest.Unresolved, problem)
			strictProblem = true
			continue
		}

		dbFiles, walkProblems := listDatabaseFiles(account.DataDir, options.IncludeBackup)
		for _, walkProblem := range walkProblems {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "database discovery skipped a path: " + walkProblem,
			})
			strictProblem = true
		}
		if len(dbFiles) == 0 {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "no database files were found",
			})
			strictProblem = true
			continue
		}

		needsKey := accountNeedsDataKey(account, dbFiles)
		if needsKey && (account.Version != 3 && account.Version != 4) {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "could not determine whether this is WeChat v3 or v4",
			})
			strictProblem = true
			continue
		}
		if needsKey && account.DataKey != "" {
			validationDatabase := selectValidationDatabase(account, dbFiles)
			validated, usedAlternate := selectCachedKey(account, validationDatabase)
			account = validated
			if account.DataKey == "" {
				message := fmt.Sprintf("None of the cached data keys for %s validated; attempting live extraction", displayAccount(account))
				if options.CentralConfigOnly {
					message = fmt.Sprintf("None of the data keys stored in the central chatlog config validated for %s", displayAccount(account))
				}
				manifest.Warnings = append(manifest.Warnings, message)
			} else if usedAlternate {
				manifest.Warnings = append(manifest.Warnings,
					fmt.Sprintf("A secondary cached data key was selected for %s after the preferred key did not validate", displayAccount(account)))
			}
		}
		if needsKey && strings.TrimSpace(account.DataKey) == "" && account.Running && !options.CentralConfigOnly {
			live := liveAccounts[canonicalPath(account.DataDir)]
			if live != nil {
				dataKey, _, keyErr := live.GetKey(context.Background())
				if keyErr == nil {
					account.DataKey = dataKey
					account.KeySource = "live_process"
				} else {
					manifest.Warnings = append(manifest.Warnings,
						fmt.Sprintf("Could not obtain a data key for running account %s: %v", displayAccount(account), keyErr))
				}
			}
		}
		if needsKey && strings.TrimSpace(account.DataKey) == "" {
			reason := "encrypted databases were found but no cached or live data key is available; sign in to this account and run the export again"
			if options.CentralConfigOnly {
				reason = "encrypted account databases were found, but chatlog.json contains no data key that validates for them"
			}
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  reason,
			})
			strictProblem = true
			continue
		}
		accountID := safeName(account.Account) + "_" + shortHash(account.DataDir)
		baselineAccount, hasBaselineAccount := baseline[canonicalPath(account.DataDir)]
		if hasBaselineAccount {
			accountID = baselineAccount.ID
		}
		accountStage := filepath.Join(stage, accountID)
		fmt.Printf("Preparing %s: %d database file(s)\n", displayAccount(account), len(dbFiles))
		entry := manifestAccount{
			ID:          accountID,
			Account:     account.Account,
			Platform:    account.Platform,
			Version:     account.Version,
			FullVersion: account.FullVersion,
			DataDir:     account.DataDir,
			StageDir:    accountStage,
			Running:     account.Running,
			KeySource:   account.KeySource,
			Resolved:    len(walkProblems) == 0,
			Status:      "complete",
			Errors:      []string{},
			Databases:   []manifestDatabase{},
		}
		if len(walkProblems) != 0 {
			entry.Status = "partial"
			for _, walkProblem := range walkProblems {
				entry.Errors = append(entry.Errors, "database discovery skipped a path: "+walkProblem)
			}
		}
		for _, source := range dbFiles {
			relative, _ := filepath.Rel(account.DataDir, source)
			relative = filepath.ToSlash(relative)
			fmt.Printf("  %s\n", relative)
			destination := filepath.Join(accountStage, relative)
			info, statErr := os.Stat(source)
			plainSQLite := hasSQLiteHeader(source)
			backupDatabase := isBackupDatabase(relative)
			database := manifestDatabase{
				SourcePath:   source,
				RelativePath: relative,
				StagedPath:   destination,
				Mode:         "decrypted",
				Status:       "failed",
			}
			if plainSQLite {
				database.Mode = "copied_plaintext"
			}
			if backupDatabase {
				database.Mode = "decrypted_phone_backup_index"
			}
			if statErr == nil {
				database.Size = info.Size()
				database.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
			}

			failDatabase := func(databaseErr error) {
				database.Error = databaseErr.Error()
				entry.Resolved = false
				entry.Status = "partial"
				entry.Errors = append(entry.Errors, database.Error)
				strictProblem = true
			}

			sourceHash, hashErr := hashDatabaseSource(source)
			if hashErr != nil {
				failDatabase(fmt.Errorf("fingerprint source database: %w", hashErr))
				entry.Databases = append(entry.Databases, database)
				continue
			}
			database.SourceSHA256 = sourceHash
			if backupDatabase {
				auxiliaryHash, auxiliaryErr := hashBackupAuxiliary(filepath.Dir(source))
				if auxiliaryErr != nil {
					failDatabase(fmt.Errorf("fingerprint phone-backup archives: %w", auxiliaryErr))
					entry.Databases = append(entry.Databases, database)
					continue
				}
				database.AuxiliarySHA256 = auxiliaryHash
			}

			// DuckDB deltas restage v4 message/contact databases because rebuilding
			// sender mappings needs SQLite rowids that raw DuckDB tables do not retain.
			// A SQLite-only backup preserves the original database and can safely reuse it.
			if hasBaselineAccount && baselineAccount.Version == account.Version &&
				baselineAccount.Version != 0 && (account.Version != 4 || backupDatabase || options.VerifySQLite) {
				prior, exists := baselineAccount.Databases[baselineRelativePath(relative)]
				if exists && baselineDatabaseMatches(prior, database.SourceSHA256, database.AuxiliarySHA256) {
					if options.VerifySQLite && baselineRoot != "" {
						snapshotSize, snapshotSHA256, fileSHA256, reuseErr := reuseBaselineSQLite(
							baselineRoot, baselineAccount.ID, relative, destination, prior,
						)
						if reuseErr != nil {
							failDatabase(fmt.Errorf("reuse unchanged SQLite backup: %w", reuseErr))
							entry.Databases = append(entry.Databases, database)
							continue
						}
						database.Mode = "reused_decrypted_backup"
						database.SnapshotSize = snapshotSize
						database.SnapshotSHA256 = snapshotSHA256
						database.FileSHA256 = fileSHA256
					} else {
						database.StagedPath = ""
						database.SnapshotSize = prior.SnapshotSize
						database.SnapshotSHA256 = strings.ToLower(prior.SnapshotSHA256)
					}
					database.LegacyPhoneBootstrap = prior.LegacyPhoneBootstrap
					database.Status = "unchanged"
					database.Error = ""
					readyDatabases++
					entry.Databases = append(entry.Databases, database)
					continue
				}
			}

			databaseAccount := account
			// A plaintext Backup.db needs no key for the SQLite-only backup.
			// The normal DuckDB export still requires the separate key because
			// it also decrypts the associated BAK_* archives downstream.
			if backupDatabase && (!plainSQLite || !options.CentralConfigOnly) {
				if backupKey == "" {
					failDatabase(fmt.Errorf("phone-backup database is new or changed; --backup-key-file is required to stage Backup.db"))
					entry.Databases = append(entry.Databases, database)
					continue
				}
				databaseAccount.DataKey = backupKey
			}

			decryptErr := prepareDatabase(source, destination, databaseAccount)
			if decryptErr == nil && options.VerifySQLite && !isBackupArchive(filepath.Base(source)) {
				if integrityErr := verifySQLiteIntegrity(destination); integrityErr != nil {
					decryptErr = fmt.Errorf("verify staged SQLite integrity: %w", integrityErr)
				}
			}
			if decryptErr == nil {
				afterSourceHash, afterHashErr := hashDatabaseSource(source)
				if afterHashErr != nil {
					decryptErr = fmt.Errorf("verify source database after staging: %w", afterHashErr)
				} else if afterSourceHash != database.SourceSHA256 {
					decryptErr = fmt.Errorf("source database changed while its snapshot was being staged")
				}
			}
			if decryptErr == nil && backupDatabase {
				afterAuxiliaryHash, afterAuxiliaryErr := hashBackupAuxiliary(filepath.Dir(source))
				if afterAuxiliaryErr != nil {
					decryptErr = fmt.Errorf("verify phone-backup archives after staging: %w", afterAuxiliaryErr)
				} else if afterAuxiliaryHash != database.AuxiliarySHA256 {
					decryptErr = fmt.Errorf("phone-backup archives changed while Backup.db was being staged")
				}
			}
			if decryptErr == nil {
				snapshotSize, snapshotHash, fileHash, snapshotErr := hashSnapshot(destination)
				if snapshotErr != nil {
					decryptErr = fmt.Errorf("fingerprint staged snapshot: %w", snapshotErr)
				} else {
					database.SnapshotSize = snapshotSize
					database.SnapshotSHA256 = snapshotHash
					database.FileSHA256 = fileHash
				}
			}
			if decryptErr != nil {
				_ = os.Remove(destination)
				failDatabase(decryptErr)
			} else {
				database.Status = "ok"
				database.Error = ""
				readyDatabases++
			}
			entry.Databases = append(entry.Databases, database)
		}
		afterFiles, afterWalkProblems := listDatabaseFiles(account.DataDir, options.IncludeBackup)
		if len(afterWalkProblems) != 0 || !sameDatabaseInventory(dbFiles, afterFiles) {
			entry.Resolved = false
			entry.Status = "partial"
			strictProblem = true
			reason := "database inventory changed while the account was being staged; exit WeChat completely and rerun"
			if len(afterWalkProblems) != 0 {
				reason = "database inventory could not be rechecked after staging: " + strings.Join(afterWalkProblems, "; ")
			}
			entry.Errors = append(entry.Errors, reason)
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  reason,
			})
		}
		if !entry.Resolved {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "one or more database paths could not be staged",
			})
		}
		manifest.Accounts = append(manifest.Accounts, entry)
	}
	if options.VerifySQLite {
		if options.beforeFinalSourceCheck != nil {
			options.beforeFinalSourceCheck()
		}
		// Perform one final, source-wide pass after every account has staged.
		// This binds all snapshots to the same stopped-source interval and
		// catches an early account changing while a later account is copied.
		for accountIndex := range manifest.Accounts {
			entry := &manifest.Accounts[accountIndex]
			sourceChangedDuringFinalValidation := false
			expectedSources := make([]string, 0, len(entry.Databases))
			for databaseIndex := range entry.Databases {
				database := &entry.Databases[databaseIndex]
				expectedSources = append(expectedSources, database.SourcePath)
				if database.Status != "ok" && database.Status != "unchanged" {
					continue
				}
				var revalidationErr error
				currentSourceHash, sourceHashErr := hashDatabaseSource(database.SourcePath)
				if sourceHashErr != nil {
					revalidationErr = fmt.Errorf("revalidate source after all database staging: %w", sourceHashErr)
				} else if currentSourceHash != database.SourceSHA256 {
					revalidationErr = fmt.Errorf("source database changed after its snapshot was staged")
				}
				if revalidationErr == nil && isBackupDatabase(database.RelativePath) {
					currentAuxiliaryHash, auxiliaryErr := hashBackupAuxiliary(filepath.Dir(database.SourcePath))
					if auxiliaryErr != nil {
						revalidationErr = fmt.Errorf("revalidate phone-backup archives after all database staging: %w", auxiliaryErr)
					} else if currentAuxiliaryHash != database.AuxiliarySHA256 {
						revalidationErr = fmt.Errorf("phone-backup archives changed after Backup.db was staged")
					}
				}
				if revalidationErr != nil {
					if database.StagedPath != "" {
						_ = os.Remove(database.StagedPath)
					}
					database.Status = "failed"
					database.Error = revalidationErr.Error()
					entry.Resolved = false
					entry.Status = "partial"
					entry.Errors = append(entry.Errors, database.Error)
					strictProblem = true
					readyDatabases--
					sourceChangedDuringFinalValidation = true
				}
			}
			currentSources, inventoryProblems := listDatabaseFiles(entry.DataDir, options.IncludeBackup)
			if len(inventoryProblems) != 0 || !sameDatabaseInventory(expectedSources, currentSources) {
				reason := "database inventory changed before final publication; exit WeChat completely and rerun"
				if len(inventoryProblems) != 0 {
					reason = "database inventory could not be validated before final publication: " + strings.Join(inventoryProblems, "; ")
				}
				entry.Resolved = false
				entry.Status = "partial"
				entry.Errors = append(entry.Errors, reason)
				manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
					Account: entry.Account,
					DataDir: entry.DataDir,
					Reason:  reason,
				})
				strictProblem = true
			}
			if sourceChangedDuringFinalValidation {
				manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
					Account: entry.Account,
					DataDir: entry.DataDir,
					Reason:  "one or more sources changed before final SQLite backup validation",
				})
			}
		}
	}
	if options.RejectWeChatRestart {
		running, probeErr := probeAllWeChatClients()
		if probeErr != nil {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Reason: "could not verify that WeChat remained stopped through the backup: " + probeErr.Error(),
			})
			strictProblem = true
		} else if len(running) != 0 {
			labels := runningWeChatClientLabels(running)
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Reason: "WeChat restarted while databases were being staged: " + strings.Join(labels, ", ") + "; exit it completely and rerun",
			})
			strictProblem = true
		}
	}
	if readyDatabases == 0 {
		strictProblem = true
		manifest.Warnings = append(manifest.Warnings, "No databases were staged successfully")
	}

	if strictProblem && !options.AllowPartial {
		manifest.Status = "partial"
		if options.CentralConfigOnly {
			return manifest, fmt.Errorf("the SQLite backup would be incomplete; no backup was published")
		}
		return manifest, fmt.Errorf("the export would be incomplete; see %s for details or rerun with -AllowPartial", "the preparation manifest")
	}
	if strictProblem {
		manifest.Status = "partial"
	} else {
		manifest.Status = "complete"
	}
	return manifest, nil
}

func preflightConfiguredBackup(
	accounts []candidate,
	backupKey string,
	manifest *exportManifest,
	includeBackupArchives bool,
) ([]candidate, bool) {
	problem := false
	for index, original := range accounts {
		account := original
		databasePaths, walkProblems := listDatabaseFiles(account.DataDir, includeBackupArchives)
		for _, walkProblem := range walkProblems {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "database discovery skipped a path: " + walkProblem,
			})
			problem = true
		}
		if len(databasePaths) == 0 {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "no database files were found",
			})
			problem = true
			accounts[index] = account
			continue
		}

		needsDataKey := accountNeedsDataKey(account, databasePaths)
		needsBackupKey := false
		backupValidationDatabases := []string{}
		for _, databasePath := range databasePaths {
			relative, relativeErr := filepath.Rel(account.DataDir, databasePath)
			if relativeErr == nil && isBackupDatabase(relative) && !isBackupArchive(filepath.Base(databasePath)) && !hasSQLiteHeader(databasePath) {
				needsBackupKey = true
				backupValidationDatabases = append(backupValidationDatabases, databasePath)
			}
		}
		if (needsDataKey || needsBackupKey) && account.Version != 3 && account.Version != 4 {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "could not determine whether encrypted databases use WeChat v3 or v4 format",
			})
			problem = true
		}
		if needsDataKey {
			validationDatabase := selectValidationDatabase(account, databasePaths)
			validated, usedAlternate := selectCachedKey(account, validationDatabase)
			account = validated
			if strings.TrimSpace(account.DataKey) == "" {
				manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
					Account: account.Account,
					DataDir: account.DataDir,
					Reason:  "encrypted account databases were found, but chatlog.json contains no data key that validates for them",
				})
				problem = true
			} else if usedAlternate {
				manifest.Warnings = append(manifest.Warnings,
					fmt.Sprintf("A secondary key stored in the central chatlog config was selected for %s", displayAccount(account)))
			}
		}
		if needsBackupKey && strings.TrimSpace(backupKey) == "" {
			manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
				Account: account.Account,
				DataDir: account.DataDir,
				Reason:  "an encrypted BackupFiles/Backup.db uses a separate phone-backup key; provide -BackupKeyFile to the backup script",
			})
			problem = true
		} else if needsBackupKey && (account.Version == 3 || account.Version == 4) {
			backupAccount := account
			backupAccount.DataKey = backupKey
			for _, backupValidationDatabase := range backupValidationDatabases {
				if !validDataKey(backupAccount, backupValidationDatabase) {
					relative, _ := filepath.Rel(account.DataDir, backupValidationDatabase)
					manifest.Unresolved = append(manifest.Unresolved, manifestProblem{
						Account: account.Account,
						DataDir: account.DataDir,
						Reason:  "the separate phone-backup key did not validate for " + filepath.ToSlash(relative),
					})
					problem = true
				}
			}
		}
		accounts[index] = normalizeCachedKeys(account)
	}
	return accounts, problem
}

func accountNeedsDataKey(account candidate, databasePaths []string) bool {
	for _, databasePath := range databasePaths {
		relative, err := filepath.Rel(account.DataDir, databasePath)
		if err == nil && isBackupDatabase(relative) {
			// Backup.db has a separate key and is handled per file.
			continue
		}
		if !hasSQLiteHeader(databasePath) {
			return true
		}
	}
	return false
}

func captureLiveDataKeys(ordered []candidate, liveAccounts map[string]*wechat.Account, manifest *exportManifest) ([]candidate, []string) {
	failures := []string{}
	for index, original := range ordered {
		account := original
		if !account.Running {
			continue
		}
		databasePaths, _ := listDatabaseFiles(account.DataDir, false)
		if len(databasePaths) == 0 || !accountNeedsDataKey(account, databasePaths) {
			continue
		}
		if account.Version != 3 && account.Version != 4 {
			failures = append(failures, displayAccount(account)+" has an unknown database version")
			continue
		}

		validationDatabase := selectValidationDatabase(account, databasePaths)
		if strings.TrimSpace(account.DataKey) != "" {
			validated, usedAlternate := selectCachedKey(account, validationDatabase)
			account = validated
			if account.DataKey == "" {
				manifest.Warnings = append(manifest.Warnings,
					fmt.Sprintf("None of the cached data keys for %s validated; attempting live extraction before the exit prompt", displayAccount(account)))
			} else if usedAlternate {
				manifest.Warnings = append(manifest.Warnings,
					fmt.Sprintf("A secondary cached data key was selected for %s before the exit prompt", displayAccount(account)))
			}
		}

		if strings.TrimSpace(account.DataKey) == "" {
			live := liveAccounts[canonicalPath(account.DataDir)]
			if live == nil {
				failures = append(failures, displayAccount(account)+" has no matching live process")
				ordered[index] = account
				continue
			}
			dataKey, _, keyErr := live.GetKey(context.Background())
			if keyErr != nil {
				failures = append(failures,
					fmt.Sprintf("%s key extraction failed: %v", displayAccount(account), keyErr))
				ordered[index] = account
				continue
			}
			account.DataKey = strings.TrimSpace(dataKey)
			account.KeySource = "live_process"
			if account.DataKey == "" || !validDataKey(account, validationDatabase) {
				account.DataKey = ""
				account.KeySource = ""
				failures = append(failures, displayAccount(account)+" live key did not validate")
			}
		}
		ordered[index] = normalizeCachedKeys(account)
	}
	return ordered, failures
}

type runningWeChatClient struct {
	Name string
	PID  uint32
}

func probeRunningWeChatClients() ([]runningWeChatClient, error) {
	return probeRunningWeChatClientsWith(false)
}

func probeAllWeChatClients() ([]runningWeChatClient, error) {
	return probeRunningWeChatClientsWith(true)
}

func probeRunningWeChatClientsWith(includeWeixinHelpers bool) ([]runningWeChatClient, error) {
	processes, err := gopsprocess.Processes()
	if err != nil {
		return nil, err
	}
	running := []runningWeChatClient{}
	for _, process := range processes {
		name, nameErr := process.Name()
		if nameErr != nil {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.HasSuffix(strings.ToLower(name), ".exe") {
			name = name[:len(name)-len(".exe")]
		}
		if !strings.EqualFold(name, "WeChat") && !strings.EqualFold(name, "Weixin") {
			continue
		}
		if strings.EqualFold(name, "Weixin") && !includeWeixinHelpers {
			commandLine, commandErr := process.Cmdline()
			if commandErr == nil && strings.Contains(commandLine, "--") {
				continue
			}
		}
		running = append(running, runningWeChatClient{Name: name, PID: uint32(process.Pid)})
	}
	return running, nil
}

func waitForWeChatExit(capturedPIDs map[uint32]bool) error {
	return waitForWeChatExitWith(probeRunningWeChatClients, nil, nil, false, capturedPIDs)
}

func waitForAllWeChatExit() error {
	return waitForWeChatExitWith(probeAllWeChatClients, nil, nil, false, nil)
}

func waitForWeChatExitWith(
	probe func() ([]runningWeChatClient, error),
	_ io.Reader,
	_ io.Writer,
	_ bool,
	capturedPIDs map[uint32]bool,
) error {
	running, err := probe()
	if err != nil {
		return fmt.Errorf("could not recheck whether WeChat is running: %w", err)
	}
	if len(running) == 0 {
		return nil
	}
	if capturedPIDs != nil {
		uncaptured := []string{}
		for _, client := range running {
			if !capturedPIDs[client.PID] {
				uncaptured = append(uncaptured, fmt.Sprintf("%s (PID %d)", client.Name, client.PID))
			}
		}
		if len(uncaptured) != 0 {
			sort.Strings(uncaptured)
			return fmt.Errorf(
				"a WeChat process appeared or could not be associated during live-key capture: %s; exit it completely and rerun the export so its account can be resolved safely",
				strings.Join(uncaptured, ", "),
			)
		}
	}

	labels := runningWeChatClientLabels(running)
	instruction := "WeChat is still running: " + strings.Join(labels, ", ") + ". " +
		"Use WeChat's menu or tray icon to exit completely; closing only the window is not enough."
	return fmt.Errorf("%s Exit WeChat and rerun the export", instruction)
}

func runningWeChatClientLabels(running []runningWeChatClient) []string {
	labels := make([]string, 0, len(running))
	for _, client := range running {
		name := strings.TrimSpace(client.Name)
		if name == "" {
			name = "WeChat"
		}
		labels = append(labels, fmt.Sprintf("%s (PID %d)", name, client.PID))
	}
	sort.Strings(labels)
	return labels
}

func defaultConfigPath() string {
	if configDir := strings.TrimSpace(os.Getenv("CHATLOG_DIR")); configDir != "" {
		return filepath.Join(configDir, "chatlog.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".chatlog", "chatlog.json")
}

func resolveBackupKey(explicitPath, configPath string) (string, error) {
	if strings.TrimSpace(explicitPath) != "" {
		return loadBackupKey(explicitPath)
	}

	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	if strings.TrimSpace(configPath) == "" {
		return "", nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read chatlog config for phone-backup key: %w", err)
	}
	var config storedConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("parse chatlog config for phone-backup key: %w", err)
	}
	if strings.TrimSpace(config.BackupKey) == "" {
		return "", nil
	}
	normalized, ok := normalizeHexKey(config.BackupKey, 32)
	if !ok {
		return "", fmt.Errorf("chatlog.json backup_key must contain exactly one 32-byte hexadecimal key")
	}
	return normalized, nil
}

func loadBackupKey(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read backup key file: %w", err)
	}
	value := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("backup key file must contain exactly one 32-byte hexadecimal key")
	}
	return strings.ToLower(value), nil
}

func loadBaseline(path string) (baselineIndex, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read delta baseline: %w", err)
	}
	var manifest baselineManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse delta baseline: %w", err)
	}
	if manifest.FormatVersion != 2 {
		return nil, fmt.Errorf("delta baseline format_version must be 2, got %d", manifest.FormatVersion)
	}

	result := make(baselineIndex, len(manifest.Accounts))
	seenIDs := make(map[string]string)
	for accountIndex, account := range manifest.Accounts {
		account.ID = strings.TrimSpace(account.ID)
		account.DataDir = strings.TrimSpace(account.DataDir)
		if account.ID == "" || account.DataDir == "" {
			return nil, fmt.Errorf("delta baseline account %d must have id and data_dir", accountIndex+1)
		}
		if !safeAccountID(account.ID) {
			return nil, fmt.Errorf("delta baseline account id is unsafe: %q", account.ID)
		}
		canonical := canonicalPath(account.DataDir)
		if _, exists := result[canonical]; exists {
			return nil, fmt.Errorf("delta baseline contains duplicate data_dir: %s", account.DataDir)
		}
		if priorPath, exists := seenIDs[account.ID]; exists {
			return nil, fmt.Errorf("delta baseline account id %q is shared by %s and %s", account.ID, priorPath, account.DataDir)
		}
		seenIDs[account.ID] = account.DataDir

		databases := make(map[string]baselineDatabase, len(account.Databases))
		for databaseIndex, database := range account.Databases {
			key := baselineRelativePath(database.RelativePath)
			if key == "" {
				return nil, fmt.Errorf("delta baseline database %d for %s has no relative_path", databaseIndex+1, account.ID)
			}
			if _, exists := databases[key]; exists {
				return nil, fmt.Errorf("delta baseline contains duplicate database path for %s: %s", account.ID, database.RelativePath)
			}
			database.SourceSHA256 = normalizeSHA256(database.SourceSHA256)
			database.SnapshotSHA256 = normalizeSHA256(database.SnapshotSHA256)
			database.FileSHA256 = normalizeSHA256(database.FileSHA256)
			database.AuxiliarySHA256 = normalizeSHA256(database.AuxiliarySHA256)
			for label, digest := range map[string]string{
				"source_sha256":    database.SourceSHA256,
				"snapshot_sha256":  database.SnapshotSHA256,
				"file_sha256":      database.FileSHA256,
				"auxiliary_sha256": database.AuxiliarySHA256,
			} {
				if digest != "" && !validSHA256(digest) {
					return nil, fmt.Errorf("delta baseline %s for %s/%s is not a SHA-256 digest", label, account.ID, database.RelativePath)
				}
			}
			if database.SnapshotSize < 0 {
				return nil, fmt.Errorf("delta baseline snapshot_size for %s/%s is negative", account.ID, database.RelativePath)
			}
			if database.LegacyPhoneBootstrap && !isBackupDatabase(database.RelativePath) {
				return nil, fmt.Errorf("delta baseline legacy bootstrap is only valid for Backup.db: %s/%s", account.ID, database.RelativePath)
			}
			databases[key] = database
		}
		result[canonical] = baselineAccountIndex{ID: account.ID, Version: account.Version, Databases: databases}
	}
	return result, nil
}

func baselineRelativePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	return strings.ToLower(strings.TrimLeft(value, "/"))
}

func safeAccountID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." || filepath.Base(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizeSHA256(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func baselineDatabaseMatches(database baselineDatabase, sourceSHA256, auxiliarySHA256 string) bool {
	return validSHA256(database.SourceSHA256) &&
		validSHA256(database.SnapshotSHA256) &&
		database.SnapshotSize > 0 &&
		database.SourceSHA256 == normalizeSHA256(sourceSHA256) &&
		database.AuxiliarySHA256 == normalizeSHA256(auxiliarySHA256)
}

func safeBackupDatabasePath(value string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, ":") {
		return "", false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return "", false
		}
	}
	if !strings.EqualFold(filepath.Ext(value), ".db") && !isBackupArchive(filepath.Base(value)) {
		return "", false
	}
	return value, true
}

func copyStableRegularFile(source, destination string) error {
	state, info, err := stableFileStateOf(source, false)
	if err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil {
		return err
	}
	openedState := stableFileState{Exists: true, Size: opened.Size(), Modified: opened.ModTime().UnixNano(), Mode: opened.Mode()}
	if openedState != state || !os.SameFile(opened, info) {
		return errInputChanged
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	openedAfter, err := input.Stat()
	if err != nil {
		return err
	}
	pathAfter, pathAfterInfo, err := stableFileStateOf(source, false)
	if err != nil {
		return err
	}
	openedAfterState := stableFileState{Exists: true, Size: openedAfter.Size(), Modified: openedAfter.ModTime().UnixNano(), Mode: openedAfter.Mode()}
	if openedAfterState != state || pathAfter != state || !os.SameFile(openedAfter, pathAfterInfo) {
		return errInputChanged
	}
	if err := replaceFile(temporary, destination); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func reuseBaselineSQLite(root, accountID, relativePath, destination string, prior baselineDatabase) (int64, string, string, error) {
	relativePath, ok := safeBackupDatabasePath(relativePath)
	if !ok || !safeAccountID(accountID) {
		return 0, "", "", fmt.Errorf("baseline contains an unsafe database output path")
	}
	outputPath := strings.TrimSpace(strings.ReplaceAll(prior.OutputPath, "\\", "/"))
	expectedOutput := accountID + "/" + relativePath
	if !strings.EqualFold(outputPath, expectedOutput) {
		return 0, "", "", fmt.Errorf("baseline output_path %q does not match %q", prior.OutputPath, expectedOutput)
	}
	if prior.SnapshotSize <= 0 || !validSHA256(prior.SnapshotSHA256) || !validSHA256(prior.FileSHA256) {
		return 0, "", "", fmt.Errorf("baseline lacks a valid snapshot size or digest")
	}
	accountRoot := filepath.Join(root, accountID)
	source := filepath.Join(accountRoot, filepath.FromSlash(relativePath))
	if !pathWithin(root, accountRoot) || !pathWithin(accountRoot, source) {
		return 0, "", "", fmt.Errorf("baseline database path escapes its account directory")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return 0, "", "", fmt.Errorf("inspect baseline SQLite database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, "", "", fmt.Errorf("baseline SQLite database is not a regular non-symlink file")
	}
	size, snapshotSHA256, fileSHA256, err := hashSnapshot(source)
	if err != nil {
		return 0, "", "", fmt.Errorf("fingerprint baseline SQLite database: %w", err)
	}
	if size != prior.SnapshotSize || snapshotSHA256 != prior.SnapshotSHA256 || fileSHA256 != prior.FileSHA256 {
		return 0, "", "", fmt.Errorf("baseline SQLite database no longer matches its manifest")
	}
	if !isBackupArchive(filepath.Base(source)) {
		if err := verifySQLiteIntegrity(source); err != nil {
			return 0, "", "", fmt.Errorf("verify baseline SQLite integrity: %w", err)
		}
	}
	if err := copyStableRegularFile(source, destination); err != nil {
		return 0, "", "", fmt.Errorf("copy unchanged baseline SQLite database: %w", err)
	}
	if !isBackupArchive(filepath.Base(destination)) {
		if err := verifySQLiteIntegrity(destination); err != nil {
			_ = os.Remove(destination)
			return 0, "", "", fmt.Errorf("verify copied baseline SQLite integrity: %w", err)
		}
	}
	copiedSize, copiedSnapshotSHA256, copiedFileSHA256, err := hashSnapshot(destination)
	if err != nil {
		_ = os.Remove(destination)
		return 0, "", "", fmt.Errorf("fingerprint copied baseline SQLite database: %w", err)
	}
	if copiedSize != prior.SnapshotSize || copiedSnapshotSHA256 != prior.SnapshotSHA256 || copiedFileSHA256 != prior.FileSHA256 {
		_ = os.Remove(destination)
		return 0, "", "", fmt.Errorf("copied baseline SQLite database changed during reuse")
	}
	return copiedSize, copiedSnapshotSHA256, copiedFileSHA256, nil
}

var errInputChanged = errors.New("input changed while it was being fingerprinted")

type stableFileState struct {
	Exists   bool
	Size     int64
	Modified int64
	Mode     fs.FileMode
}

func stableFileStateOf(path string, optional bool) (stableFileState, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return stableFileState{}, nil, nil
		}
		return stableFileState{}, nil, err
	}
	if !info.Mode().IsRegular() {
		return stableFileState{}, nil, fmt.Errorf("path is not a regular non-symlink file: %s", path)
	}
	return stableFileState{
		Exists:   true,
		Size:     info.Size(),
		Modified: info.ModTime().UnixNano(),
		Mode:     info.Mode(),
	}, info, nil
}

func normalizeEmptyOptionalFile(state stableFileState, info os.FileInfo) (stableFileState, os.FileInfo) {
	// SQLite can materialize or remove an empty WAL during a read-only open.
	// Zero bytes means there are no WAL frames, so its presence is not a
	// logical source change. Non-empty WALs are still hashed and stabilized.
	if state.Exists && state.Size == 0 {
		return stableFileState{}, nil
	}
	return state, info
}

func writeFingerprintHeader(destination io.Writer, label string, state stableFileState) {
	fmt.Fprintf(destination, "%d:%s:%t:%d:", len(label), label, state.Exists, state.Size)
}

func hashExpectedFile(destination io.Writer, label, path string, expected stableFileState, expectedInfo os.FileInfo) error {
	writeFingerprintHeader(destination, label, expected)
	if !expected.Exists {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	openedState := stableFileState{Exists: true, Size: opened.Size(), Modified: opened.ModTime().UnixNano(), Mode: opened.Mode()}
	if openedState != expected || !os.SameFile(opened, expectedInfo) {
		return errInputChanged
	}
	if _, err := io.Copy(destination, file); err != nil {
		return err
	}
	openedAfter, err := file.Stat()
	if err != nil {
		return err
	}
	openedAfterState := stableFileState{Exists: true, Size: openedAfter.Size(), Modified: openedAfter.ModTime().UnixNano(), Mode: openedAfter.Mode()}
	pathAfter, pathAfterInfo, err := stableFileStateOf(path, false)
	if err != nil {
		if os.IsNotExist(err) {
			return errInputChanged
		}
		return err
	}
	if openedAfterState != expected || pathAfter != expected || !os.SameFile(openedAfter, pathAfterInfo) {
		return errInputChanged
	}
	return nil
}

func hashDatabaseSource(path string) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		digest, err := hashDatabaseSourceOnce(path)
		if err == nil {
			return digest, nil
		}
		lastErr = err
		if !errors.Is(err, errInputChanged) || attempt == 3 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", lastErr
}

func hashDatabaseSourceOnce(path string) (string, error) {
	mainState, mainInfo, err := stableFileStateOf(path, false)
	if err != nil {
		return "", err
	}
	walPath := path + "-wal"
	walState, walInfo, err := stableFileStateOf(walPath, true)
	if err != nil {
		return "", err
	}
	walState, walInfo = normalizeEmptyOptionalFile(walState, walInfo)
	digest := sha256.New()
	io.WriteString(digest, "wechat-database-source-v1\x00")
	if err := hashExpectedFile(digest, "main", path, mainState, mainInfo); err != nil {
		return "", err
	}
	if err := hashExpectedFile(digest, "wal", walPath, walState, walInfo); err != nil {
		return "", err
	}
	afterMain, afterMainInfo, err := stableFileStateOf(path, false)
	if err != nil {
		return "", err
	}
	afterWAL, afterWALInfo, err := stableFileStateOf(walPath, true)
	if err != nil {
		return "", err
	}
	afterWAL, afterWALInfo = normalizeEmptyOptionalFile(afterWAL, afterWALInfo)
	if mainState != afterMain || walState != afterWAL || !os.SameFile(mainInfo, afterMainInfo) ||
		(walState.Exists && !os.SameFile(walInfo, afterWALInfo)) {
		return "", errInputChanged
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func hashSnapshot(path string) (int64, string, string, error) {
	state, info, err := stableFileStateOf(path, false)
	if err != nil {
		return 0, "", "", err
	}
	snapshotDigest := sha256.New()
	fileDigest := sha256.New()
	io.WriteString(snapshotDigest, "wechat-sqlite-snapshot-v1\x00")
	writeFingerprintHeader(snapshotDigest, "snapshot", state)

	file, err := os.Open(path)
	if err != nil {
		return 0, "", "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return 0, "", "", err
	}
	openedState := stableFileState{Exists: true, Size: opened.Size(), Modified: opened.ModTime().UnixNano(), Mode: opened.Mode()}
	if openedState != state || !os.SameFile(opened, info) {
		return 0, "", "", errInputChanged
	}
	if _, err := io.Copy(io.MultiWriter(snapshotDigest, fileDigest), file); err != nil {
		return 0, "", "", err
	}
	openedAfter, err := file.Stat()
	if err != nil {
		return 0, "", "", err
	}
	openedAfterState := stableFileState{Exists: true, Size: openedAfter.Size(), Modified: openedAfter.ModTime().UnixNano(), Mode: openedAfter.Mode()}
	pathAfter, pathAfterInfo, err := stableFileStateOf(path, false)
	if err != nil || openedAfterState != state || pathAfter != state || !os.SameFile(opened, pathAfterInfo) {
		return 0, "", "", errInputChanged
	}
	return state.Size,
		hex.EncodeToString(snapshotDigest.Sum(nil)),
		hex.EncodeToString(fileDigest.Sum(nil)),
		nil
}

type backupAuxiliaryEntry struct {
	Name     string
	Kind     string
	Path     string
	State    stableFileState
	FileInfo os.FileInfo
}

func backupAuxiliaryInventory(directory string) ([]backupAuxiliaryEntry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make([]backupAuxiliaryEntry, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		upper := strings.ToUpper(entry.Name())
		kind := ""
		switch {
		case strings.HasPrefix(upper, "BAK_") && strings.HasSuffix(upper, "_TEXT"):
			kind = "text"
		case strings.HasPrefix(upper, "BAK_") && strings.HasSuffix(upper, "_MEDIA"):
			kind = "media"
		default:
			continue
		}
		identity := strings.ToLower(entry.Name())
		if seen[identity] {
			return nil, fmt.Errorf("duplicate case-insensitive phone-backup payload name: %s", entry.Name())
		}
		seen[identity] = true
		path := filepath.Join(directory, entry.Name())
		state, info, err := stableFileStateOf(path, false)
		if err != nil {
			return nil, err
		}
		result = append(result, backupAuxiliaryEntry{Name: entry.Name(), Kind: kind, Path: path, State: state, FileInfo: info})
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := strings.ToLower(result[i].Name), strings.ToLower(result[j].Name)
		if left == right {
			return result[i].Name < result[j].Name
		}
		return left < right
	})
	return result, nil
}

func sameBackupInventory(left, right []backupAuxiliaryEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].Kind != right[index].Kind || left[index].State != right[index].State ||
			!os.SameFile(left[index].FileInfo, right[index].FileInfo) {
			return false
		}
	}
	return true
}

func hashBackupAuxiliary(directory string) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		digest, err := hashBackupAuxiliaryOnce(directory)
		if err == nil {
			return digest, nil
		}
		lastErr = err
		if !errors.Is(err, errInputChanged) || attempt == 3 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", lastErr
}

func hashBackupAuxiliaryOnce(directory string) (string, error) {
	inventory, err := backupAuxiliaryInventory(directory)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	io.WriteString(digest, "wechat-phone-backup-auxiliary-v1\x00")
	for _, entry := range inventory {
		fmt.Fprintf(digest, "%d:%s:%d:%s:%d:%d:", len(entry.Name), entry.Name, len(entry.Kind), entry.Kind, entry.State.Size, entry.State.Modified)
		if entry.Kind == "text" {
			if err := hashExpectedFile(digest, "text-content", entry.Path, entry.State, entry.FileInfo); err != nil {
				return "", err
			}
		}
	}
	after, err := backupAuxiliaryInventory(directory)
	if err != nil {
		return "", err
	}
	if !sameBackupInventory(inventory, after) {
		return "", errInputChanged
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func isBackupDatabase(relativePath string) bool {
	components := strings.Split(strings.ToLower(filepath.ToSlash(relativePath)), "/")
	if len(components) < 3 || components[0] != "backupfiles" {
		return false
	}
	leaf := components[len(components)-1]
	if leaf == "backup.db" {
		return true
	}
	return isBackupArchive(leaf)
}

func isBackupArchive(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "BAK_") && (strings.HasSuffix(upper, "_TEXT") || strings.HasSuffix(upper, "_MEDIA"))
}

func loadStoredAccounts(path string) ([]storedAccount, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read chatlog config %s: %w", path, err)
	}
	var config storedConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse chatlog config %s: %w", path, err)
	}
	if len(config.History) != 0 {
		return config.History, nil
	}

	// The per-account chatlog.json written beside a WeChat data directory is a
	// ProcessConfig object rather than the central {"history": [...]} object.
	var account storedAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("parse chatlog account config %s: %w", path, err)
	}
	if account.Account != "" || account.DataDir != "" || account.DataKey != "" || account.Version != 0 {
		return []storedAccount{account}, nil
	}
	return nil, nil
}

func loadLocalAccount(dataDir string) (candidate, error) {
	path := filepath.Join(dataDir, "chatlog.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return candidate{DataDir: dataDir}, nil
		}
		return candidate{DataDir: dataDir}, fmt.Errorf("read account config %s: %w", path, err)
	}
	var stored storedAccount
	if err := json.Unmarshal(data, &stored); err != nil {
		return candidate{DataDir: dataDir}, fmt.Errorf("parse account config %s: %w", path, err)
	}
	result := candidateFromStored(stored)
	result.DataDir = dataDir
	if result.DataKey != "" {
		result.KeySource = "data_dir_config"
	}
	return result, nil
}

func candidateFromStored(account storedAccount) candidate {
	keySource := ""
	if account.DataKey != "" {
		keySource = "chatlog_config"
	}
	return candidate{
		Account:     account.Account,
		Platform:    account.Platform,
		Version:     account.Version,
		FullVersion: account.FullVersion,
		DataDir:     account.DataDir,
		DataKey:     account.DataKey,
		KeySource:   keySource,
	}
}

func mergeCandidate(all map[string]candidate, incoming candidate, preferIncoming bool) {
	if strings.TrimSpace(incoming.DataDir) == "" {
		return
	}
	incoming.DataDir, _ = filepath.Abs(filepath.Clean(incoming.DataDir))
	key := canonicalPath(incoming.DataDir)
	existing, ok := all[key]
	if !ok {
		incoming = normalizeCachedKeys(incoming)
		all[key] = incoming
		return
	}
	keyOptions := []cachedKey{{Value: existing.DataKey, Source: existing.KeySource}}
	keyOptions = append(keyOptions, existing.AlternateKeys...)
	keyOptions = append(keyOptions, cachedKey{Value: incoming.DataKey, Source: incoming.KeySource})
	keyOptions = append(keyOptions, incoming.AlternateKeys...)
	mergeString := func(old, fresh string) string {
		if fresh != "" && (old == "" || preferIncoming) {
			return fresh
		}
		return old
	}
	existing.Account = mergeString(existing.Account, incoming.Account)
	existing.Platform = mergeString(existing.Platform, incoming.Platform)
	existing.FullVersion = mergeString(existing.FullVersion, incoming.FullVersion)
	if incoming.DataKey != "" && (existing.DataKey == "" || preferIncoming) {
		existing.DataKey = incoming.DataKey
		existing.KeySource = incoming.KeySource
	}
	if incoming.Version != 0 && (existing.Version == 0 || preferIncoming) {
		existing.Version = incoming.Version
	}
	existing.Running = existing.Running || incoming.Running
	existing.AlternateKeys = keyOptions
	existing = normalizeCachedKeys(existing)
	all[key] = existing
}

func normalizeCachedKeys(account candidate) candidate {
	primary := strings.TrimSpace(account.DataKey)
	account.DataKey = primary
	seen := make(map[string]bool)
	if primary != "" {
		seen[strings.ToLower(primary)] = true
	}
	unique := make([]cachedKey, 0, len(account.AlternateKeys))
	for _, option := range account.AlternateKeys {
		option.Value = strings.TrimSpace(option.Value)
		if option.Value == "" || seen[strings.ToLower(option.Value)] {
			continue
		}
		seen[strings.ToLower(option.Value)] = true
		unique = append(unique, option)
	}
	account.AlternateKeys = unique
	return account
}

func selectCachedKey(account candidate, databasePath string) (candidate, bool) {
	options := []cachedKey{{Value: account.DataKey, Source: account.KeySource}}
	options = append(options, account.AlternateKeys...)
	for index, option := range options {
		if strings.TrimSpace(option.Value) == "" {
			continue
		}
		trial := account
		trial.DataKey = option.Value
		trial.KeySource = option.Source
		if validDataKey(trial, databasePath) {
			return trial, index != 0
		}
	}
	account.DataKey = ""
	account.KeySource = ""
	return account, false
}

func selectValidationDatabase(account candidate, databasePaths []string) string {
	canonical := decrypt.GetSimpleDBFile(account.Platform, account.Version)
	if canonical != "" {
		expected := canonicalPath(filepath.Join(account.DataDir, canonical))
		for _, databasePath := range databasePaths {
			if canonicalPath(databasePath) == expected && !hasSQLiteHeader(databasePath) {
				return databasePath
			}
		}
	}

	firstEncrypted := ""
	for _, databasePath := range databasePaths {
		if hasSQLiteHeader(databasePath) {
			continue
		}
		if firstEncrypted == "" {
			firstEncrypted = databasePath
		}
		relative, err := filepath.Rel(account.DataDir, databasePath)
		if err != nil {
			continue
		}
		isBackup := false
		for _, component := range strings.Split(strings.ToLower(filepath.ToSlash(relative)), "/") {
			if component == "backupfiles" {
				isBackup = true
				break
			}
		}
		if !isBackup {
			return databasePath
		}
	}
	return firstEncrypted
}

func candidateRoots(candidates map[string]candidate) []string {
	seen := make(map[string]bool)
	var roots []string
	add := func(path string) {
		if path == "" {
			return
		}
		path, err := filepath.Abs(path)
		if err != nil || seen[canonicalPath(path)] {
			return
		}
		seen[canonicalPath(path)] = true
		roots = append(roots, path)
	}
	for _, account := range candidates {
		add(filepath.Dir(account.DataDir))
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"WeChat Files", "Weixin Files", "xwechat_files"} {
			add(filepath.Join(home, "Documents", name))
		}
	}
	for _, envName := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		if root := os.Getenv(envName); root != "" {
			for _, name := range []string{"WeChat Files", "Weixin Files", "xwechat_files"} {
				add(filepath.Join(root, "Documents", name))
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, root := range registryDataRoots() {
			add(root)
			for _, name := range []string{"WeChat Files", "Weixin Files", "xwechat_files"} {
				add(filepath.Join(root, name))
			}
		}
	}
	return roots
}

func registryDataRoots() []string {
	var roots []string
	for _, key := range []string{`HKCU\Software\Tencent\WeChat`, `HKCU\Software\Tencent\Weixin`} {
		output, err := exec.Command("reg.exe", "query", key, "/v", "FileSavePath").CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			for index, field := range fields {
				if strings.HasPrefix(field, "REG_") && index+1 < len(fields) {
					value := expandPercentEnvironment(strings.Join(fields[index+1:], " "))
					if value != "" {
						roots = append(roots, value)
					}
					break
				}
			}
		}
	}
	return roots
}

func expandPercentEnvironment(value string) string {
	for start := strings.IndexByte(value, '%'); start >= 0; start = strings.IndexByte(value, '%') {
		endOffset := strings.IndexByte(value[start+1:], '%')
		if endOffset < 0 {
			break
		}
		end := start + 1 + endOffset
		name := value[start+1 : end]
		replacement, ok := os.LookupEnv(name)
		if !ok {
			break
		}
		value = value[:start] + replacement + value[end+1:]
	}
	return strings.TrimSpace(value)
}

func discoverAccountDirs(roots []string) ([]string, []manifestProblem) {
	seen := make(map[string]bool)
	var result []string
	var problems []manifestProblem
	for _, root := range roots {
		if isWechatDataDir(root) && !seen[canonicalPath(root)] {
			seen[canonicalPath(root)] = true
			result = append(result, root)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			if !os.IsNotExist(err) {
				problems = append(problems, manifestProblem{
					DataDir: root,
					Reason:  "could not scan a potential WeChat account root: " + err.Error(),
				})
			}
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			path := filepath.Join(root, entry.Name())
			if !isWechatDataDir(path) || seen[canonicalPath(path)] {
				continue
			}
			seen[canonicalPath(path)] = true
			result = append(result, path)
		}
	}
	sort.Strings(result)
	return result, problems
}

func isWechatDataDir(path string) bool {
	markers := []string{
		filepath.Join(path, "Msg", "Misc.db"),
		filepath.Join(path, "Msg", "MicroMsg.db"),
		filepath.Join(path, "db_storage", "session", "session.db"),
	}
	for _, marker := range markers {
		if info, err := os.Stat(marker); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func inferVersion(dataDir string) int {
	if _, err := os.Stat(filepath.Join(dataDir, "db_storage", "session", "session.db")); err == nil {
		return 4
	}
	if _, err := os.Stat(filepath.Join(dataDir, "Msg")); err == nil {
		return 3
	}
	return 0
}

func listDatabaseFiles(dataDir string, includeBackupArchives bool) ([]string, []string) {
	var files []string
	var problems []string
	_ = filepath.WalkDir(dataDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, walkErr))
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			problems = append(problems, fmt.Sprintf("%s is a symbolic link or reparse point", path))
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".db") {
			files = append(files, path)
		} else if includeBackupArchives {
			upper := strings.ToUpper(entry.Name())
			if strings.HasPrefix(upper, "BAK_") && (strings.HasSuffix(upper, "_TEXT") || strings.HasSuffix(upper, "_MEDIA")) {
				files = append(files, path)
			}
		}
		return nil
	})
	sort.Strings(files)
	return files, problems
}

func sameDatabaseInventory(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]bool, len(left))
	for _, path := range left {
		seen[canonicalPath(path)] = true
	}
	if len(seen) != len(left) {
		return false
	}
	for _, path := range right {
		if !seen[canonicalPath(path)] {
			return false
		}
	}
	return true
}

const (
	sqliteWALHeaderSize      = 32
	sqliteWALFrameHeaderSize = 24
	sqliteWALMagicLittle     = uint32(0x377f0682)
	sqliteWALMagicBig        = uint32(0x377f0683)
	sqliteWALFormatVersion   = uint32(3007000)
)

func sqliteWALChecksum(data []byte, bigEndian bool, first, second uint32) (uint32, uint32, error) {
	if len(data) == 0 || len(data)%8 != 0 {
		return 0, 0, fmt.Errorf("WAL checksum input length %d is not a positive multiple of 8", len(data))
	}
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	for offset := 0; offset < len(data); offset += 8 {
		first += order.Uint32(data[offset:offset+4]) + second
		second += order.Uint32(data[offset+4:offset+8]) + first
	}
	return first, second, nil
}

// materializeEncryptedWALSnapshot creates a standalone encrypted database image
// by applying only complete, checksum-verified WAL transactions. SQLCipher-style
// WAL page payloads remain encrypted database pages, so the ordinary decryptor
// can process the resulting image without modifying the source database.
func materializeEncryptedWALSnapshot(mainPath, walPath, destination string, pageSize int64) (returnErr error) {
	if pageSize <= 0 || pageSize > int64(^uint32(0)) {
		return fmt.Errorf("unsupported encrypted database page size %d", pageSize)
	}
	mainFile, err := os.Open(mainPath)
	if err != nil {
		return fmt.Errorf("open encrypted database for WAL snapshot: %w", err)
	}
	defer mainFile.Close()
	mainInfo, err := mainFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect encrypted database for WAL snapshot: %w", err)
	}
	if !mainInfo.Mode().IsRegular() || mainInfo.Size() <= 0 || mainInfo.Size()%pageSize != 0 {
		return fmt.Errorf("encrypted database is not a regular positive multiple of its %d-byte page size", pageSize)
	}

	walFile, err := os.Open(walPath)
	if err != nil {
		return fmt.Errorf("open encrypted database WAL: %w", err)
	}
	defer walFile.Close()
	walInfo, err := walFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect encrypted database WAL: %w", err)
	}
	if !walInfo.Mode().IsRegular() {
		return fmt.Errorf("encrypted database WAL is not a regular file")
	}
	if walInfo.Size() < sqliteWALHeaderSize {
		return fmt.Errorf("encrypted database WAL is shorter than its %d-byte header", sqliteWALHeaderSize)
	}
	frameSize := int64(sqliteWALFrameHeaderSize) + pageSize
	frameBytes := walInfo.Size() - sqliteWALHeaderSize
	if frameBytes%frameSize != 0 {
		return fmt.Errorf("encrypted database WAL size %d does not contain complete %d-byte frames", walInfo.Size(), frameSize)
	}

	_ = os.Remove(destination)
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create encrypted WAL snapshot: %w", err)
	}
	closed := false
	succeeded := false
	defer func() {
		if !closed {
			if closeErr := output.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
		if !succeeded || returnErr != nil {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.CopyN(output, mainFile, mainInfo.Size()); err != nil {
		return fmt.Errorf("copy encrypted database for WAL snapshot: %w", err)
	}
	if after, err := mainFile.Stat(); err != nil || after.Size() != mainInfo.Size() || after.ModTime() != mainInfo.ModTime() {
		return fmt.Errorf("encrypted database changed while its WAL snapshot was being copied")
	}

	header := make([]byte, sqliteWALHeaderSize)
	if _, err := io.ReadFull(walFile, header); err != nil {
		return fmt.Errorf("read encrypted database WAL header: %w", err)
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != sqliteWALMagicLittle && magic != sqliteWALMagicBig {
		return fmt.Errorf("encrypted database WAL has an invalid magic number")
	}
	if binary.BigEndian.Uint32(header[4:8]) != sqliteWALFormatVersion {
		return fmt.Errorf("encrypted database WAL uses an unsupported format version")
	}
	walPageSize := binary.BigEndian.Uint32(header[8:12])
	if walPageSize == 1 {
		walPageSize = 65536
	}
	if int64(walPageSize) != pageSize {
		return fmt.Errorf("encrypted database WAL page size %d does not match database page size %d", walPageSize, pageSize)
	}
	bigEndianChecksum := magic == sqliteWALMagicBig
	checksumFirst, checksumSecond, err := sqliteWALChecksum(header[:24], bigEndianChecksum, 0, 0)
	if err != nil {
		return err
	}
	if checksumFirst != binary.BigEndian.Uint32(header[24:28]) || checksumSecond != binary.BigEndian.Uint32(header[28:32]) {
		return fmt.Errorf("encrypted database WAL header checksum is invalid")
	}
	saltFirst := binary.BigEndian.Uint32(header[16:20])
	saltSecond := binary.BigEndian.Uint32(header[20:24])

	frameHeader := make([]byte, sqliteWALFrameHeaderSize)
	page := make([]byte, int(pageSize))
	pending := make(map[uint32][]byte)
	frameCount := frameBytes / frameSize
	for frameIndex := int64(0); frameIndex < frameCount; frameIndex++ {
		if _, err := io.ReadFull(walFile, frameHeader); err != nil {
			return fmt.Errorf("read encrypted database WAL frame %d header: %w", frameIndex+1, err)
		}
		if _, err := io.ReadFull(walFile, page); err != nil {
			return fmt.Errorf("read encrypted database WAL frame %d page: %w", frameIndex+1, err)
		}
		pageNumber := binary.BigEndian.Uint32(frameHeader[0:4])
		if pageNumber == 0 {
			return fmt.Errorf("encrypted database WAL frame %d has page number zero", frameIndex+1)
		}
		if binary.BigEndian.Uint32(frameHeader[8:12]) != saltFirst || binary.BigEndian.Uint32(frameHeader[12:16]) != saltSecond {
			return fmt.Errorf("encrypted database WAL frame %d has mismatched salts", frameIndex+1)
		}
		checksumFirst, checksumSecond, err = sqliteWALChecksum(frameHeader[:8], bigEndianChecksum, checksumFirst, checksumSecond)
		if err != nil {
			return err
		}
		checksumFirst, checksumSecond, err = sqliteWALChecksum(page, bigEndianChecksum, checksumFirst, checksumSecond)
		if err != nil {
			return err
		}
		if checksumFirst != binary.BigEndian.Uint32(frameHeader[16:20]) || checksumSecond != binary.BigEndian.Uint32(frameHeader[20:24]) {
			return fmt.Errorf("encrypted database WAL frame %d checksum is invalid", frameIndex+1)
		}
		pending[pageNumber] = append([]byte(nil), page...)

		databasePages := binary.BigEndian.Uint32(frameHeader[4:8])
		if databasePages == 0 {
			continue
		}
		for committedPage, contents := range pending {
			if committedPage > databasePages {
				continue
			}
			offset := (int64(committedPage) - 1) * pageSize
			if _, err := output.WriteAt(contents, offset); err != nil {
				return fmt.Errorf("apply encrypted database WAL page %d: %w", committedPage, err)
			}
		}
		if err := output.Truncate(int64(databasePages) * pageSize); err != nil {
			return fmt.Errorf("apply encrypted database WAL commit size: %w", err)
		}
		clear(pending)
	}
	if after, err := walFile.Stat(); err != nil || after.Size() != walInfo.Size() || after.ModTime() != walInfo.ModTime() {
		return fmt.Errorf("encrypted database WAL changed while its snapshot was being materialized")
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("flush encrypted WAL snapshot: %w", err)
	}
	if err := output.Close(); err != nil {
		closed = true
		return fmt.Errorf("close encrypted WAL snapshot: %w", err)
	}
	closed = true
	succeeded = true
	return nil
}

func prepareDatabase(source, destination string, account candidate) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}
	if hasSQLiteHeader(source) {
		return snapshotSQLite(source, destination)
	}
	if isBackupArchive(filepath.Base(source)) {
		return copyFileBytes(source, destination)
	}

	decryptor, err := decrypt.NewDecryptor(account.Platform, account.Version)
	if err != nil {
		return err
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("inspect encrypted database: %w", err)
	}
	pageSize := int64(decryptor.GetPageSize())
	if pageSize <= 0 || sourceInfo.Size() == 0 || sourceInfo.Size()%pageSize != 0 {
		return fmt.Errorf("encrypted database size %d is not a positive multiple of its %d-byte page size", sourceInfo.Size(), pageSize)
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		beforeWAL, walErr := optionalFileSignatureOf(source + "-wal")
		if walErr != nil {
			return fmt.Errorf("inspect encrypted database WAL: %w", walErr)
		}
		before, statErr := fileSignatureOf(source)
		if statErr != nil {
			return statErr
		}
		decryptSource := source
		encryptedSnapshot := destination + ".encrypted.tmp"
		_ = os.Remove(encryptedSnapshot)
		if beforeWAL.Exists && beforeWAL.Size > 0 {
			if snapshotErr := materializeEncryptedWALSnapshot(source, source+"-wal", encryptedSnapshot, pageSize); snapshotErr != nil {
				lastErr = fmt.Errorf("materialize encrypted database WAL: %w", snapshotErr)
				_ = os.Remove(encryptedSnapshot)
				if attempt < 3 {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				break
			}
			decryptSource = encryptedSnapshot
		}
		temporary := destination + ".tmp"
		_ = os.Remove(temporary)
		output, createErr := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			_ = os.Remove(encryptedSnapshot)
			return fmt.Errorf("create decrypted database: %w", createErr)
		}
		decryptErr := decryptor.Decrypt(context.Background(), decryptSource, account.DataKey, output)
		closeErr := output.Close()
		_ = os.Remove(encryptedSnapshot)
		if decryptErr == nil && closeErr != nil {
			decryptErr = closeErr
		}
		after, afterErr := fileSignatureOf(source)
		if decryptErr == nil && afterErr != nil {
			decryptErr = afterErr
		}
		afterWAL, afterWALErr := optionalFileSignatureOf(source + "-wal")
		if decryptErr == nil && afterWALErr != nil {
			decryptErr = fmt.Errorf("inspect encrypted database WAL after decryption: %w", afterWALErr)
		}
		if decryptErr == nil && before != after {
			decryptErr = fmt.Errorf("source database changed while it was being decrypted")
		}
		if decryptErr == nil && beforeWAL != afterWAL {
			decryptErr = fmt.Errorf("encrypted database WAL changed while it was being decrypted; close WeChat cleanly and rerun the export")
		}
		if decryptErr == nil && !hasSQLiteHeader(temporary) {
			decryptErr = fmt.Errorf("decrypted output does not have a SQLite header")
		}
		if decryptErr == nil {
			if err := replaceFile(temporary, destination); err != nil {
				_ = os.Remove(temporary)
				return fmt.Errorf("publish decrypted database: %w", err)
			}
			return nil
		}
		lastErr = decryptErr
		_ = os.Remove(temporary)
		if attempt < 3 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return fmt.Errorf("decrypt %s after 3 attempts: %w", filepath.Base(source), lastErr)
}

func validDataKey(account candidate, databasePath string) bool {
	decryptor, err := decrypt.NewDecryptor(account.Platform, account.Version)
	if err != nil {
		return false
	}
	key, err := hex.DecodeString(strings.TrimSpace(account.DataKey))
	if err != nil {
		return false
	}
	file, err := os.Open(databasePath)
	if err != nil {
		return false
	}
	defer file.Close()
	page := make([]byte, decryptor.GetPageSize())
	if _, err := io.ReadFull(file, page); err != nil {
		return false
	}
	return decryptor.Validate(page, key)
}

type fileSignature struct {
	Size       int64
	ModifiedAt int64
}

type optionalFileSignature struct {
	Exists     bool
	Size       int64
	ModifiedAt int64
}

func fileSignatureOf(path string) (fileSignature, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileSignature{}, err
	}
	return fileSignature{Size: info.Size(), ModifiedAt: info.ModTime().UnixNano()}, nil
}

func optionalFileSignatureOf(path string) (optionalFileSignature, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return optionalFileSignature{}, nil
		}
		return optionalFileSignature{}, err
	}
	if info.IsDir() {
		return optionalFileSignature{}, fmt.Errorf("path is a directory: %s", path)
	}
	if info.Size() == 0 {
		// SQLite may create or remove an empty WAL merely by opening a
		// WAL-mode database read-only. With no frames, both states represent
		// the same logical input; a non-empty WAL remains significant.
		return optionalFileSignature{}, nil
	}
	return optionalFileSignature{
		Exists:     true,
		Size:       info.Size(),
		ModifiedAt: info.ModTime().UnixNano(),
	}, nil
}

func copyFileBytes(source, destination string) error {
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		output.Close()
		if !succeeded {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if after, err := input.Stat(); err != nil || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return fmt.Errorf("file changed while being copied: %s", source)
	}
	succeeded = true
	output.Close()
	return replaceFile(temporary, destination)
}

func snapshotSQLite(source, destination string) error {
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	dsn := "file:" + filepath.ToSlash(source) + "?mode=ro"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open plaintext SQLite database: %w", err)
	}
	defer database.Close()
	if _, err := database.Exec("PRAGMA busy_timeout=10000"); err != nil {
		return fmt.Errorf("set SQLite busy timeout: %w", err)
	}
	if _, err := database.Exec("VACUUM INTO " + sqliteString(temporary)); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("create consistent SQLite snapshot: %w", err)
	}
	if !hasSQLiteHeader(temporary) {
		_ = os.Remove(temporary)
		return fmt.Errorf("SQLite snapshot does not have a valid header")
	}
	if err := replaceFile(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func verifySQLiteIntegrity(path string) error {
	if !hasSQLiteHeader(path) {
		return fmt.Errorf("database does not have a SQLite 3 header")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if info, err := os.Lstat(path + suffix); err == nil {
			return fmt.Errorf("standalone SQLite snapshot unexpectedly has a %s sidecar (%d bytes)", suffix, info.Size())
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect SQLite sidecar %s: %w", suffix, err)
		}
	}

	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&immutable=1"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open staged SQLite database: %w", err)
	}
	defer database.Close()
	if _, err := database.Exec("PRAGMA query_only=ON"); err != nil {
		return fmt.Errorf("make SQLite verification connection read-only: %w", err)
	}
	var schemaObjects int64
	if err := database.QueryRow("SELECT count(*) FROM sqlite_schema").Scan(&schemaObjects); err != nil {
		return fmt.Errorf("read SQLite schema: %w", err)
	}

	rows, err := database.Query("PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("run PRAGMA integrity_check: %w", err)
	}
	defer rows.Close()
	results := []string{}
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("read PRAGMA integrity_check result: %w", err)
		}
		if len(results) < 8 {
			results = append(results, result)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("complete PRAGMA integrity_check: %w", err)
	}
	if len(results) != 1 || results[0] != "ok" {
		if len(results) == 0 {
			return fmt.Errorf("PRAGMA integrity_check returned no result")
		}
		return fmt.Errorf("PRAGMA integrity_check failed: %s", strings.Join(results, "; "))
	}
	return nil
}

func sqliteString(value string) string {
	return "'" + strings.ReplaceAll(filepath.ToSlash(value), "'", "''") + "'"
}

func hasSQLiteHeader(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	header := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(file, header); err != nil {
		return false
	}
	return string(header) == sqliteHeader
}

func writeManifest(path string, manifest *exportManifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	encodeErr := encoder.Encode(manifest)
	closeErr := file.Close()
	if encodeErr != nil {
		_ = os.Remove(temporary)
		return encodeErr
	}
	if closeErr != nil {
		_ = os.Remove(temporary)
		return closeErr
	}
	return replaceFile(temporary, path)
}

func replaceFile(source, destination string) error {
	destinationInfo, err := os.Lstat(destination)
	if err != nil {
		if os.IsNotExist(err) {
			return os.Rename(source, destination)
		}
		return fmt.Errorf("inspect existing destination: %w", err)
	}
	if destinationInfo.IsDir() {
		return fmt.Errorf("destination is a directory: %s", destination)
	}

	backup := fmt.Sprintf("%s.backup-%d-%d", destination, os.Getpid(), time.Now().UnixNano())
	if err := os.Rename(destination, backup); err != nil {
		return fmt.Errorf("back up existing destination: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		restoreErr := os.Rename(backup, destination)
		if restoreErr != nil {
			return fmt.Errorf("publish replacement: %v (also failed to restore previous destination: %v)", err, restoreErr)
		}
		return fmt.Errorf("publish replacement: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}

func pathWithin(parent, child string) bool {
	parent, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	child, err = filepath.Abs(child)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func pathsOverlap(left, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func canonicalPath(path string) string {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		abs = filepath.Clean(path)
	}
	if runtime.GOOS == "windows" {
		return strings.ToLower(abs)
	}
	return abs
}

func safeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "account"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}
	result := strings.Trim(builder.String(), "_")
	if result == "" {
		return "account"
	}
	if len(result) > 48 {
		return result[:48]
	}
	return result
}

func shortHash(value string) string {
	digest := sha1.Sum([]byte(canonicalPath(value)))
	return hex.EncodeToString(digest[:])[:10]
}

func displayAccount(account candidate) string {
	if account.Account != "" {
		return account.Account
	}
	if account.DataDir != "" {
		return filepath.Base(account.DataDir)
	}
	return "unknown account"
}
