//go:build windows

// Command recover_wechat_backup_key scans a running WeChat process for a
// 32-byte key that validates every explicitly named encrypted Backup.db. It
// never writes the key to stdout; the caller must provide an exclusive output
// file inside an ACL-protected staging directory.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/pkg/util"
)

const (
	backupKeySize = 32
	readChunkSize = 4 << 20
)

type databasePathsFlag []string

func (paths *databasePathsFlag) String() string {
	return strings.Join(*paths, ",")
}

func (paths *databasePathsFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("database path is empty")
	}
	*paths = append(*paths, value)
	return nil
}

func main() {
	pidsValue := flag.String("pids", "", "comma-separated WeChat process IDs")
	var databasePaths databasePathsFlag
	flag.Var(&databasePaths, "database", "encrypted Backup.db used for validation (repeat for every database)")
	version := flag.Int("version", 3, "Windows database major version (3 or 4)")
	outputPath := flag.String("output", "", "exclusive output path for the recovered hexadecimal key")
	flag.Parse()

	if strings.TrimSpace(*pidsValue) == "" || len(databasePaths) == 0 || strings.TrimSpace(*outputPath) == "" {
		fmt.Fprintln(os.Stderr, "pids, database, and output are required")
		os.Exit(2)
	}

	decryptor, err := decrypt.NewDecryptor("windows", *version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not initialize backup database validation")
		os.Exit(1)
	}
	pages := make([][]byte, 0, len(databasePaths))
	for _, databasePath := range databasePaths {
		file, openErr := os.Open(databasePath)
		if openErr != nil {
			fmt.Fprintln(os.Stderr, "could not open backup database")
			os.Exit(1)
		}
		page := make([]byte, decryptor.GetPageSize())
		_, readErr := io.ReadFull(file, page)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			fmt.Fprintln(os.Stderr, "could not read backup database header")
			os.Exit(1)
		}
		pages = append(pages, page)
	}

	for _, rawPID := range strings.Split(*pidsValue, ",") {
		pid64, parseErr := strconv.ParseUint(strings.TrimSpace(rawPID), 10, 32)
		if parseErr != nil {
			continue
		}
		key, scanErr := findBackupKey(uint32(pid64), func(candidate []byte) bool {
			for _, page := range pages {
				if !decryptor.Validate(page, candidate) {
					return false
				}
			}
			return true
		})
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "PID %d could not be scanned: %v\n", pid64, scanErr)
			continue
		}
		if len(key) == backupKeySize {
			if err := writeExclusive(*outputPath, []byte(hex.EncodeToString(key))); err != nil {
				fmt.Fprintln(os.Stderr, "could not write recovered backup key")
				os.Exit(1)
			}
			fmt.Printf("Recovered and validated the backup key from PID %d.\n", pid64)
			return
		}
	}

	fmt.Fprintln(os.Stderr, "no running WeChat process contained a key that validates Backup.db")
	os.Exit(1)
}

func findBackupKey(pid uint32, validate func([]byte) bool) ([]byte, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	is64Bit, err := util.Is64Bit(handle)
	if err != nil {
		return nil, err
	}
	ptrSize := 4
	if is64Bit {
		ptrSize = 8
	}

	seen := make(map[[sha256.Size]byte]struct{})
	var current uintptr = 0x10000
	maxAddress := uintptr(0x7fff0000)
	if is64Bit {
		maxAddress = uintptr(0x7fffffffffff)
	}

	for current < maxAddress {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, current, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= current {
			break
		}
		if mbi.State == windows.MEM_COMMIT && readableWritable(mbi.Protect) {
			if key := scanRegion(handle, mbi.BaseAddress, mbi.RegionSize, ptrSize, seen, validate); len(key) != 0 {
				return key, nil
			}
		}
		current = next
	}
	return nil, nil
}

func readableWritable(protect uint32) bool {
	if protect&windows.PAGE_GUARD != 0 || protect&windows.PAGE_NOACCESS != 0 {
		return false
	}
	return protect&(windows.PAGE_READWRITE|windows.PAGE_WRITECOPY|windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0
}

func scanRegion(handle windows.Handle, base, size uintptr, ptrSize int, seen map[[sha256.Size]byte]struct{}, validate func([]byte) bool) []byte {
	pattern := []byte{backupKeySize, 0, 0, 0}
	for offset := uintptr(0); offset < size; {
		remaining := size - offset
		chunkSize := uintptr(readChunkSize)
		if remaining < chunkSize {
			chunkSize = remaining
		}
		chunk := make([]byte, chunkSize)
		var bytesRead uintptr
		if err := windows.ReadProcessMemory(handle, base+offset, &chunk[0], chunkSize, &bytesRead); err == nil && bytesRead > 0 {
			chunk = chunk[:bytesRead]
			for cursor := 0; cursor < len(chunk); {
				index := bytes.Index(chunk[cursor:], pattern)
				if index < 0 {
					break
				}
				index += cursor
				if index >= ptrSize {
					pointer := pointerValue(chunk[index-ptrSize:index], ptrSize)
					if pointer >= 0x10000 && pointer < uint64(0x7fffffffffff) {
						candidate := make([]byte, backupKeySize)
						var candidateRead uintptr
						if err := windows.ReadProcessMemory(handle, uintptr(pointer), &candidate[0], backupKeySize, &candidateRead); err == nil && candidateRead == backupKeySize {
							digest := sha256.Sum256(candidate)
							if _, ok := seen[digest]; !ok {
								seen[digest] = struct{}{}
								if validate(candidate) {
									return candidate
								}
							}
						}
					}
				}
				cursor = index + 1
			}
		}
		offset += chunkSize
	}
	return nil
}

func pointerValue(raw []byte, ptrSize int) uint64 {
	var value uint64
	for index := ptrSize - 1; index >= 0; index-- {
		value = value<<8 | uint64(raw[index])
	}
	return value
}

func writeExclusive(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(value)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}
