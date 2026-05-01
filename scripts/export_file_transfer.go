package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/pkg/util/lz4"
	"github.com/sjzar/chatlog/pkg/util/zstd"
	_ "modernc.org/sqlite"
)

type FileTransferMsg struct {
	MsgSvrID   int64  `json:"MsgSvrID"`
	CreateTime int64  `json:"CreateTime"`
	IsSender   int    `json:"IsSender"`
	Type       int    `json:"Type"`
	SubType    int    `json:"SubType"`
	StrContent string `json:"StrContent"`
	Title      string `json:"Title,omitempty"`
	URL        string `json:"Url,omitempty"`
}

func main() {
	outDir := filepath.Join("temp", "results")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	wechat.Load()
	accounts := wechat.GetAccounts()
	if len(accounts) == 0 {
		fmt.Println("No WeChat instances found")
		return
	}

	var allMessages []FileTransferMsg

	for _, acc := range accounts {
		fmt.Printf("Checking Account: %s, Version: %d\n", acc.Name, acc.Version)
		_, _, err := acc.GetKey(context.Background())
		if err != nil {
			fmt.Printf("Error getting key: %v\n", err)
			continue
		}

		var msgDirs []string
		if acc.Version == 3 {
			msgDirs = []string{filepath.Join(acc.DataDir, "Msg", "Multi")}
		} else {
			msgDirs = []string{filepath.Join(acc.DataDir, "db_storage", "message")}
		}

		for _, msgDir := range msgDirs {
			entries, err := os.ReadDir(msgDir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				name := entry.Name()
				if strings.HasSuffix(name, ".db") && (strings.HasPrefix(name, "MSG") || strings.HasPrefix(name, "message_")) {
					dbPath := filepath.Join(msgDir, name)
					decryptedDbPath := filepath.Join(outDir, name+"_decrypted.db")

					err = acc.DecryptDatabase(context.Background(), dbPath, decryptedDbPath)
					if err != nil {
						continue
					}

					msgs := queryFileHelper(decryptedDbPath, acc.Version)
					allMessages = append(allMessages, msgs...)
					os.Remove(decryptedDbPath) // clean up after query
				}
			}
		}
	}

	outPath := filepath.Join(outDir, "file_transfer_messages.json")
	file, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("Create output file failed: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(allMessages); err != nil {
		log.Fatalf("Encode JSON failed: %v", err)
	}

	fmt.Printf("Successfully exported %d messages to %s\n", len(allMessages), outPath)
}

func queryFileHelper(dbPath string, version int) []FileTransferMsg {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	var msgs []FileTransferMsg
	var query string

	if version == 3 {
		query = "SELECT MsgSvrID, CreateTime, IsSender, Type, SubType, StrContent, CompressContent FROM MSG WHERE StrTalker = 'filehelper'"
	} else {
		// For V4, table name is Msg_md5(talker)
		hash := md5.Sum([]byte("filehelper"))
		tableName := fmt.Sprintf("Msg_%s", hex.EncodeToString(hash[:]))
		
		// Check if table exists
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
		if err != nil {
			return nil
		}

		query = fmt.Sprintf("SELECT server_id, create_time, status, local_type, 0, '', message_content FROM %s", tableName)
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var m FileTransferMsg
		var compressContent []byte
		
		if err := rows.Scan(&m.MsgSvrID, &m.CreateTime, &m.IsSender, &m.Type, &m.SubType, &m.StrContent, &compressContent); err == nil {
			contentStr := m.StrContent
			
			if version == 3 {
				if m.Type == 49 && len(compressContent) > 0 {
					if b, err := lz4.Decompress(compressContent); err == nil {
						contentStr = string(b)
					}
				}
			} else {
				// V4 decompression logic
				if bytes.HasPrefix(compressContent, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
					if b, err := zstd.Decompress(compressContent); err == nil {
						contentStr = string(b)
					}
				} else {
					contentStr = string(compressContent)
				}
			}
			
			m.StrContent = contentStr

			if m.Type == 49 {
				var msg struct {
					XMLName xml.Name `xml:"msg"`
					App     struct {
						Type  int    `xml:"type"`
						Title string `xml:"title"`
						URL   string `xml:"url"`
					} `xml:"appmsg"`
				}
				if err := xml.Unmarshal([]byte(contentStr), &msg); err == nil {
					m.SubType = msg.App.Type
					if m.SubType == 5 {
						m.Title = msg.App.Title
						m.URL = msg.App.URL
					}
				}
			}

			msgs = append(msgs, m)
		}
	}
	return msgs
}
