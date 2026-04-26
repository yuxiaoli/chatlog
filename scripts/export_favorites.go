package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clbanning/mxj/v2"
	"github.com/sjzar/chatlog/internal/wechat"
	_ "modernc.org/sqlite"
)

type FavItemXML struct {
	XMLName    xml.Name `xml:"favitem"`
	Type       int      `xml:"type,attr"`
	WebURLItem struct {
		PageTitle string `xml:"pagetitle"`
		Link      string `xml:"link"`
	} `xml:"weburlitem"`
	Desc     string `xml:"desc"`
	Title    string `xml:"title"`
	DataList struct {
		DataItems []struct {
			DataType  string `xml:"datatype,attr"`
			DataTitle string `xml:"datatitle"`
			DataDesc  string `xml:"datadesc"`
		} `xml:"dataitem"`
	} `xml:"datalist"`
	Source struct {
		FromUser string `xml:"fromusr"`
	} `xml:"source"`
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

	var decryptedDbPath string

	for _, acc := range accounts {
		fmt.Printf("Checking Account: %s, Version: %d\n", acc.Name, acc.Version)
		_, _, err := acc.GetKey(context.Background())
		if err != nil {
			fmt.Printf("Error getting key: %v\n", err)
			continue
		}

		var favPath string
		if acc.Version == 3 {
			favPath = filepath.Join(acc.DataDir, "Msg", "Favorite.db")
		} else {
			favPath = filepath.Join(acc.DataDir, "db_storage", "favorite", "favorite.db")
		}

		if _, err := os.Stat(favPath); err == nil {
			decryptedDbPath = filepath.Join(outDir, "Favorite_decrypted.db")
			err = acc.DecryptDatabase(context.Background(), favPath, decryptedDbPath)
			if err != nil {
				fmt.Printf("Decrypt failed for %s: %v\n", favPath, err)
			} else {
				fmt.Printf("Successfully decrypted DB to %s\n", decryptedDbPath)
				break
			}
		} else {
			fmt.Printf("Favorite.db not found at %s\n", favPath)
		}
	}

	if decryptedDbPath == "" {
		log.Fatal("Could not find or decrypt any Favorite.db")
	}

	exportJSON(decryptedDbPath, filepath.Join(outDir, "wechat_favorites.json"))
	exportMD(decryptedDbPath, filepath.Join(outDir, "wechat_favorites.md"))
}

func exportJSON(dbPath, outPath string) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("JSON Export Error: %v", err)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM FavItems ORDER BY UpdateTime DESC")
	if err != nil {
		log.Printf("JSON Export Query Error: %v", err)
		return
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		log.Printf("JSON Export Columns Error: %v", err)
		return
	}

	var allFavorites []map[string]interface{}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			log.Printf("JSON Export Scan Error: %v", err)
			return
		}

		rowMap := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				rowMap[col] = string(b)
			} else {
				rowMap[col] = val
			}
		}

		if xmlBuf, ok := rowMap["XmlBuf"].(string); ok && xmlBuf != "" {
			m, err := mxj.NewMapXml([]byte(xmlBuf))
			if err == nil {
				rowMap["XmlData"] = m
			} else {
				rowMap["XmlData"] = map[string]interface{}{
					"error": "Failed to parse XML",
					"raw":   xmlBuf,
				}
			}
		}

		allFavorites = append(allFavorites, rowMap)
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("JSON Export File Error: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(allFavorites); err != nil {
		log.Printf("JSON Export Encode Error: %v", err)
		return
	}

	fmt.Printf("Exported %d favorites with all fields to %s\n", len(allFavorites), outPath)
}

func exportMD(dbPath, outPath string) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("MD Export Error: %v", err)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT FavLocalID, Type, UpdateTime, XmlBuf FROM FavItems ORDER BY UpdateTime DESC")
	if err != nil {
		log.Printf("MD Export Query Error: %v", err)
		return
	}
	defer rows.Close()

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("MD Export File Error: %v", err)
		return
	}
	defer file.Close()

	file.WriteString("# WeChat Favorites\n\n")

	count := 0
	for rows.Next() {
		var id int
		var typ int
		var utime int
		var xmlBuf string
		rows.Scan(&id, &typ, &utime, &xmlBuf)

		var item FavItemXML
		_ = xml.Unmarshal([]byte(xmlBuf), &item)

		t := time.Unix(int64(utime), 0).Format("2006-01-02 15:04:05")

		title := ""
		content := ""
		link := ""

		if typ == 1 {
			title = "Text Favorite"
			content = item.Desc
		} else if typ == 5 {
			title = item.WebURLItem.PageTitle
			link = item.WebURLItem.Link
		} else if typ == 2 {
			title = "Image Favorite"
		} else if typ == 4 {
			title = "Video Favorite"
		} else if typ == 8 {
			title = "File Favorite"
			if len(item.DataList.DataItems) > 0 {
				title = item.DataList.DataItems[0].DataTitle
			}
		} else if typ == 14 {
			title = item.Title
			content = item.Desc
		} else {
			title = fmt.Sprintf("Other Favorite (Type: %d)", typ)
			if item.Title != "" {
				title = item.Title
			}
			content = item.Desc
		}

		if title == "" {
			title = "Untitled"
		}

		title = strings.TrimSpace(strings.ReplaceAll(title, "\n", " "))

		file.WriteString(fmt.Sprintf("## %s\n", title))
		file.WriteString(fmt.Sprintf("- **Date:** %s\n", t))
		if item.Source.FromUser != "" {
			file.WriteString(fmt.Sprintf("- **From:** %s\n", item.Source.FromUser))
		}
		if link != "" {
			file.WriteString(fmt.Sprintf("- **Link:** %s\n", link))
		}
		if content != "" {
			file.WriteString(fmt.Sprintf("- **Content:** %s\n", content))
		}
		file.WriteString("\n")
		count++
	}

	fmt.Printf("Exported %d favorites to %s\n", count, outPath)
}
