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
		Link     string `xml:"link"`
	} `xml:"source"`
}

// FavoriteSchema matches the data/favorites.schema.json
type FavoriteSchema struct {
	FavLocalID    int         `json:"FavLocalID"`
	Type          int         `json:"Type"`
	UpdateTime    int64       `json:"UpdateTime"`
	URL           string      `json:"URL"`
	PageTitle     string      `json:"PageTitle"`
	Content       string      `json:"Content"`
	SearchKey     string      `json:"SearchKey"`
	Tags          []string    `json:"Tags"`
	SourceFromUsr string      `json:"SourceFromUsr"`
	SourceLink    string      `json:"SourceLink"`
	XmlBuf        string      `json:"XmlBuf"`
}

type FavSource struct {
	FromUsr string `json:"fromusr"`
	Link    string `json:"link"`
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

	exportJSON(decryptedDbPath, filepath.Join(outDir, "favorites.json"))
}

func exportJSON(dbPath, outPath string) {
	sqliteDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("SQLite Open Error: %v", err)
		return
	}
	defer sqliteDB.Close()

	query := `
		SELECT 
			f.FavLocalID, 
			f.Type,
			f.UpdateTime,
			f.SearchKey,
			f.XmlBuf,
			GROUP_CONCAT(t.Tag, '|||') AS tags
		FROM FavItems f
		LEFT JOIN FavTags t ON f.FavLocalID = t.FavLocalID
		GROUP BY f.FavLocalID
		ORDER BY f.UpdateTime DESC
	`

	rows, err := sqliteDB.Query(query)
	if err != nil {
		log.Printf("SQLite Query Error: %v", err)
		return
	}
	defer rows.Close()

	var allFavorites []map[string]interface{}

	for rows.Next() {
		var id int
		var typ int
		var utime int64
		var searchKey sql.NullString
		var xmlBuf sql.NullString
		var tagsStr sql.NullString

		if err := rows.Scan(&id, &typ, &utime, &searchKey, &xmlBuf, &tagsStr); err != nil {
			log.Printf("SQLite Scan Error: %v", err)
			return
		}

		var item FavItemXML
		_ = xml.Unmarshal([]byte(xmlBuf.String), &item)

		url := item.WebURLItem.Link
		if url == "" {
			url = item.Source.Link
		}

		pageTitle := item.WebURLItem.PageTitle
		if pageTitle == "" {
			pageTitle = item.Title
		}
		if pageTitle == "" && len(item.DataList.DataItems) > 0 {
			pageTitle = item.DataList.DataItems[0].DataTitle
		}

		content := item.Desc
		if content == "" {
			content = ""
		}

		tags := []string{}
		if tagsStr.Valid && tagsStr.String != "" {
			tags = strings.Split(tagsStr.String, "|||")
		}

		fav := map[string]interface{}{
			"FavLocalID":    id,
			"Type":          typ,
			"UpdateTime":    utime,
			"URL":           url,
			"PageTitle":     pageTitle,
			"Content":       content,
			"SearchKey":     searchKey.String,
			"Tags":          tags,
			"SourceFromUsr": item.Source.FromUser,
			"SourceLink":    item.Source.Link,
			"XmlBuf":        xmlBuf.String,
		}

		allFavorites = append(allFavorites, fav)
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("Create JSON file Error: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(allFavorites); err != nil {
		log.Printf("JSON Encode Error: %v", err)
		return
	}

	fmt.Printf("Successfully exported %d favorites to JSON at %s\n", len(allFavorites), outPath)
}
