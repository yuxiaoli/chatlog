package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"
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

type FavoriteSchema struct {
	FavLocalID int         `json:"FavLocalID"`
	URL        string      `json:"url"`
	PageTitle  string      `json:"pagetitle"`
	Content    string      `json:"content"`
	SearchKey  string      `json:"SearchKey"`
	Tags       []string    `json:"tags"`
	Source     FavSource   `json:"source"`
}

type FavSource struct {
	FromUsr string `json:"fromusr"`
	Link    string `json:"link"`
}

func main() {
	outDir := filepath.Join("temp", "results")
	duckDbPath := filepath.Join(outDir, "chatlog.duckdb")

	if _, err := os.Stat(duckDbPath); os.IsNotExist(err) {
		log.Fatalf("DuckDB database not found at %s", duckDbPath)
	}

	db, err := sql.Open("duckdb", duckDbPath)
	if err != nil {
		log.Fatalf("Failed to open DuckDB: %v", err)
	}
	defer db.Close()

	exportFileTransfer(db, filepath.Join(outDir, "file_transfer_messages.json"))
	exportFavoritesJSON(db, filepath.Join(outDir, "wechat_favorites.json"))
	exportFavoritesMD(db, filepath.Join(outDir, "wechat_favorites.md"))
}

func exportFileTransfer(db *sql.DB, outPath string) {
	rows, err := db.Query("SELECT MsgSvrID, CreateTime, IsSender, Type, SubType, StrContent, Title, URL FROM file_transfer_messages")
	if err != nil {
		log.Printf("Failed to query file_transfer_messages: %v", err)
		return
	}
	defer rows.Close()

	var messages []FileTransferMsg
	for rows.Next() {
		var m FileTransferMsg
		if err := rows.Scan(&m.MsgSvrID, &m.CreateTime, &m.IsSender, &m.Type, &m.SubType, &m.StrContent, &m.Title, &m.URL); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		messages = append(messages, m)
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("Create output file failed: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(messages); err != nil {
		log.Printf("Encode JSON failed: %v", err)
		return
	}

	fmt.Printf("Exported %d file transfer messages to %s\n", len(messages), outPath)
}

func exportFavoritesJSON(db *sql.DB, outPath string) {
	rows, err := db.Query("SELECT FavLocalID, URL, PageTitle, Content, SearchKey, Tags, SourceFromUsr, SourceLink FROM wechat_favorites ORDER BY UpdateTime DESC")
	if err != nil {
		log.Printf("Failed to query wechat_favorites: %v", err)
		return
	}
	defer rows.Close()

	var favorites []FavoriteSchema
	for rows.Next() {
		var f FavoriteSchema
		var tagsJSON string
		var tags []string
		
		if err := rows.Scan(&f.FavLocalID, &f.URL, &f.PageTitle, &f.Content, &f.SearchKey, &tagsJSON, &f.Source.FromUsr, &f.Source.Link); err != nil {
			log.Printf("Failed to scan favorite: %v", err)
			continue
		}
		
		if tagsJSON != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &tags)
		}
		f.Tags = tags

		favorites = append(favorites, f)
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("Create output file failed: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(favorites); err != nil {
		log.Printf("Encode JSON failed: %v", err)
		return
	}

	fmt.Printf("Exported %d favorites to %s\n", len(favorites), outPath)
}

func exportFavoritesMD(db *sql.DB, outPath string) {
	rows, err := db.Query("SELECT Type, UpdateTime, URL, PageTitle, Content, Tags, SourceFromUsr, SourceLink FROM wechat_favorites ORDER BY UpdateTime DESC")
	if err != nil {
		log.Printf("Failed to query wechat_favorites: %v", err)
		return
	}
	defer rows.Close()

	file, err := os.Create(outPath)
	if err != nil {
		log.Printf("Create output file failed: %v", err)
		return
	}
	defer file.Close()

	file.WriteString("# WeChat Favorites\n\n")

	count := 0
	for rows.Next() {
		var typ int
		var utime int64
		var url, pageTitle, content, tagsJSON, sourceFromUsr, sourceLink string

		if err := rows.Scan(&typ, &utime, &url, &pageTitle, &content, &tagsJSON, &sourceFromUsr, &sourceLink); err != nil {
			continue
		}

		t := time.Unix(utime, 0).Format("2006-01-02 15:04:05")

		title := ""
		if typ == 1 {
			title = "Text Favorite"
		} else if typ == 5 {
			title = pageTitle
		} else if typ == 2 {
			title = "Image Favorite"
		} else if typ == 4 {
			title = "Video Favorite"
		} else if typ == 8 {
			title = "File Favorite"
			if pageTitle != "" {
				title = pageTitle
			}
		} else if typ == 14 {
			title = pageTitle
		} else {
			title = fmt.Sprintf("Other Favorite (Type: %d)", typ)
			if pageTitle != "" {
				title = pageTitle
			}
		}

		if title == "" {
			title = "Untitled"
		}

		title = strings.TrimSpace(strings.ReplaceAll(title, "\n", " "))

		file.WriteString(fmt.Sprintf("## %s\n", title))
		file.WriteString(fmt.Sprintf("- **Date:** %s\n", t))
		
		var tags []string
		if tagsJSON != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &tags)
			if len(tags) > 0 {
				file.WriteString(fmt.Sprintf("- **Tags:** %s\n", strings.Join(tags, ", ")))
			}
		}
		
		if sourceFromUsr != "" {
			file.WriteString(fmt.Sprintf("- **From:** %s\n", sourceFromUsr))
		}
		link := url
		if link == "" {
			link = sourceLink
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
