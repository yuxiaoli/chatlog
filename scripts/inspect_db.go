package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "temp/results/Favorite_decrypted.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := `
		SELECT 
			f.FavLocalID, 
			f.SearchKey, 
			GROUP_CONCAT(t.Tag, '|||') AS tags
		FROM FavItems f
		LEFT JOIN FavTags t ON f.FavLocalID = t.FavLocalID
		WHERE t.Tag IS NOT NULL
		GROUP BY f.FavLocalID
		LIMIT 5;
	`
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var sk string
		var tags string
		rows.Scan(&id, &sk, &tags)
		fmt.Printf("ID: %d, SearchKey: %s, Tags: %s\n", id, sk, tags)
	}
}
