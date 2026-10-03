package http

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"

	"github.com/sjzar/chatlog/internal/model"
)

var contactCSVHeader = []string{
	"UserName", "Alias", "Remark", "NickName", "Description", "Tags",
	"Signature", "AddScene", "AddSceneEnum", "AddSceneString", "Country", "Province", "City",
}

func writeContactsCSV(writer io.Writer, contacts []*model.Contact) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(contactCSVHeader); err != nil {
		return err
	}

	for _, contact := range contacts {
		tags := contact.Tags
		if tags == nil {
			tags = make([]model.ContactTag, 0)
		}
		encodedTags, err := json.Marshal(tags)
		if err != nil {
			return err
		}
		addScene := ""
		if contact.AddScene != nil {
			addScene = strconv.FormatInt(int64(*contact.AddScene), 10)
		}
		if err := csvWriter.Write([]string{
			contact.UserName,
			contact.Alias,
			contact.Remark,
			contact.NickName,
			contact.Description,
			string(encodedTags),
			contact.Signature,
			addScene,
			contact.AddSceneEnum,
			contact.AddSceneString,
			contact.Country,
			contact.Province,
			contact.City,
		}); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}
