package model

import "strings"

type ContactTag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Contact struct {
	UserName       string       `json:"userName"`
	Alias          string       `json:"alias"`
	Remark         string       `json:"remark"`
	NickName       string       `json:"nickName"`
	IsFriend       bool         `json:"isFriend"`
	Description    string       `json:"description"`
	Tags           []ContactTag `json:"tags"`
	Signature      string       `json:"signature"`
	AddScene       *int32       `json:"addScene"`
	AddSceneEnum   string       `json:"addSceneEnum"`
	AddSceneString string       `json:"addSceneString"`
	Country        string       `json:"country"`
	Province       string       `json:"province"`
	City           string       `json:"city"`
}

// CREATE TABLE Contact(
// UserName TEXT PRIMARY KEY ,
// Alias TEXT,
// EncryptUserName TEXT,
// DelFlag INTEGER DEFAULT 0,
// Type INTEGER DEFAULT 0,
// VerifyFlag INTEGER DEFAULT 0,
// Reserved1 INTEGER DEFAULT 0,
// Reserved2 INTEGER DEFAULT 0,
// Reserved3 TEXT,
// Reserved4 TEXT,
// Remark TEXT,
// NickName TEXT,
// LabelIDList TEXT,
// DomainList TEXT,
// ChatRoomType int,
// PYInitial TEXT,
// QuanPin TEXT,
// RemarkPYInitial TEXT,
// RemarkQuanPin TEXT,
// BigHeadImgUrl TEXT,
// SmallHeadImgUrl TEXT,
// HeadImgMd5 TEXT,
// ChatRoomNotify INTEGER DEFAULT 0,
// Reserved5 INTEGER DEFAULT 0,
// Reserved6 TEXT,
// Reserved7 TEXT,
// ExtraBuf BLOB,
// Reserved8 INTEGER DEFAULT 0,
// Reserved9 INTEGER DEFAULT 0,
// Reserved10 TEXT,
// Reserved11 TEXT
// )
type ContactV3 struct {
	UserName    string `json:"UserName"`
	Alias       string `json:"Alias"`
	Remark      string `json:"Remark"`
	NickName    string `json:"NickName"`
	Reserved1   int    `json:"Reserved1"` // 1 自己好友或自己加入的群聊; 0 群聊成员(非好友)
	Reserved6   string `json:"Reserved6"`
	LabelIDList string `json:"LabelIDList"`
	ExtraBuf    []byte `json:"-"`
}

func (c *ContactV3) Wrap() *Contact {
	return c.WrapWithLabelNames(nil)
}

// WrapWithLabelNames maps the comma-separated LabelIDList to resolved tags.
// IDs without a ContactLabel definition are retained with an empty name.
func (c *ContactV3) WrapWithLabelNames(labelNames map[string]string) *Contact {
	profile, ok := parseContactExtraBuf(c.ExtraBuf)
	if !ok {
		profile = contactExtraProfile{}
	}
	addSceneEnum, addSceneString := contactAddSceneDetails(profile.AddScene)
	return &Contact{
		UserName:       c.UserName,
		Alias:          c.Alias,
		Remark:         c.Remark,
		NickName:       c.NickName,
		IsFriend:       c.Reserved1 == 1,
		Description:    c.Reserved6,
		Tags:           contactTags(c.LabelIDList, labelNames),
		Signature:      profile.Signature,
		AddScene:       profile.AddScene,
		AddSceneEnum:   addSceneEnum,
		AddSceneString: addSceneString,
		Country:        profile.Country,
		Province:       profile.Province,
		City:           profile.City,
	}
}

func contactTags(labelIDList string, labelNames map[string]string) []ContactTag {
	tags := make([]ContactTag, 0)
	for _, value := range strings.Split(labelIDList, ",") {
		id := strings.TrimSpace(value)
		if id == "" {
			continue
		}
		tags = append(tags, ContactTag{
			ID:   id,
			Name: labelNames[id],
		})
	}
	return tags
}

func (c *Contact) DisplayName() string {
	switch {
	case c.Remark != "":
		return c.Remark
	case c.NickName != "":
		return c.NickName
	}
	return ""
}
