package model

import "fmt"

type contactAddSceneDetail struct {
	Enum   string
	String string
}

// contactAddSceneDetails returns stable, export-safe metadata for a raw
// Windows v3 add-scene code. The raw code remains authoritative on Contact.
// Unknown non-null values are described explicitly so new WeChat codes are
// never silently discarded or mistaken for an absent value.
func contactAddSceneDetails(addScene *int32) (string, string) {
	if addScene == nil {
		return "", ""
	}
	if detail, ok := contactAddSceneDetailsByCode[*addScene]; ok {
		return detail.Enum, detail.String
	}
	return fmt.Sprintf("FRIENDSHIP_SCENE_TYPE_UNKNOWN_%d", *addScene), fmt.Sprintf("Unknown (%d)", *addScene)
}

// The identifiers mirror Wechaty's legacy FriendshipSceneType protobuf enum:
// https://github.com/wechaty/grpc/blob/main/proto/wechaty/puppet/friendship.proto
// The readable strings are a stable exporter policy, not official WeChat UI
// labels, and therefore avoid inferring details absent from the source enum.
var contactAddSceneDetailsByCode = map[int32]contactAddSceneDetail{
	0:  {Enum: "FRIENDSHIP_SCENE_TYPE_UNSPECIFIED", String: "Unspecified"},
	1:  {Enum: "FRIENDSHIP_SCENE_TYPE_QQ", String: "QQ"},
	2:  {Enum: "FRIENDSHIP_SCENE_TYPE_EMAIL", String: "Email"},
	3:  {Enum: "FRIENDSHIP_SCENE_TYPE_WEIXIN", String: "WeChat ID"},
	12: {Enum: "FRIENDSHIP_SCENE_TYPE_QQTBD", String: "QQ (TBD)"},
	14: {Enum: "FRIENDSHIP_SCENE_TYPE_ROOM", String: "Group Chat"},
	15: {Enum: "FRIENDSHIP_SCENE_TYPE_PHONE", String: "Phone Contacts"},
	17: {Enum: "FRIENDSHIP_SCENE_TYPE_CARD", String: "Contact Card"},
	18: {Enum: "FRIENDSHIP_SCENE_TYPE_LOCATION", String: "Location"},
	25: {Enum: "FRIENDSHIP_SCENE_TYPE_BOTTLE", String: "Drift Bottle"},
	29: {Enum: "FRIENDSHIP_SCENE_TYPE_SHAKING", String: "Shake"},
	30: {Enum: "FRIENDSHIP_SCENE_TYPE_QRCODE", String: "Scan QR Code"},
}
