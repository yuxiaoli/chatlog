package repository

import (
	"context"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/sjzar/chatlog/internal/model"
)

type contactDescriptionDataSource struct {
	contacts []*model.Contact
}

func (d *contactDescriptionDataSource) GetMessages(context.Context, time.Time, time.Time, string, string, string, int, int) ([]*model.Message, error) {
	return nil, nil
}

func (d *contactDescriptionDataSource) GetContacts(context.Context, string, int, int) ([]*model.Contact, error) {
	return d.contacts, nil
}

func (d *contactDescriptionDataSource) GetChatRooms(context.Context, string, int, int) ([]*model.ChatRoom, error) {
	return []*model.ChatRoom{}, nil
}

func (d *contactDescriptionDataSource) GetSessions(context.Context, string, int, int) ([]*model.Session, error) {
	return nil, nil
}

func (d *contactDescriptionDataSource) GetMedia(context.Context, string, string) (*model.Media, error) {
	return nil, nil
}

func (d *contactDescriptionDataSource) SetCallback(string, func(fsnotify.Event) error) error {
	return nil
}

func (d *contactDescriptionDataSource) Close() error {
	return nil
}

func TestGetContactsFindsDescriptionExactAndSubstring(t *testing.T) {
	want := &model.Contact{
		UserName:    "wxid_xiaorui",
		Alias:       "xiaoruizhao-",
		Remark:      "无理取闹的大瑞",
		NickName:    "晓晓",
		IsFriend:    true,
		Description: "生日：阴历1994年11月18日（冬月18）",
	}
	repo, err := New(&contactDescriptionDataSource{
		contacts: []*model.Contact{
			want,
			{UserName: "wxid_other", Description: "其他联系人说明"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	for _, keyword := range []string{want.Description, "阴历1994年", "冬月18"} {
		t.Run(keyword, func(t *testing.T) {
			single, err := repo.GetContact(context.Background(), keyword)
			if err != nil {
				t.Fatalf("GetContact(%q) error = %v", keyword, err)
			}
			if single != want {
				t.Fatalf("GetContact(%q) = %#v, want %#v", keyword, single, want)
			}

			got, err := repo.GetContacts(context.Background(), keyword, 0, 0)
			if err != nil {
				t.Fatalf("GetContacts(%q) error = %v", keyword, err)
			}
			if len(got) != 1 {
				t.Fatalf("GetContacts(%q) returned %d contacts, want 1", keyword, len(got))
			}
			if got[0] != want {
				t.Fatalf("GetContacts(%q)[0] = %#v, want %#v", keyword, got[0], want)
			}
		})
	}
}

func TestGetContactsDescriptionMatchIsNotDuplicated(t *testing.T) {
	want := &model.Contact{
		UserName:    "shared-key",
		Description: "shared-key appears in the description too",
	}
	repo, err := New(&contactDescriptionDataSource{contacts: []*model.Contact{want}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	got, err := repo.GetContacts(context.Background(), "shared-key", 0, 0)
	if err != nil {
		t.Fatalf("GetContacts() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetContacts() returned %d contacts, want 1", len(got))
	}
}

func TestGetContactsFindsTagsAndDeduplicatesMatches(t *testing.T) {
	want := &model.Contact{
		UserName: "wxid_tagged",
		Tags: []model.ContactTag{
			{ID: "3", Name: "Shanghai Family"},
			{ID: "3", Name: "Shanghai Family"},
			{ID: "404", Name: ""},
		},
	}
	repo, err := New(&contactDescriptionDataSource{contacts: []*model.Contact{want}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	for _, keyword := range []string{"3", "404", "Shanghai Family", "hai Fam"} {
		t.Run(keyword, func(t *testing.T) {
			got, err := repo.GetContacts(context.Background(), keyword, 0, 0)
			if err != nil {
				t.Fatalf("GetContacts(%q) error = %v", keyword, err)
			}
			if len(got) != 1 || got[0] != want {
				t.Fatalf("GetContacts(%q) = %#v, want one tagged contact", keyword, got)
			}

			single, err := repo.GetContact(context.Background(), keyword)
			if err != nil {
				t.Fatalf("GetContact(%q) error = %v", keyword, err)
			}
			if single != want {
				t.Fatalf("GetContact(%q) = %#v, want %#v", keyword, single, want)
			}
		})
	}
}

func TestGetContactsFindsExtraBufProfileTextAndDeduplicatesMatches(t *testing.T) {
	want := &model.Contact{
		UserName:       "shared-profile-key",
		Signature:      "shared-profile-key 碰巧遇到你",
		AddSceneEnum:   "FRIENDSHIP_SCENE_TYPE_QRCODE",
		AddSceneString: "Scan QR Code",
		Country:        "HK",
		Province:       "Kowloon Peninsula",
		City:           "Yau Tsim Mong",
	}
	repo, err := New(&contactDescriptionDataSource{contacts: []*model.Contact{want}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	for _, keyword := range []string{
		want.Signature, "碰巧遇到", want.AddSceneEnum, "TYPE_QR", want.AddSceneString, "QR Code", want.Country, want.Province, "Peninsula", want.City, "Tsim",
	} {
		t.Run(keyword, func(t *testing.T) {
			got, err := repo.GetContacts(context.Background(), keyword, 0, 0)
			if err != nil {
				t.Fatalf("GetContacts(%q) error = %v", keyword, err)
			}
			if len(got) != 1 || got[0] != want {
				t.Fatalf("GetContacts(%q) = %#v, want one profile match", keyword, got)
			}

			single, err := repo.GetContact(context.Background(), keyword)
			if err != nil {
				t.Fatalf("GetContact(%q) error = %v", keyword, err)
			}
			if single != want {
				t.Fatalf("GetContact(%q) = %#v, want %#v", keyword, single, want)
			}
		})
	}

	got, err := repo.GetContacts(context.Background(), "shared-profile-key", 0, 0)
	if err != nil {
		t.Fatalf("GetContacts(shared field) error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetContacts(shared field) returned %d contacts, want 1", len(got))
	}
}

func TestAddSceneSearchIndexesEachKeyOnce(t *testing.T) {
	contacts := []*model.Contact{
		{
			UserName:       "wxid_scene_one",
			AddSceneEnum:   "FRIENDSHIP_SCENE_TYPE_QRCODE",
			AddSceneString: "Scan QR Code",
		},
		{
			UserName:       "wxid_scene_two",
			AddSceneEnum:   "FRIENDSHIP_SCENE_TYPE_QRCODE",
			AddSceneString: "Scan QR Code",
		},
	}
	repo, err := New(&contactDescriptionDataSource{contacts: contacts})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	if len(repo.addSceneEnumList) != 1 || repo.addSceneEnumList[0] != "FRIENDSHIP_SCENE_TYPE_QRCODE" {
		t.Fatalf("addSceneEnumList = %#v, want one unique key", repo.addSceneEnumList)
	}
	if len(repo.addSceneStringList) != 1 || repo.addSceneStringList[0] != "Scan QR Code" {
		t.Fatalf("addSceneStringList = %#v, want one unique key", repo.addSceneStringList)
	}

	for _, keyword := range []string{"TYPE_QR", "QR Code"} {
		got, err := repo.GetContacts(context.Background(), keyword, 0, 0)
		if err != nil {
			t.Fatalf("GetContacts(%q) error = %v", keyword, err)
		}
		if len(got) != len(contacts) {
			t.Fatalf("GetContacts(%q) returned %d contacts, want %d", keyword, len(got), len(contacts))
		}
	}
}
