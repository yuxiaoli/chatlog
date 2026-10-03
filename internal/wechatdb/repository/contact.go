package repository

import (
	"context"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
)

// initContactCache 初始化联系人缓存
func (r *Repository) initContactCache(ctx context.Context) error {

	contactMap := make(map[string]*model.Contact)
	aliasMap := make(map[string][]*model.Contact)
	remarkMap := make(map[string][]*model.Contact)
	nickNameMap := make(map[string][]*model.Contact)
	descriptionMap := make(map[string][]*model.Contact)
	signatureMap := make(map[string][]*model.Contact)
	addSceneEnumMap := make(map[string][]*model.Contact)
	addSceneStringMap := make(map[string][]*model.Contact)
	countryMap := make(map[string][]*model.Contact)
	provinceMap := make(map[string][]*model.Contact)
	cityMap := make(map[string][]*model.Contact)
	tagIDMap := make(map[string][]*model.Contact)
	tagNameMap := make(map[string][]*model.Contact)
	chatRoomUserMap := make(map[string]*model.Contact)
	chatRoomInContactMap := make(map[string]*model.Contact)
	contactList := make([]string, 0)
	aliasList := make([]string, 0)
	remarkList := make([]string, 0)
	nickNameList := make([]string, 0)
	descriptionList := make([]string, 0)
	signatureList := make([]string, 0)
	addSceneEnumList := make([]string, 0)
	addSceneStringList := make([]string, 0)
	countryList := make([]string, 0)
	provinceList := make([]string, 0)
	cityList := make([]string, 0)
	tagNameList := make([]string, 0)

	// 加载所有联系人到缓存
	// 暂时忽略获取不到联系人的错误
	contacts, err := r.ds.GetContacts(ctx, "", 0, 0)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load contacts")
	}

	for _, contact := range contacts {
		contactMap[contact.UserName] = contact
		contactList = append(contactList, contact.UserName)

		// 建立快速查找索引
		if contact.Alias != "" {
			alias, ok := aliasMap[contact.Alias]
			if !ok {
				alias = make([]*model.Contact, 0)
			}
			alias = append(alias, contact)
			aliasMap[contact.Alias] = alias
			aliasList = append(aliasList, contact.Alias)
		}
		if contact.Remark != "" {
			remark, ok := remarkMap[contact.Remark]
			if !ok {
				remark = make([]*model.Contact, 0)
			}
			remark = append(remark, contact)
			remarkMap[contact.Remark] = remark
			remarkList = append(remarkList, contact.Remark)
		}
		if contact.NickName != "" {
			nickName, ok := nickNameMap[contact.NickName]
			if !ok {
				nickName = make([]*model.Contact, 0)
			}
			nickName = append(nickName, contact)
			nickNameMap[contact.NickName] = nickName
			nickNameList = append(nickNameList, contact.NickName)
		}
		if contact.Description != "" {
			descriptions, ok := descriptionMap[contact.Description]
			if !ok {
				descriptions = make([]*model.Contact, 0)
			}
			descriptions = append(descriptions, contact)
			descriptionMap[contact.Description] = descriptions
			descriptionList = append(descriptionList, contact.Description)
		}
		if contact.Signature != "" {
			signatureMap[contact.Signature] = append(signatureMap[contact.Signature], contact)
			signatureList = append(signatureList, contact.Signature)
		}
		if contact.AddSceneEnum != "" {
			if _, exists := addSceneEnumMap[contact.AddSceneEnum]; !exists {
				addSceneEnumList = append(addSceneEnumList, contact.AddSceneEnum)
			}
			addSceneEnumMap[contact.AddSceneEnum] = append(addSceneEnumMap[contact.AddSceneEnum], contact)
		}
		if contact.AddSceneString != "" {
			if _, exists := addSceneStringMap[contact.AddSceneString]; !exists {
				addSceneStringList = append(addSceneStringList, contact.AddSceneString)
			}
			addSceneStringMap[contact.AddSceneString] = append(addSceneStringMap[contact.AddSceneString], contact)
		}
		if contact.Country != "" {
			countryMap[contact.Country] = append(countryMap[contact.Country], contact)
			countryList = append(countryList, contact.Country)
		}
		if contact.Province != "" {
			provinceMap[contact.Province] = append(provinceMap[contact.Province], contact)
			provinceList = append(provinceList, contact.Province)
		}
		if contact.City != "" {
			cityMap[contact.City] = append(cityMap[contact.City], contact)
			cityList = append(cityList, contact.City)
		}
		for _, tag := range contact.Tags {
			if tag.ID != "" {
				tagIDMap[tag.ID] = append(tagIDMap[tag.ID], contact)
			}
			if tag.Name != "" {
				tagNameMap[tag.Name] = append(tagNameMap[tag.Name], contact)
				tagNameList = append(tagNameList, tag.Name)
			}
		}

		// 如果是群聊成员（非好友），添加到群聊成员索引
		if !contact.IsFriend {
			chatRoomUserMap[contact.UserName] = contact
		}

		if strings.HasSuffix(contact.UserName, "@chatroom") {
			chatRoomInContactMap[contact.UserName] = contact
		}
	}

	sort.Strings(contactList)
	sort.Strings(aliasList)
	sort.Strings(remarkList)
	sort.Strings(nickNameList)
	sort.Strings(descriptionList)
	sort.Strings(signatureList)
	sort.Strings(addSceneEnumList)
	sort.Strings(addSceneStringList)
	sort.Strings(countryList)
	sort.Strings(provinceList)
	sort.Strings(cityList)
	sort.Strings(tagNameList)

	r.contactCache = contactMap
	r.aliasToContact = aliasMap
	r.remarkToContact = remarkMap
	r.nickNameToContact = nickNameMap
	r.descriptionToContact = descriptionMap
	r.signatureToContact = signatureMap
	r.addSceneEnumToContact = addSceneEnumMap
	r.addSceneStringToContact = addSceneStringMap
	r.countryToContact = countryMap
	r.provinceToContact = provinceMap
	r.cityToContact = cityMap
	r.tagIDToContact = tagIDMap
	r.tagNameToContact = tagNameMap
	r.chatRoomUserToInfo = chatRoomUserMap
	r.chatRoomInContact = chatRoomInContactMap
	r.contactList = contactList
	r.aliasList = aliasList
	r.remarkList = remarkList
	r.nickNameList = nickNameList
	r.descriptionList = descriptionList
	r.signatureList = signatureList
	r.addSceneEnumList = addSceneEnumList
	r.addSceneStringList = addSceneStringList
	r.countryList = countryList
	r.provinceList = provinceList
	r.cityList = cityList
	r.tagNameList = tagNameList
	return nil
}

func (r *Repository) GetContact(ctx context.Context, key string) (*model.Contact, error) {
	// 先尝试从缓存中获取
	contact := r.findContact(key)
	if contact == nil {
		return nil, errors.ContactNotFound(key)
	}
	return contact, nil
}

func (r *Repository) GetContacts(ctx context.Context, key string, limit, offset int) ([]*model.Contact, error) {
	ret := make([]*model.Contact, 0)
	if key != "" {
		ret = r.findContacts(key)
		if len(ret) == 0 {
			return []*model.Contact{}, nil
		}
		if limit > 0 {
			end := offset + limit
			if end > len(ret) {
				end = len(ret)
			}
			if offset >= len(ret) {
				return []*model.Contact{}, nil
			}
			return ret[offset:end], nil
		}
	} else {
		list := r.contactList
		if limit > 0 {
			end := offset + limit
			if end > len(list) {
				end = len(list)
			}
			if offset >= len(list) {
				return []*model.Contact{}, nil
			}
			list = list[offset:end]
		}
		for _, name := range list {
			ret = append(ret, r.contactCache[name])
		}
	}
	return ret, nil
}

func (r *Repository) findContact(key string) *model.Contact {
	if contact, ok := r.contactCache[key]; ok {
		return contact
	}
	if contact, ok := r.aliasToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.remarkToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.nickNameToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.descriptionToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.signatureToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.addSceneEnumToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.addSceneStringToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.countryToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.provinceToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.cityToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.tagIDToContact[key]; ok {
		return contact[0]
	}
	if contact, ok := r.tagNameToContact[key]; ok {
		return contact[0]
	}

	// Contain
	for _, alias := range r.aliasList {
		if strings.Contains(alias, key) {
			return r.aliasToContact[alias][0]
		}
	}
	for _, remark := range r.remarkList {
		if strings.Contains(remark, key) {
			return r.remarkToContact[remark][0]
		}
	}
	for _, nickName := range r.nickNameList {
		if strings.Contains(nickName, key) {
			return r.nickNameToContact[nickName][0]
		}
	}
	for _, description := range r.descriptionList {
		if strings.Contains(description, key) {
			return r.descriptionToContact[description][0]
		}
	}
	for _, signature := range r.signatureList {
		if strings.Contains(signature, key) {
			return r.signatureToContact[signature][0]
		}
	}
	for _, addSceneEnum := range r.addSceneEnumList {
		if strings.Contains(addSceneEnum, key) {
			return r.addSceneEnumToContact[addSceneEnum][0]
		}
	}
	for _, addSceneString := range r.addSceneStringList {
		if strings.Contains(addSceneString, key) {
			return r.addSceneStringToContact[addSceneString][0]
		}
	}
	for _, country := range r.countryList {
		if strings.Contains(country, key) {
			return r.countryToContact[country][0]
		}
	}
	for _, province := range r.provinceList {
		if strings.Contains(province, key) {
			return r.provinceToContact[province][0]
		}
	}
	for _, city := range r.cityList {
		if strings.Contains(city, key) {
			return r.cityToContact[city][0]
		}
	}
	for _, tagName := range r.tagNameList {
		if strings.Contains(tagName, key) {
			return r.tagNameToContact[tagName][0]
		}
	}
	return nil
}

func (r *Repository) findContacts(key string) []*model.Contact {
	ret := make([]*model.Contact, 0)
	distinct := make(map[string]bool)
	if contact, ok := r.contactCache[key]; ok {
		ret = append(ret, contact)
		distinct[contact.UserName] = true
	}
	if contacts, ok := r.aliasToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.remarkToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.nickNameToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.descriptionToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.signatureToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.addSceneEnumToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.addSceneStringToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.countryToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.provinceToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.cityToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.tagIDToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	if contacts, ok := r.tagNameToContact[key]; ok {
		for _, contact := range contacts {
			if !distinct[contact.UserName] {
				ret = append(ret, contact)
				distinct[contact.UserName] = true
			}
		}
	}
	// Contain
	for _, alias := range r.aliasList {
		if strings.Contains(alias, key) {
			for _, contact := range r.aliasToContact[alias] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, remark := range r.remarkList {
		if strings.Contains(remark, key) {
			for _, contact := range r.remarkToContact[remark] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, nickName := range r.nickNameList {
		if strings.Contains(nickName, key) {
			for _, contact := range r.nickNameToContact[nickName] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, description := range r.descriptionList {
		if strings.Contains(description, key) {
			for _, contact := range r.descriptionToContact[description] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, signature := range r.signatureList {
		if strings.Contains(signature, key) {
			for _, contact := range r.signatureToContact[signature] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, addSceneEnum := range r.addSceneEnumList {
		if strings.Contains(addSceneEnum, key) {
			for _, contact := range r.addSceneEnumToContact[addSceneEnum] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, addSceneString := range r.addSceneStringList {
		if strings.Contains(addSceneString, key) {
			for _, contact := range r.addSceneStringToContact[addSceneString] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, country := range r.countryList {
		if strings.Contains(country, key) {
			for _, contact := range r.countryToContact[country] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, province := range r.provinceList {
		if strings.Contains(province, key) {
			for _, contact := range r.provinceToContact[province] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, city := range r.cityList {
		if strings.Contains(city, key) {
			for _, contact := range r.cityToContact[city] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}
	for _, tagName := range r.tagNameList {
		if strings.Contains(tagName, key) {
			for _, contact := range r.tagNameToContact[tagName] {
				if !distinct[contact.UserName] {
					ret = append(ret, contact)
					distinct[contact.UserName] = true
				}
			}
		}
	}

	return ret
}

// getFullContact 获取联系人信息，包括群聊成员
func (r *Repository) getFullContact(userName string) *model.Contact {
	// 先查找联系人缓存
	if contact, ok := r.contactCache[userName]; ok {
		return contact
	}

	// 再查找群聊成员缓存
	contact, ok := r.chatRoomUserToInfo[userName]

	if ok {
		return contact
	}

	return nil
}
