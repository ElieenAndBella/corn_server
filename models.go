package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// GeoInfo 用于解析 IP 定位服务返回的 JSON
type GeoInfo struct {
	Status     string `json:"status"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"` // 省
	City       string `json:"city"`       // 市
	Query      string `json:"query"`
	Message    string `json:"message"`
}

// EncryptedResponse API 返回的加密数据结构
type EncryptedResponse struct {
	Payload string `json:"payload"`
}

// Item 用于描述 Awards 数组中的项目
type Item struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Amount int    `json:"amount"`
}

// ActivityResp 是客户端提交的爬取结果的数据结构
type ActivityResp struct {
	ActivityID  int      `json:"activity_id"`
	ArticleID   int64    `json:"article_id"`
	Awards      []Item   `json:"awards"`
	Conditions  []string `json:"conditions"`
	Title       string   `json:"title"`
	LinkTitle   string   `json:"link_title"`
	GameName    string   `json:"game_name"`
	AuthorName  string   `json:"author_name"`
	Cover       string   `json:"cover"`
	DrawTime    string   `json:"draw_time"`
	PublishTime string   `json:"publish_time"`
}

// Activity 用于从数据库中读取的活动数据
type Activity struct {
	ActivityID  int       `json:"activity_id"`
	ArticleID   string    `json:"article_id"`
	Awards      []Item    `json:"awards"`
	Conditions  []string  `json:"conditions"`
	Title       string    `json:"title"`
	LinkTitle   string    `json:"link_title"`
	GameName    string    `json:"game_name"`
	AuthorName  string    `json:"author_name"`
	Cover       string    `json:"cover"`
	DrawTime    time.Time `json:"draw_time"`
	PublishTime time.Time `json:"publish_time"`
}

// ApkInfo 用于接收要打包的 APK 数据
type ApkInfo struct {
	AppName       string `json:"appName" form:"appName" binding:"required"`
	ApplicationId string `json:"applicationId" form:"applicationId" binding:"required"`
	VersionCode   string `json:"versionCode" form:"versionCode" binding:"required"`
	VersionName   string `json:"versionName" form:"versionName" binding:"required"`
}

type SearchRequest struct {
	Keyword   string   `form:"keyword" binding:"required"`
	Platforms []string `form:"platforms" binding:"required,min=1"`
}

type CacheRequest struct {
	Keyword string                     `form:"keyword" json:"keyword" binding:"required"`
	Data    map[string][]GameBasicInfo `json:"data" binding:"required"`
}

type GameBasicInfo struct {
	GameID      string
	Pic         string
	Name        string
	Identifier  string
	Size        string
	VersionName string
	VersionCode string
	Score       string
	Platform    string
}

// woo 49 游戏盒 yxhGameSubscribe

type Amount string

func (a *Amount) UnmarshalJSON(data []byte) error {
	// 如果是字符串
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = Amount(s)
		return nil
	}

	// 如果是数字
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}

	*a = Amount(num.String())
	return nil
}

type DownSetting struct {
	BannerRecommend string `json:"bannerRecommend"`
	Prize           []struct {
		Amount Amount `json:"amount"`
		Title  string `json:"title"`
	} `json:"prize"`
	Name string `json:"name"`
}

type Result struct {
	CarouselList []struct {
		Message string `json:"message"`
		Nick    string `json:"nick"`
	} `json:"carouselList"`

	DownSetting DownSetting `json:"downSetting"`
}

type SubscribeInfo struct {
	Code   int    `json:"code"`
	Result Result `json:"result"`
}

func (r *Result) UnmarshalJSON(data []byte) error {
	type Raw struct {
		CarouselList []struct {
			Message string `json:"message"`
			Nick    string `json:"nick"`
		} `json:"carouselList"`

		DownSetting json.RawMessage `json:"downSetting"`
		Setting     json.RawMessage `json:"setting"`
	}

	var raw Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r.CarouselList = raw.CarouselList

	// 统一处理函数
	parse := func(b json.RawMessage) (*DownSetting, error) {
		if len(b) == 0 {
			return nil, nil
		}

		var tmp any
		if err := json.Unmarshal(b, &tmp); err != nil {
			fmt.Println("raw 解析失败:", err)
			return nil, err
		}

		switch tmp.(type) {
		case []any:
			return nil, nil

		case map[string]any:
			var ds DownSetting
			if err := json.Unmarshal(b, &ds); err != nil {
				fmt.Println("DownSetting 解析失败:", err)
				return nil, err
			}
			return &ds, nil
		}

		return nil, nil
	}

	// 优先 downSetting
	if ds, _ := parse(raw.DownSetting); ds != nil {
		r.DownSetting = *ds
		return nil
	}

	// fallback 到 setting
	if ds, _ := parse(raw.Setting); ds != nil {
		r.DownSetting = *ds
	}

	return nil
}
