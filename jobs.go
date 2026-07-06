package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// 4399 游戏盒
type HDInfo struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	CUrl   string `json:"cli_url"`
	STime  string `json:"stime"`
	ETime  string `json:"etime"`
	Url    string `json:"url"`
}

type BoxActsResp struct {
	Result struct {
		Data     []HDInfo `json:"data"`
		StartKey string   `json:"startKey"`
		More     int      `json:"more"`
	} `json:"result"`
}

var HDIsLatest []HDInfo
var HDIs []HDInfo

// 偷懒，数据存内存
func BoxActivitiesAll() {
	log.Println("启动 更新4399游戏盒活动")
	startKey := ""
	more := 1

	for more != 0 {
		req, _ := http.NewRequest("GET", "https://mapi.yxhapi.com/android/box/other/v1.0/huodong-all.html", nil)
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0")
		query := req.URL.Query()
		query.Add("tag", "0")
		query.Add("startKey", startKey)
		query.Add("n", "20")
		query.Add("type", "activity")
		req.URL.RawQuery = query.Encode()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		rbs, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		var basResp BoxActsResp
		json.Unmarshal(rbs, &basResp)

		for _, v := range basResp.Result.Data {
			if strings.Contains(v.CUrl, "longTermSub") {
				HDIs = append(HDIs, v)
			}
		}

		startKey = basResp.Result.StartKey
		more = basResp.Result.More
		time.Sleep(1 * time.Second)
	}

	HDIsLatest = HDIs
	HDIs = []HDInfo{}
	log.Println("更新4399游戏盒活动 结束")
}

// 4399 游戏盒
