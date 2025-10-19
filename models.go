package main

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
