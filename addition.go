package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// netClient is a shared HTTP client with a timeout for external requests.
var netClient = &http.Client{
	Timeout: time.Second * 10,
}

// ROUND V1 AND V2

type ProductRound struct {
	ProductID string `json:"product_id"`
}

type ValidRound struct {
	Name       string `json:"name"`
	Url        string `json:"url"`
	Created    string `json:"created"`
	IsFinished bool   `json:"is_finished"`
}

// GetRound fetches and processes data from external sources.
// It now returns an error to be handled by the caller.
func GetRound(roundType string) ([]ValidRound, error) {
	roundTime := strconv.FormatInt(time.Now().Unix(), 10)

	products, err := GetAllProducts(roundTime)
	if err != nil {
		// Propagate the error instead of just logging
		return nil, fmt.Errorf("GetAllProducts failed: %w", err)
	}

	rounds, err := GetOnlyRound(roundTime)
	if err != nil {
		// Propagate the error
		return nil, fmt.Errorf("GetOnlyRound failed: %w", err)
	}

	// ReflectRound now also returns an error, which we propagate.
	validRounds, err := ReflectRound(products, rounds, roundType)
	if err != nil {
		return nil, fmt.Errorf("ReflectRound failed: %w", err)
	}

	return validRounds, nil
}

// GetAllProducts fetches product data from the remote URL.
func GetAllProducts(roundTime string) (map[string]map[string]any, error) {
	req, err := http.NewRequest("GET", productsUrl+"?"+roundTime, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")

	resp, err := netClient.Do(req) // Use client with timeout
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	respString := string(respBytes)
	respString = strings.TrimPrefix(respString, "var products=")
	respString = strings.TrimSuffix(respString, ";")

	var ps map[string]map[string]any
	if err := json.Unmarshal([]byte(respString), &ps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal products json: %w", err)
	}

	return ps, nil
}

// GetOnlyRound fetches round data from the remote URL.
func GetOnlyRound(roundTime string) ([]ProductRound, error) {
	req, err := http.NewRequest("GET", roundUrl+"?"+roundTime, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")

	resp, err := netClient.Do(req) // Use client with timeout
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	respString := string(respBytes)
	respString = strings.TrimPrefix(respString, "var classify_24=")
	respString = strings.TrimSuffix(respString, ";")

	var rs []ProductRound
	if err := json.Unmarshal([]byte(respString), &rs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal round json: %w", err)
	}

	return rs, nil
}

// ReflectRound correlates and filters the product and round data.
// It now uses safe type assertions to prevent panics.
func ReflectRound(products map[string]map[string]any, rounds []ProductRound, roundType string) ([]ValidRound, error) {
	var validRounds []ValidRound
	for _, round := range rounds {
		pr, productExists := products[round.ProductID]
		if !productExists {
			continue // Skip if product ID from round doesn't exist in products map
		}

		// Safe type assertion for jump_url
		jumpURL, ok := pr["jump_url"].(string)
		if !ok {
			log.Printf("Warning: 'jump_url' for product ID %s is not a string, skipping.", round.ProductID)
			continue
		}

		if strings.Contains(jumpURL, roundType) {
			// Safe type assertions for other fields
			productName, nameOk := pr["product_name"].(string)
			createAt, createOk := pr["create_at"].(string)

			if !nameOk || !createOk {
				log.Printf("Warning: Data for product ID %s has incorrect types, skipping.", round.ProductID)
				continue
			}

			validRounds = append(validRounds, ValidRound{
				Name:       productName,
				Url:        strings.ReplaceAll(jumpURL, "amp;", ""),
				Created:    createAt,
				IsFinished: false,
			})
		}
	}
	return validRounds, nil
}

// SHOP LOTTERY

type LotteryList struct {
	Code int `json:"code"`
	Data struct {
		Products []LotteryProduct `json:"products"`
	} `json:"data"`
	LoginStatus int `json:"login_status"`
}

type LotteryProduct struct {
	ID            int    `json:"id"`
	ProductName   string `json:"product_name"`
	ProductImg    string `json:"product_img"`
	Imm           string `json:"imm"`
	JumpType      string `json:"jump_type"`
	JumpURL       string `json:"jump_url"`
	ProductType   string `json:"product_type"`
	PriceState    string `json:"price_state"`
	OriginalPrice string `json:"original_price"`
	ProductPrice  string `json:"product_price"`
	SuperPrice    string `json:"super_price"`
	CustomPrice   string `json:"custom_price"`
	ExpectPrice   string `json:"expect_price"`
	PriceTextArr  []struct {
		Price string `json:"price"`
		Name  string `json:"name"`
	} `json:"price_text_arr"`
	PlatformState   string `json:"platform_state"`
	StockState      string `json:"stock_state"`
	Sort            string `json:"sort"`
	Stock           int    `json:"stock"`
	TagType         string `json:"tag_type"`
	WebProductState int    `json:"web_product_state"`
	Headcount       int    `json:"headcount"`
	PrizeText       string `json:"prize_text"`
	StartTimestamp  int    `json:"start_timestamp"`
	EndTimestamp    int    `json:"end_timestamp"`
	PrizeTimestamp  int    `json:"prize_timestamp"`
	IsOpenTask      int    `json:"is_open_task"`
	BtnText         string `json:"btn_text"`
}

var shopLotteryListUrl string = "https://shop.3839.com/index.php?c=Lottery&a=homeApi"

func GetLottery() (ll []LotteryProduct, err error) {
	payload := url.Values{}

	payload.Set("r", fmt.Sprintf("%.16f", rand.Float64()))
	payload.Set("page", "1")
	payload.Set("page_size", "100")
	payload.Set("client", "1")

	data := strings.NewReader(payload.Encode())
	req, _ := http.NewRequest("POST", shopLotteryListUrl, data)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Origin", "https://shop.3839.com")
	req.Header.Set("Referer", "https://shop.3839.com/?c=Lottery&a=home&imm=1")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := netClient.Do(req)
	if err != nil {
		fmt.Println("getLotteryListWithFilter do error -> ", err.Error())
		return
	}
	var reader io.Reader
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			fmt.Println("gzipReader error -> ", err.Error())
			return ll, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	} else {
		reader = resp.Body
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("ReadAll error -> ", err.Error())
		return
	}

	var tll LotteryList
	err = json.Unmarshal(body, &tll)
	for _, product := range tll.Data.Products {
		if product.PrizeText == "已结束" || strings.Contains(product.ProductName, "已结束") || strings.Contains(product.ProductName, "已开奖") {
			continue
		}
		ll = append(ll, product)
	}
	return
}
