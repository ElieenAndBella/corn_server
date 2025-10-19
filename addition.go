package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// netClient is a shared HTTP client with a timeout for external requests.
var netClient = &http.Client{
	Timeout: time.Second * 10,
}

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