package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var _ = redis.Nil // Acknowledge redis import is needed for rdb's type

// handleValidation 处理长期 Key 的验证、IP 绑定并签发 JWT
func handleValidation(c *gin.Context) {
	longTermKey := c.GetHeader("X-Token")
	if longTermKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Token header is required"})
		return
	}

	// 1. 检查长期 Key 的基本有效性和封禁状态
	keyData, err := rdb.HGetAll(ctx, longTermKey).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error on key check"})
		return
	}
	if len(keyData) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid X-Token"})
		return
	}

	if status, ok := keyData["status"]; ok && status == "banned" {
		log.Printf("Key '%s' 已被封禁，拒绝访问。", longTermKey)
		c.JSON(http.StatusForbidden, gin.H{"error": "This key has been banned due to security policy violations."})
		return
	}

	// 2. IP 及地区风控
	clientIP := c.ClientIP()
	geoInfo, err := getGeoInfoForIP(clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("IP geolocation failed: %v", err)})
		return
	}
	currentProvince := geoInfo.RegionName
	currentCity := geoInfo.City

	storedProvince := keyData["province"]
	storedCities := keyData["cities"]

	// --- 核心风控逻辑 ---
	if storedProvince == "" { // a. 首次使用，绑定地区
		fields := map[string]any{"province": currentProvince, "cities": currentCity}
		if err := rdb.HSet(ctx, longTermKey, fields).Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to bind location"})
			return
		}
		log.Printf("Key '%s' 首次使用，已绑定省份: %s, 城市: %s", longTermKey, currentProvince, currentCity)

	} else if storedProvince != currentProvince { // b. 省份不匹配，封禁
		log.Printf("安全警报: Key '%s' 尝试跨省使用。绑定省份: '%s', 当前省份: '%s'。执行封禁。", longTermKey, storedProvince, currentProvince)
		rdb.HSet(ctx, longTermKey, "status", "banned")
		c.JSON(http.StatusForbidden, gin.H{"error": "Security risk: Access from a different province is not allowed. This key has been banned."})
		return

	} else { // c. 省份匹配，检查城市
		var cityList []string
		if storedCities != "" {
			cityList = strings.Split(storedCities, ",")
		}

		isKnownCity := false
		for _, city := range cityList {
			if city == currentCity {
				isKnownCity = true
				break
			}
		}

		if !isKnownCity { // 发现新城市
			if len(cityList) < 2 { // c1. 城市数量未满2个，添加新城市
				log.Printf("Key '%s' 在新城市 '%s' 使用。当前城市列表: [%s]。允许访问。", longTermKey, currentCity, storedCities)
				newCityList := append(cityList, currentCity)
				newCities := strings.Join(newCityList, ",")
				if err := rdb.HSet(ctx, longTermKey, "cities", newCities).Err(); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update city list"})
					return
				}
			} else { // c2. 城市数量已满，封禁
				log.Printf("安全警报: Key '%s' 尝试在第三个城市 '%s' 使用。已绑定城市: [%s]。执行封禁。", longTermKey, currentCity, storedCities)
				rdb.HSet(ctx, longTermKey, "status", "banned")
				c.JSON(http.StatusForbidden, gin.H{"error": "Security risk: Access from more than 2 cities is not allowed. This key has been banned."})
				return
			}
		}
	}

	// 3. 生成 JWT (逻辑保持不变)
	claims := jwt.MapClaims{
		"sub": longTermKey,
		"exp": time.Now().Add(tokenLifetime).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// handleProfile 一个受保护的示例 API，返回加密后的用户信息
func handleProfile(c *gin.Context) {
	// 从中间件设置的 context 中获取长期 Key
	longTermKey, exists := c.Get("longTermKey")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not find user key in context"})
		return
	}

	// 1. 准备原始数据
	profileData := gin.H{
		"user":      longTermKey,
		"email":     "user@example.com",
		"createdAt": time.Now().Format(time.RFC3339),
	}
	jsonData, err := json.Marshal(profileData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize profile data"})
		return
	}

	// 2. 加密数据
	encryptionKey := []byte(longTermKey.(string))
	if len(encryptionKey) != 32 {
		key := make([]byte, 32)
		copy(key, encryptionKey)
		encryptionKey = key
	}

	encryptedPayload, err := encrypt(jsonData, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Encryption failed: %v", err)})
		return
	}

	// 3. 返回加密后的数据
	c.JSON(http.StatusOK, EncryptedResponse{Payload: encryptedPayload})
}

// handleString an example protected API that returns an encrypted string
func handleString(c *gin.Context) {
	longTermKey, _ := c.Get("longTermKey")

	// 1. Prepare raw data (a simple string)
	// Note: even a raw string is marshaled into a JSON string (e.g., "\"hello\"")
	stringData := "This is a test string from the server."
	jsonData, err := json.Marshal(stringData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize string data"})
		return
	}

	// 2. Encrypt data
	encryptionKey := []byte(longTermKey.(string))
	if len(encryptionKey) != 32 {
		key := make([]byte, 32)
		copy(key, encryptionKey)
		encryptionKey = key
	}

	encryptedPayload, err := encrypt(jsonData, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Encryption failed: %v", err)})
		return
	}

	// 3. Return encrypted data
	c.JSON(http.StatusOK, EncryptedResponse{Payload: encryptedPayload})
}

// handleArray an example protected API that returns an encrypted array of strings
func handleArray(c *gin.Context) {
	longTermKey, _ := c.Get("longTermKey")

	// 1. Prepare raw data (a slice of strings)
	arrayData := []string{"apple", "banana", "cherry"}
	jsonData, err := json.Marshal(arrayData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize array data"})
		return
	}

	// 2. Encrypt data
	encryptionKey := []byte(longTermKey.(string))
	if len(encryptionKey) != 32 {
		key := make([]byte, 32)
		copy(key, encryptionKey)
		encryptionKey = key
	}

	encryptedPayload, err := encrypt(jsonData, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Encryption failed: %v", err)})
		return
	}

	// 3. Return encrypted data
	c.JSON(http.StatusOK, EncryptedResponse{Payload: encryptedPayload})
}

// handleGateway is a generic endpoint for fetching UI components like menus.
// It uses an obfuscated request body to determine what to return.
func handleGateway(c *gin.Context) {
	longTermKey, _ := c.Get("longTermKey")

	var reqBody struct {
		Target string            `json:"target"`
		Param  string            `json:"p,omitempty"`      // Optional parameter
		Params map[string]string `json:"params,omitempty"` // New field for variable-length parameters
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var dataToEncrypt any

	// The "target" field determines what to fetch.
	// All target codes are intentionally obfuscated.
	switch reqBody.Target {
	// target "a1": Fetches the main application menu.
	case "a1":
		dataToEncrypt = []string{"转盘", "转盘v2", "玉米农场", "退出"}

	// target "b2": Fetches the action menu for a specific module.
	case "b2":
		// The "p" (param) field identifies the module.
		switch reqBody.Param {
		// p="d8a7f1" corresponds to the "转盘" (Turntable) module.
		case "d8a7f1":
			dataToEncrypt = []string{"获取并添加所有转盘信息", "添加单个转盘", "删除单个转盘", "领取所有转盘次数", "现在抽", "零点抽", "返回上一级"}
		// Add other sub-menus here as needed.
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown module parameter"})
			return
		}

	// target "c3": Fetches the remote configuration URLs for the client.
	case "c3":
		dataToEncrypt = map[string]string{
			"products":  productsUrl,
			"round":     roundUrl,
			"universal": universalUrl,
			"wanneng":   wannengUrl,
		}

	// target "e5": Fetches a secret key/value pair for client-side use.
	case "e5":
		dataToEncrypt = map[string]string{
			"key":   clientSecretKey,
			"value": clientSecretValue,
		}

	// target "g7": Processes a map of parameters and returns its sorted keys plus "secret".
	case "g7":
		if reqBody.Params == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'params' in request body for target 'g7'"})
			return
		}
		keys := make([]string, 0, len(reqBody.Params)+1)
		for k := range reqBody.Params {
			keys = append(keys, k)
		}
		keys = append(keys, "secret")
		sort.Strings(keys)
		dataToEncrypt = keys

	// target "f6": Fetches another secret string.
	case "f6":
		dataToEncrypt = anotherSecretString

	// target "d4": Fetches and processes external round data.
	case "d4":
		var roundType string
		// The "p" (param) field identifies the round type.
		switch reqBody.Param {
		// p="u1" corresponds to the "universal" type.
		case "u1":
			roundType = "universal"
		// p="w1" corresponds to the "wanneng" type.
		case "w1":
			roundType = "wanneng"
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown round parameter"})
			return
		}

		validRounds, err := GetRound(roundType)
		if err != nil {
			// Log the detailed error on the server, but return a generic error to the client.
			log.Printf("GetRound failed for type '%s': %v", roundType, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process round data"})
			return
		}
		dataToEncrypt = validRounds

	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "Unknown target"})
		return
	}

	// --- Encryption (same logic as other handlers) ---
	jsonData, err := json.Marshal(dataToEncrypt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize data"})
		return
	}

	encryptionKey := []byte(longTermKey.(string))
	encryptedPayload, err := encrypt(jsonData, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Encryption failed: %v", err)})
		return
	}

	c.JSON(http.StatusOK, EncryptedResponse{Payload: encryptedPayload})
}
