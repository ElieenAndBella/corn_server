package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// handleValidation 处理长期 Key 的验证、IP 绑定并签发 JWT
func handleValidation(c *gin.Context) {
	longTermKey := c.GetHeader("X-Token")
	if longTermKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Token header is required"})
		return
	}

	// 1. 检查长期 Key 是否存在于 Redis
	storedLocation, err := rdb.HGet(ctx, longTermKey, "location").Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid X-Token"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// 2. IP 及地区风控
	clientIP := c.ClientIP()
	geoInfo, err := getGeoInfoForIP(clientIP)
	if err != nil {
		// 如果 IP 定位失败，可以选择是拒绝还是放行，这里我们选择拒绝
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("IP geolocation failed: %v", err)})
		return
	}
	currentLocation := fmt.Sprintf("%s-%s", geoInfo.RegionName, geoInfo.City)

	if storedLocation == "" { // 首次使用，绑定地区
		err := rdb.HSet(ctx, longTermKey, "location", currentLocation).Err()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to bind location"})
			return
		}
		log.Printf("Key '%s' 首次使用，已绑定地区: %s", longTermKey, currentLocation)
	} else if storedLocation != currentLocation { // 后续使用，检查地区是否匹配
		log.Printf("Key '%s' 存在安全风险，绑定地区: %s, 当前地区: %s", longTermKey, storedLocation, currentLocation)
		c.JSON(http.StatusForbidden, gin.H{"error": "Security risk: Access from an unusual location."})
		return
	}

	// 3. 生成 JWT
	claims := jwt.MapClaims{
		"sub": longTermKey, // subject, 我们将长期 key 作为主题
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
	// 我们使用长期 Key 本身作为加密密钥。注意：密钥长度需要满足 AES 的要求（16, 24, or 32 bytes）
	// 为了简单起见，我们假设 Key 的长度是合格的，或者通过哈希函数（如 SHA-256）处理成 32 字节
	encryptionKey := []byte(longTermKey.(string))
	if len(encryptionKey) != 32 {
		// 在真实应用中，你需要一个健壮的密钥派生函数
		// 这里我们简单地拒绝不符合长度的 key
		log.Printf("警告: 用于加密的 Key 长度不为 32 字节: %d", len(encryptionKey))
		// c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid key length for encryption"})
		// return
		// 为了演示，我们填充或截断它
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
