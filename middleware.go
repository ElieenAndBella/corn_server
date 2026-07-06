package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// authMiddleware 验证 JWT 的中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			return
		}

		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecretKey), nil
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid token: %v", err)})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// 将长期 Key 存入 context，以便后续 handler 使用
			c.Set("longTermKey", claims["sub"])
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		}
	}
}

// appIntegrityMiddleware 校验客户端请求的签名，防止第三方客户端调用
func appIntegrityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		timestampStr := c.GetHeader("X-Timestamp")
		clientSignature := c.GetHeader("X-Signature")

		if timestampStr == "" || clientSignature == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Missing required integrity headers"})
			return
		}

		// 1. 校验时间戳 (允许10秒的误差范围)
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid timestamp format"})
			return
		}

		if time.Now().Unix()-timestamp > 5 || timestamp-time.Now().Unix() > 5 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Timestamp is out of date"})
			return
		}

		// 2. 在服务器端重新计算签名
		path := c.Request.URL.Path
		payload := fmt.Sprintf("%s,%s,%s", path, timestampStr, appIntegritySecret)

		hasher := sha256.New()
		hasher.Write([]byte(payload))
		serverSignature := hex.EncodeToString(hasher.Sum(nil))

		// 3. 比较签名
		if serverSignature != clientSignature {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
			return
		}

		c.Next()
	}
}

// 检查用户是否拥有访问taie的权限
func taiePermissionMiddlerware(force bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if force {
			if keyData["useTaie"] != "true" {
				fmt.Printf("Access denied for key %s: useTaie permission not granted\n", longTermKey)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
				return
			}
		} else {
			if keyData["useTaie"] != "true" {
				c.Set("useTaie", false)
			} else {
				c.Set("useTaie", true)
			}
		}

		c.Next()
	}
}

// 检查用户是否拥有商店奖券的权限
func shopPermissionMiddlerware(force bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if force {
			if keyData["useShop"] != "true" {
				fmt.Printf("Access denied for key %s: useShop permission not granted\n", longTermKey)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
				return
			}
		} else {
			if keyData["useShop"] != "true" {
				c.Set("useShop", false)
			} else {
				c.Set("useShop", true)
			}
		}

		c.Next()
	}
}

// 检查用户是否拥有亮评的权限
func lightPermissionMiddlerware(force bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if force {
			if keyData["useLight"] != "true" {
				fmt.Printf("Access denied for key %s: useLight permission not granted\n", longTermKey)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
				return
			}
		} else {
			if keyData["useLight"] != "true" {
				c.Set("useLight", false)
			} else {
				c.Set("useLight", true)
			}
		}

		c.Next()
	}
}

// activitiesPermissionMiddleware 检查用户是否拥有访问活动的权限
func activitiesPermissionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if keyData["useActivities"] != "true" {
			fmt.Printf("Access denied for key %s: useActivities permission not granted\n", longTermKey)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
			return
		}

		c.Next()
	}
}

// cyberPermissionMiddleware 检查用户是否有构造安装包的权限
func cyberPermissionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if keyData["useCyber"] != "true" {
			fmt.Printf("Access denied for key %s: useCyber permission not granted\n", longTermKey)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
			return
		}

		c.Next()
	}
}

func wooPermissionMiddlerware() gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if keyData["useWoo"] != "true" {
			fmt.Printf("Access denied for key %s: useWoo permission not granted\n", longTermKey)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
			return
		}

		c.Next()
	}
}

func wooProPermissionMiddlerware() gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if keyData["useWooPro"] != "true" {
			fmt.Printf("Access denied for key %s: useWoo permission not granted\n", longTermKey)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
			return
		}

		c.Next()
	}
}

func whiteUserMiddlerware() gin.HandlerFunc {
	return func(c *gin.Context) {
		longTermKey, exists := c.Get("longTermKey")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: authentication key missing"})
			return
		}

		keyData, err := swordRdb.HGetAll(ctx, longTermKey.(string)).Result()
		if err != nil {
			fmt.Printf("Failed to retrieve key data from Redis for %s: %v\n", longTermKey, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify permissions"})
			return
		}

		if keyData["whitelisted"] != "true" {
			fmt.Printf("Access denied for key %s: useWoo permission not granted\n", longTermKey)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have permission to access this resource"})
			return
		}

		c.Next()
	}
}

// encryptionMiddleware	响应加密中间件
func encryptionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		longTermKey, _ := c.Get("longTermKey")
		dataToEncrypt, exists := c.Get("dataToEncrypt")

		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No data to encrypt"})
			return
		}

		log.Printf("本次响应: %v", dataToEncrypt)
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

		c.Status(http.StatusOK)
		c.JSON(http.StatusOK, EncryptedResponse{Payload: encryptedPayload})
	}
}
