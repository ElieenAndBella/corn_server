package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
