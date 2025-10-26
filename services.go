package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/pbkdf2"
)

// --- KDF and Encryption Constants ---
const (
	saltSize         = 8
	pbkdf2Iterations = 4096
	ipCacheTTL       = 120 * time.Hour // IP 地址缓存的有效期
)

// getGeoInfoForIP 调用外部服务获取 IP 的地理位置，并使用 Redis 进行缓存
func getGeoInfoForIP(ip string) (*GeoInfo, error) {
	// 对于本地测试，IP 可能是 127.0.0.1 或 ::1，这无法定位，直接返回模拟数据
	if ip == "127.0.0.1" || ip == "::1" {
		log.Println("检测到本地 IP，返回模拟地理位置")
		return &GeoInfo{
			Status:     "success",
			RegionName: "本地",
			City:       "开发环境",
			Query:      ip,
		}, nil
	}

	// 1. 优先查询 Redis 缓存
	cacheKey := fmt.Sprintf("ip_cache:%s", ip)
	cachedData, err := rdb.Get(ctx, cacheKey).Result()
	if err == nil {
		// 缓存命中
		log.Printf("IP 地址 %s 命中缓存", ip)
		var geoInfo GeoInfo
		if err := json.Unmarshal([]byte(cachedData), &geoInfo); err != nil {
			log.Printf("解析缓存的 GeoInfo JSON 失败: %v", err)
			// 如果缓存数据有问题，则继续往下走，从 API 获取
		} else {
			return &geoInfo, nil
		}
	} else if err != redis.Nil {
		// 如果是除了 "not found" 之外的其他 Redis 错误，打印日志但继续执行
		log.Printf("查询 Redis 缓存时出错: %v", err)
	}

	// 2. 缓存未命中，请求外部 API
	log.Printf("IP 地址 %s 未命中缓存，请求外部 API", ip)
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var geoInfo GeoInfo
	if err := json.Unmarshal(body, &geoInfo); err != nil {
		return nil, err
	}

	if geoInfo.Status != "success" {
		return nil, fmt.Errorf("IP-API error: %s", geoInfo.Message)
	}

	// 3. 将从 API 获取的结果存入 Redis 缓存，并设置有效期
	err = rdb.Set(ctx, cacheKey, body, ipCacheTTL).Err()
	if err != nil {
		log.Printf("设置 Redis 缓存失败: %v", err)
	}

	return &geoInfo, nil
}

// encrypt 使用 PBKDF2 派生密钥，然后使用 AES-GCM 加密数据
func encrypt(plaintext []byte, password []byte) (string, error) {
	// 1. 生成一个随机的 salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// 2. 使用 PBKDF2 从 password 和 salt 派生出密钥
	derivedKey := pbkdf2.Key(password, salt, pbkdf2Iterations, 32, sha256.New)

	// 3. 使用派生密钥进行 AES-GCM 加密
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// gcm.Seal 会将 nonce 附加到密文的开头
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// 4. 将 salt 附加到 [nonce + ciphertext] 的最前面
	finalPayload := append(salt, ciphertext...)

	// 5. 对最终的 payload 进行 Base64 编码
	return base64.StdEncoding.EncodeToString(finalPayload), nil
}
