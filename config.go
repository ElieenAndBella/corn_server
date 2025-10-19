package main

import (
	"log"
	"os"
	"strconv"
	"time"
)

// --- Configuration ---

var (
	jwtSecretKey       string
	redisAddress       string
	redisPassword      string
	redisDB            int
	tokenLifetime      = time.Hour * 12 // 这个可以保持不变
	appIntegritySecret string
	productsUrl        string
	roundUrl           string
	universalUrl       string
	wannengUrl         string
	clientSecretKey    string
	clientSecretValue  string
	anotherSecretString string
)

// init 函数在包初始化时自动执行，非常适合用来加载配置
func init() {
	jwtSecretKey = getEnv("JWT_SECRET_KEY", "your-super-secret-jwt-key")
	redisAddress = getEnv("REDIS_ADDRESS", "localhost:6379")
	redisPassword = getEnv("REDIS_PASSWORD", "")

	dbStr := getEnv("REDIS_DB", "0")
	db, err := strconv.Atoi(dbStr)
	if err != nil {
		log.Printf("无效的 REDIS_DB 值 '%s'，将使用默认值 0。错误: %v", dbStr, err)
		redisDB = 0
	} else {
		redisDB = db
	}

	appIntegritySecret = getEnv("APP_INTEGRITY_SECRET", "a-very-secret-string-for-app-integrity")
	productsUrl = getEnv("PRODUCTS_URL", "https://shop.3839.com/html/js/products.js")
	roundUrl = getEnv("ROUND_URL", "https://shop.3839.com/html/js/classify_24.js")
	universalUrl = getEnv("UNIVERSAL_URL", "https://act.3839.com/n/hykb/universal/ajax.php")
	wannengUrl = getEnv("WANNENG_URL", "https://act.3839.com/n/hykb/wanneng/ajax.php")
	clientSecretKey = getEnv("CLIENT_SECRET_KEY", "secret")
	clientSecretValue = getEnv("CLIENT_SECRET_VALUE", "c1714e41e5a907874c59a4d81a8486ea")
	anotherSecretString = getEnv("ANOTHER_SECRET_STRING", "hbktahqbyihfiidc")

	log.Println("配置已从环境变量加载")
}

// getEnv 读取一个环境变量，如果不存在则返回一个备用值
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
