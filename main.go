package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. 初始化 Redis 客户端
	initRedis()

	// 2. 初始化 Gin 引擎
	router := gin.Default()

	// 配置 Gin 以信任代理服务器设置的 X-Forwarded-For Header
	router.SetTrustedProxies([]string{"127.0.0.1"})

	// 3. 设置路由
	// 验证接口，用于换取 JWT
	router.POST("/validate", handleValidation)

	// 受保护的 API 组
	apiGroup := router.Group("/api")
	apiGroup.Use(authMiddleware())       // 应用 JWT 认证中间件
	apiGroup.Use(appIntegrityMiddleware()) // 应用客户端完整性校验中间件
	{
		apiGroup.GET("/profile", handleProfile)
		apiGroup.GET("/string", handleString)
		apiGroup.GET("/array", handleArray)
		apiGroup.POST("/v1/gateway", handleGateway)
	}

	// 4. 启动服务器
	log.Println("服务器启动，监听端口 :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Gin 服务器启动失败: %v", err)
	}
}
