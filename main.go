package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. 设置日志记录
	// 按日期创建日志文件，例如 corn_server_2023-10-26.log
	today := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("corn_server_%s.log", today)
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}

	// 标准 log 包的输出（例如, 我们自己的业务日志）将同时写入文件和控制台
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// 2. 初始化 Redis 客户端
	initRedis()

	// 3. 初始化 Gin 引擎
	router := gin.New()

	// 添加中间件：
	// a. 第一个 logger：向文件写入纯文本日志
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output:    logFile,
		Formatter: nil, // 使用默认的纯文本格式化器
	}))

	// b. 第二个 logger：向控制台写入带颜色的日志
	router.Use(gin.Logger())

	// c. Recovery 中间件，用于从任何 panic 中恢复，并返回 500 错误
	router.Use(gin.Recovery())

	// 配置 Gin 以信任代理服务器设置的 X-Forwarded-For Header
	router.SetTrustedProxies([]string{"127.0.0.1"})

	// 4. 设置路由
	// 验证接口，用于换取 JWT
	router.POST("/validate", handleValidation)

	// 受保护的 API 组
	apiGroup := router.Group("/api")
	apiGroup.Use(authMiddleware())         // 应用 JWT 认证中间件
	apiGroup.Use(appIntegrityMiddleware()) // 应用客户端完整性校验中间件
	{
		apiGroup.POST("/v1/gateway", handleGateway)
	}

	// 5. 启动服务器
	log.Println("服务器启动，监听端口 :3839")
	if err := router.Run(":3839"); err != nil {
		log.Fatalf("Gin 服务器启动失败: %v", err)
	}
}
