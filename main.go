package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// init 设置全局时区为东八区（北京时间）
func init() {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	time.Local = loc
}

func main() {
	// ================= 1. 初始化日志系统 =================
	today := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("corn_server_%s.log", today)
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close() // 确保程序退出时关闭文件句柄

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// ================= 2. 初始化基础依赖 =================
	initRedis()
	defer closeRedis()

	initDB()
	defer closeDB()

	// ================= 3. 初始化定时器 =================
	cronManager := NewCronJobManager()

	_, err = cronManager.AddTaskWithImmediate("3 10,12,14,16,18,20,22 * * *", BoxActivitiesAll)
	if err != nil {
		panic(err)
	}

	cronManager.Start()
	defer cronManager.Stop()

	// ================= 4. 初始化 Gin 引擎 && 反向代理 =================
	router := gin.New()
	cyberProxy := ReverseProxy("http://127.0.0.1:8000")
	wooProxy := ReverseProxy("http://127.0.0.1:13456")

	// 中间件配置
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output:    logFile,
		Formatter: nil,
	}))
	router.Use(gin.Logger())
	router.SetTrustedProxies([]string{"127.0.0.1"})

	// 路由注册
	router.POST("/authenticate", handleAuthentication)

	apiGroup := router.Group("/api")
	apiGroup.Use(authMiddleware(), appIntegrityMiddleware())
	{
		apiGroup.POST("/v1/gateway", taiePermissionMiddlerware(false), shopPermissionMiddlerware(false), lightPermissionMiddlerware(false), encryptionMiddleware(), handleGateway)
		apiGroup.POST("/v1/lucy", taiePermissionMiddlerware(false), encryptionMiddleware(), handleLucy)
		apiGroup.POST("/v1/david", shopPermissionMiddlerware(true), encryptionMiddleware(), handleDavid)

		v1 := apiGroup.Group("/v1")
		{
			v1.GET("/5a3919568264927d643a934a51a439e6", getNextTaskHandler)
			v1.POST("/b474528334283249d218771959415853", submitTaskHandler)
		}

		apiGroup.GET("/activities", activitiesPermissionMiddleware(), encryptionMiddleware(), getActivitiesHandler)
		apiGroup.GET("/activities/add", activitiesPermissionMiddleware(), addUserActivityHandler)
		apiGroup.GET("/activities/getall", activitiesPermissionMiddleware(), getUserActivitiesIntsHandler)
		apiGroup.GET("/activities/search", activitiesPermissionMiddleware(), encryptionMiddleware(), searchActivitiesHandler)
		apiGroup.GET("/activities/getself", activitiesPermissionMiddleware(), encryptionMiddleware(), getUserActivitiesHandler)
	}

	cyberGroup := router.Group("/apk")
	cyberGroup.Use(authMiddleware(), appIntegrityMiddleware(), cyberPermissionMiddleware())
	{
		cyberGroup.GET("/load_cache", loadSearchCache)
		cyberGroup.POST("/submit_cache", submitSearchCache)
		cyberGroup.GET("/submit", submitGradlewJob)
		cyberGroup.GET("/download", downloadApk)
		cyberGroup.GET("/operations", OperationsProxy(cyberProxy))
		cyberGroup.GET("/operations/:operation_id/apps", OperationAppsProxy(cyberProxy))
	}

	wooGroup := router.Group("/woo")
	wooGroup.Use(authMiddleware(), appIntegrityMiddleware(), wooPermissionMiddlerware())
	{
		wooGroup.GET("/box_search", searchBoxActs)
		wooGroup.GET("/stock/:lottery_id", wooProPermissionMiddlerware(), TapStockProxy(wooProxy))
	}

	safeGroup := router.Group("/safe")
	safeGroup.Use(authMiddleware(), appIntegrityMiddleware())
	{
		safeGroup.GET("/log", logSubmit)
	}

	// ================= 5. 启动后台任务 =================
	// 创建一个可取消的 context，用于向后台协程发送停止信号
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel() // 确保主函数退出前，一定触发 cancel

	go startTaskTimeoutWatcher(bgCtx)
	go startTaskGenerator(bgCtx)

	// ================= 6. 启动 HTTP Server =================
	srv := &http.Server{
		Addr:    ":3839",
		Handler: router,
	}

	// 在单独的 goroutine 中启动服务，避免阻塞主线程
	go func() {
		log.Println("服务器启动，监听端口 :3839")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gin 服务器启动失败: %v", err)
		}
	}()

	// ================= 7. 优雅关闭流程 =================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // 阻塞在此，直到接收到 Ctrl+C 或 kill 信号

	log.Println("收到退出信号，开始优雅关闭服务...")

	// 7.1 先停止后台定时任务
	log.Println("正在停止后台定时任务...")
	bgCancel()

	// 7.2 优雅关闭 HTTP 服务（给正在处理的请求最多 5 秒钟完成时间）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("HTTP Server Shutdown:", err)
	}

	log.Println("所有服务已安全关闭，主进程退出。")
}

// GOOS=linux GOARCH=amd64 go build -o corn_server
