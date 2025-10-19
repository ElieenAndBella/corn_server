package main

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb *redis.Client

// initRedis 初始化 Redis 客户端连接
func initRedis() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Password: redisPassword,
		DB:       redisDB,
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("无法连接到 Redis: %v", err)
	}

	log.Println("成功连接到 Redis")

	// 初始化一个有效的长期 Key 用于测试
	// 在真实场景中，你应该有自己的方式来管理这些 Key
	setupInitialKeys()
}

// setupInitialKeys 在 Redis 中设置一个测试用的长期 Key
func setupInitialKeys() {
	// 我们用 Hash 来存储 Key 的信息，"location" 字段用于风控
	// 初始时，location 为空
	key := "VALID_KEY_123"
	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		log.Printf("检查 Key 时出错: %v", err)
		return
	}
	if exists == 0 {
		err := rdb.HSet(ctx, key, "location", "").Err()
		if err != nil {
			log.Fatalf("设置初始 Key 失败: %v", err)
		}
		log.Printf("测试 Key '%s' 已在 Redis 中创建", key)
	}
}
