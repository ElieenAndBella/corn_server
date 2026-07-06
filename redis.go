package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var swordRdb *redis.Client
var apkRdb *redis.Client

const (
	taskQueueTodo       = "task_queue:todo"
	taskQueueProcessing = "task_queue:processing"
	taskRetryCountHash  = "task_queue:retry_count" // 用于记录任务重试次数
	maxRetryCount       = 22                       // 最大重试次数
)

// initRedis 初始化 Redis 客户端连接
func initRedis() {
	swordRdb = redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Password: redisPassword,
		DB:       swordRedisDB,
	})

	apkRdb = redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Password: redisPassword,
		DB:       apkRedisDB,
	})

	if _, err := swordRdb.Ping(ctx).Result(); err != nil {
		log.Fatalf("无法连接到 swordRedis: %v", err)
	}

	if _, err := apkRdb.Ping(ctx).Result(); err != nil {
		log.Fatalf("无法连接到 apkRedis: %v", err)
	}

	log.Println("成功连接到 sword & apk Redis")
	setupInitialKeys()
}

func closeRedis() {
	if swordRdb != nil {
		if err := swordRdb.Close(); err != nil {
			log.Printf("关闭 swordRedis 失败: %v", err)
		} else {
			log.Println("swordRedis 已成功关闭")
		}
	}

	if apkRdb != nil {
		if err := apkRdb.Close(); err != nil {
			log.Printf("关闭 apkRedis 失败: %v", err)
		} else {
			log.Println("apkRedis 已成功关闭")
		}
	}
}

// getNextTaskID 从 todo 队列获取一个任务，检查重试次数，超过最大重试次数的任务将被丢弃
func getNextTaskID() (string, error) {
	for {
		// 从 task_queue:todo 列表的右边弹出一个任务ID
		taskID, err := swordRdb.RPop(ctx, taskQueueTodo).Result()
		if err != nil {
			if err == redis.Nil {
				// 队列为空
				return "", nil
			}
			return "", err
		}

		// 检查任务的重试次数
		shouldProcess, err := shouldProcessTask(taskID)
		if err != nil {
			log.Printf("检查任务 %s 重试次数时出错: %v", taskID, err)
			// 出错时暂时不处理这个任务，先放回队列
			if err := retryTask(taskID); err != nil {
				log.Printf("将任务 %s 放回队列时出错: %v", taskID, err)
			}
			continue
		}

		if !shouldProcess {
			// 超过最大重试次数，丢弃任务并记录日志
			log.Printf("任务 %s 已达到最大重试次数 %d，将被丢弃", taskID, maxRetryCount)
			// 清理重试次数记录
			if err := swordRdb.HDel(ctx, taskRetryCountHash, taskID).Err(); err != nil {
				log.Printf("清理任务 %s 的重试记录时出错: %v", taskID, err)
			}
			continue // 继续处理下一个任务
		}

		// 增加重试次数
		if err := incrementRetryCount(taskID); err != nil {
			log.Printf("增加任务 %s 重试次数时出错: %v", taskID, err)
			// 出错时暂时不处理这个任务，先放回队列
			if err := retryTask(taskID); err != nil {
				log.Printf("将任务 %s 放回队列时出错: %v", taskID, err)
			}
			continue
		}

		// 将任务 ID 添加到 processing 哈希表，并记录开始处理的时间戳
		now := time.Now().Unix()
		if err := swordRdb.HSet(ctx, taskQueueProcessing, taskID, now).Err(); err != nil {
			log.Printf("无法将任务 %s 添加到 processing 哈希表: %v", taskID, err)
			// 如果添加失败，减少重试次数（因为实际上还没有开始处理）
			if err := decrementRetryCount(taskID); err != nil {
				log.Printf("回滚任务 %s 重试次数时出错: %v", taskID, err)
			}
			// 将任务放回队列
			if err := retryTask(taskID); err != nil {
				log.Printf("将任务 %s 放回队列时出错: %v", taskID, err)
			}
			continue
		}

		return taskID, nil
	}
}

// shouldProcessTask 检查任务是否应该被处理（重试次数是否超过限制）
func shouldProcessTask(taskID string) (bool, error) {
	retryCount, err := swordRdb.HGet(ctx, taskRetryCountHash, taskID).Result()
	if err != nil {
		if err == redis.Nil {
			// 没有重试记录，说明是第一次处理
			return true, nil
		}
		return false, err
	}

	count, err := strconv.Atoi(retryCount)
	if err != nil {
		return false, err
	}

	return count < maxRetryCount, nil
}

// incrementRetryCount 增加任务的重试次数
func incrementRetryCount(taskID string) error {
	_, err := swordRdb.HIncrBy(ctx, taskRetryCountHash, taskID, 1).Result()
	return err
}

// decrementRetryCount 减少任务的重试次数（用于回滚）
func decrementRetryCount(taskID string) error {
	count, err := swordRdb.HGet(ctx, taskRetryCountHash, taskID).Result()
	if err != nil {
		return err
	}

	currentCount, err := strconv.Atoi(count)
	if err != nil {
		return err
	}

	if currentCount <= 1 {
		// 如果次数为1，直接删除记录
		return swordRdb.HDel(ctx, taskRetryCountHash, taskID).Err()
	}

	_, err = swordRdb.HIncrBy(ctx, taskRetryCountHash, taskID, -1).Result()
	return err
}

// retryTask 将任务重新放回队列（放在左边，以便尽快重试）
func retryTask(taskID string) error {
	return swordRdb.LPush(ctx, taskQueueTodo, taskID).Err()
}

// removeTaskFromProcessing 从 processing 哈希表中移除一个已完成的任务
// 成功处理后可选择清除重试记录
func removeTaskFromProcessing(taskID string) error {
	// 从处理中队列移除
	err := swordRdb.HDel(ctx, taskQueueProcessing, taskID).Err()
	if err != nil {
		log.Printf("警告: 无法从 processing 哈希表中移除任务 %s: %v", taskID, err)
		return err
	}

	// 如果任务成功处理，清除重试记录
	if err := swordRdb.HDel(ctx, taskRetryCountHash, taskID).Err(); err != nil {
		log.Printf("警告: 无法清除任务 %s 的重试记录: %v", taskID, err)
		// 不返回错误，因为主要操作已经完成
	}

	return nil
}

// getLatestTaskIDFromRedisQueue 获取 todo 队列中当前最大的任务ID
func getLatestTaskIDFromTodoQueue() (int, error) {
	// 获取列表中的所有元素
	items, err := swordRdb.LRange(ctx, taskQueueTodo, 0, -1).Result()
	if err != nil {
		return 0, err
	}
	maxID := 0
	for _, itemStr := range items {
		id, err := strconv.Atoi(itemStr)
		if err != nil {
			continue
		}
		if id > maxID {
			maxID = id
		}
	}

	return maxID, nil
}

// getLatestTaskIDFromProcessingQueue 获取 processing 表中最大的任务ID
func getLatestTaskIDFromProcessingQueue() (int, error) {
	// 获取 processing 表中的所有元素
	itemMaps, err := swordRdb.HGetAll(ctx, taskQueueProcessing).Result()
	if err != nil {
		return 0, err
	}

	maxID := 0
	for key := range itemMaps {
		id, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		if id > maxID {
			maxID = id
		}
	}
	return maxID, nil
}

// getTaskQueueTodoLength 获取 todo 队列的当前长度
func getTaskQueueTodoLength() (int64, error) {
	return swordRdb.LLen(ctx, taskQueueTodo).Result()
}

// setupInitialKeys 在 Redis 中设置一个测试用的长期 Key
func setupInitialKeys() {
	// 我们用 Hash 来存储 Key 的信息，"province" 和 "cities" 字段用于风控
	// 初始时，字段值为空
	key := "CF67355A3333E6E143439161ADC2D82E"
	exists, err := swordRdb.Exists(ctx, key).Result()
	if err != nil {
		log.Printf("检查 Key '%s' 时出错: %v", key, err)
		return
	}
	if exists == 0 {
		// 使用新格式创建 Key
		fields := map[string]any{
			"provinces":     "",
			"cities":        "",
			"useTaie":       true,
			"useActivities": true,
		}
		err := swordRdb.HSet(ctx, key, fields).Err()
		if err != nil {
			log.Fatalf("设置初始 Key '%s' 失败: %v", key, err)
		}
		log.Printf("测试 Key '%s' 已使用新格式在 Redis 中创建", key)
	}
}

// APK RELATED 后台只控制 WAITING 状态，
// 其他状态(BUILDING, SUCCESS, FAIL)由 Worker 控制

const (
	buildQueue = "build_queue"
)

func addGradlewJob(apkInfo ApkInfo) error {
	apkBytes, err := json.Marshal(apkInfo)
	if err != nil {
		return err
	}

	cacheKey := fmt.Sprintf("apk:%s:%s:%s", apkInfo.ApplicationId, apkInfo.VersionName, apkInfo.VersionCode)

	pipe := apkRdb.Pipeline()
	pipe.HSet(ctx, cacheKey, "status", "WAITING")
	pipe.LPush(ctx, buildQueue, string(apkBytes))
	_, err = pipe.Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func getSearchCache(cacheKey string) ([]GameBasicInfo, bool) {
	val, err := apkRdb.Get(ctx, cacheKey).Result()
	if err == redis.Nil {
		return nil, false
	} else if err != nil {
		log.Printf("Redis get error for key %s: %v", cacheKey, err)
		return nil, false
	}

	var results []GameBasicInfo
	if err := json.Unmarshal([]byte(val), &results); err != nil {
		log.Printf("JSON unmarshal error for key %s: %v", cacheKey, err)
		return nil, false
	}

	return results, true
}

func setSearchCache(cacheKey string, data []GameBasicInfo) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("JSON marshal error for key %s: %v", cacheKey, err)
		return err
	}

	expiration := 3 * time.Minute
	err = apkRdb.Set(ctx, cacheKey, jsonData, expiration).Err()
	if err != nil {
		log.Printf("Redis set error for key %s: %v", cacheKey, err)
		return err
	}

	log.Printf("Cache set successfully for key: %s", cacheKey)
	return nil
}
