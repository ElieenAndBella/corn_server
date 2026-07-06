package main

import (
	"context"
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
	"slices"
	"strconv"
	"strings"
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
	cachedData, err := swordRdb.Get(ctx, cacheKey).Result()
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

	// 2. 优先使用新接口
	log.Printf("IP 地址 %s 未命中缓存，优先请求新 API", ip)
	geoInfo, err := getGeoInfoFromNewAPI(ip)
	if err == nil {
		// 新接口成功，缓存结果
		body, _ := json.Marshal(geoInfo)
		err = swordRdb.Set(ctx, cacheKey, body, ipCacheTTL).Err()
		if err != nil {
			log.Printf("设置 Redis 缓存失败: %v", err)
		}
		return geoInfo, nil
	}

	log.Printf("新 API 请求失败: %v，回退到旧 API", err)

	// 3. 新接口失败，回退到旧接口
	geoInfo, err = getGeoInfoFromOldAPI(ip)
	if err != nil {
		return nil, err
	}

	// 缓存旧接口的结果
	body, _ := json.Marshal(geoInfo)
	err = swordRdb.Set(ctx, cacheKey, body, ipCacheTTL).Err()
	if err != nil {
		log.Printf("设置 Redis 缓存失败: %v", err)
	}

	return geoInfo, nil
}

// removeSuffix 去掉省市后缀
func removeSuffix(s string) string {
	s = strings.TrimSuffix(s, "省")
	s = strings.TrimSuffix(s, "市")
	s = strings.TrimSuffix(s, "自治区")
	s = strings.TrimSuffix(s, "壮族")
	s = strings.TrimSuffix(s, "回族")
	s = strings.TrimSuffix(s, "维吾尔")
	s = strings.TrimSuffix(s, "行政区")
	s = strings.TrimSuffix(s, "特别")
	// 可以继续添加其他需要去掉的后缀
	return s
}

// isISP 判断字符串是否为运营商
func isISP(s string) bool {
	ispList := []string{
		"移动", "联通", "电信", "广电",
	}

	return slices.Contains(ispList, s)
}

// getGeoInfoFromNewAPI 从新接口获取 IP 地理信息
func getGeoInfoFromNewAPI(ip string) (*GeoInfo, error) {
	// 新接口 URL，请替换为实际的 URL
	url := fmt.Sprintf("http://ip.plyz.net/ip.ashx?ip=%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 解析新接口返回的格式：211.97.135.69|中国 福建省 厦门市 联通
	// 或 39.144.196.7|中国 新疆 移动
	// 或 39.144.231.110|中国 移动
	responseStr := strings.TrimSpace(string(body))
	parts := strings.Split(responseStr, "|")
	if len(parts) != 2 {
		return nil, fmt.Errorf("新接口返回格式错误: %s", responseStr)
	}

	// 解析地理位置信息
	locationParts := strings.Fields(parts[1]) // 使用 Fields 可以处理多个连续空格
	if len(locationParts) < 1 {
		return nil, fmt.Errorf("地理位置信息格式错误: %s", parts[1])
	}

	// 提取基本信息
	var country, regionName, city string

	// 第一个部分通常是国家
	country = removeSuffix(locationParts[0])

	// 分析剩余部分
	remainingParts := locationParts[1:]

	// 尝试识别省份和城市
	for _, part := range remainingParts {
		// 如果遇到运营商，停止解析
		if isISP(part) {
			break
		}

		// 如果还没有设置省份，尝试设置省份
		if regionName == "" {
			// 检查是否是省份（通过常见的省份后缀判断）
			if strings.HasSuffix(part, "省") || strings.HasSuffix(part, "市") ||
				strings.HasSuffix(part, "自治区") || isLikelyProvince(part) {
				regionName = removeSuffix(part)
			}
		} else if city == "" {
			// 如果已经有省份但还没有城市，尝试设置城市
			city = removeSuffix(part)
		}
	}

	return &GeoInfo{
		Status:     "success",
		Country:    country,
		RegionName: regionName,
		City:       city,
		Query:      ip,
	}, nil
}

// isLikelyProvince 判断字符串是否可能是省份
func isLikelyProvince(s string) bool {
	provinces := []string{
		"北京", "天津", "上海", "重庆", "河北", "山西", "辽宁", "吉林", "黑龙江",
		"江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南",
		"广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾",
		"内蒙古", "广西", "宁夏", "新疆", "西藏", "香港", "澳门",
	}

	for _, province := range provinces {
		if strings.Contains(s, province) {
			return true
		}
	}
	return false
}

// getGeoInfoFromOldAPI 从旧接口获取 IP 地理信息
func getGeoInfoFromOldAPI(ip string) (*GeoInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip)
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

	// 对旧接口返回的数据也去掉省市后缀
	geoInfo.RegionName = removeSuffix(geoInfo.RegionName)
	geoInfo.City = removeSuffix(geoInfo.City)

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

// saveActivityResult 将爬取结果保存到 PostgreSQL 数据库
func saveActivityResult(activity ActivityResp, taskID string) error {
	// 1. 将切片/数组字段序列化为 JSON
	awardsJSON, err := json.Marshal(activity.Awards)
	if err != nil {
		return fmt.Errorf("序列化 awards 失败: %w", err)
	}

	conditionsJSON, err := json.Marshal(activity.Conditions)
	if err != nil {
		return fmt.Errorf("序列化 conditions 失败: %w", err)
	}

	// 2. 解析时间字符串
	// Go 的标准库使用 "2006年01月02日 15:04:05" 作为布局参考
	drawTime, err := time.Parse("2006年01月02日 15:04:05", activity.DrawTime)
	if err != nil {
		return fmt.Errorf("解析 draw_time 失败: %w", err)
	}
	drawTime = drawTime.Add(-8 * time.Hour)
	publishTime, err := time.Parse("2006年01月02日 15:04:05", activity.PublishTime)
	if err != nil {
		return fmt.Errorf("解析 publish_time 失败: %w", err)
	}
	publishTime = publishTime.Add(-8 * time.Hour)

	// 3. 执行 SQL 插入或更新语句 (UPSERT)
	query := `
		INSERT INTO activity_results (
			activity_id, article_id, awards, conditions, title, 
			link_title, game_name, author_name, cover, draw_time, publish_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (activity_id) DO UPDATE SET
			article_id = EXCLUDED.article_id,
			awards = EXCLUDED.awards,
			conditions = EXCLUDED.conditions,
			title = EXCLUDED.title,
			link_title = EXCLUDED.link_title,
			game_name = EXCLUDED.game_name,
			author_name = EXCLUDED.author_name,
			cover = EXCLUDED.cover,
			draw_time = EXCLUDED.draw_time,
			publish_time = EXCLUDED.publish_time;
	`
	_, err = dbPool.Exec(context.Background(), query,
		activity.ActivityID,
		activity.ArticleID,
		awardsJSON,
		conditionsJSON,
		activity.Title,
		activity.LinkTitle,
		activity.GameName,
		activity.AuthorName,
		activity.Cover,
		drawTime,
		publishTime,
	)

	if err != nil {
		return fmt.Errorf("插入数据到 PostgreSQL 失败: %w", err)
	}

	// 4. 从 Redis 的 processing 哈希表中移除任务
	if err := removeTaskFromProcessing(taskID); err != nil {
		// 即使这里失败了，主流程也算成功了，只记录日志
		log.Printf("警告: 从 Redis 中移除任务 %s 失败: %v", taskID, err)
	}

	log.Printf("成功处理并存储了任务 %s 的结果", taskID)
	return nil
}

// --- Task Timeout Watcher ---

const (
	taskTimeout          = 360 * time.Minute // 任务超时时间
	timeoutCheckInterval = 60 * time.Minute  // 检查周期
)

// startTaskTimeoutWatcher 启动一个后台 goroutine 来监控超时的任务
func startTaskTimeoutWatcher(ctx context.Context) {
	log.Println("后台任务超时监控已启动...")
	ticker := time.NewTicker(timeoutCheckInterval)
	defer ticker.Stop() // 确保无论何时退出，都释放 Ticker 资源

	for {
		select {
		case <-ticker.C:
			// 触发定时器，执行你的业务逻辑
			checkAndRequeueTimedOutTasks()

		case <-ctx.Done():
			// 监听到主程序的取消信号，安全退出
			log.Println("后台任务超时监控已安全停止。")
			return
		}
	}
}

// checkAndRequeueTimedOutTasks 检查并重新排队超时的任务
func checkAndRequeueTimedOutTasks() {
	// 获取所有正在处理的任务
	processingTasks, err := swordRdb.HGetAll(ctx, taskQueueProcessing).Result()
	if err != nil {
		log.Printf("错误: 无法获取正在处理的任务列表: %v", err)
		return
	}

	if len(processingTasks) == 0 {
		// log.Println("没有正在处理的任务。") // 在没有任务时减少日志噪音
		return
	}

	now := time.Now().Unix()
	var tasksToRequeue []string

	for taskID, startTimeStr := range processingTasks {
		startTime, err := strconv.ParseInt(startTimeStr, 10, 64)
		if err != nil {
			log.Printf("警告: 无法解析任务 %s 的开始时间戳: %v", taskID, err)
			continue
		}

		if now-startTime > int64(taskTimeout.Seconds()) {
			// 任务超时
			tasksToRequeue = append(tasksToRequeue, taskID)
		}
	}

	if len(tasksToRequeue) > 0 {
		log.Printf("发现 %d 个超时任务: %v", len(tasksToRequeue), tasksToRequeue)
		// 使用 pipeline 来原子化操作
		pipe := swordRdb.Pipeline()
		for _, taskID := range tasksToRequeue {
			pipe.RPush(ctx, taskQueueTodo, taskID)      // 重新推入 todo 队列
			pipe.HDel(ctx, taskQueueProcessing, taskID) // 从 processing 哈希表中删除
		}
		_, err := pipe.Exec(ctx)
		if err != nil {
			log.Printf("错误: 重新排队超时任务失败: %v", err)
		} else {
			log.Printf("成功将 %d 个任务重新排队。", len(tasksToRequeue))
		}
	}
}

// --- Task Generator ---

const (
	fastGenThreshold  = 12               // 任务数低于此值时，加快生成速度
	fastGenInterval   = 1 * time.Minute  // 快速生成间隔
	normalGenInterval = 60 * time.Minute // 普通生成间隔
)

// getLatestActivityIDFromDB 获取数据库中最大的 activity_id
func getLatestActivityIDFromDB() (int, error) {
	var maxID int
	// 使用 COALESCE 来处理表中没有记录时返回 NULL 的情况，此时会返回 0
	err := dbPool.QueryRow(context.Background(), "SELECT COALESCE(MAX(activity_id), 0) FROM activity_results").Scan(&maxID)
	if err != nil {
		return 0, err
	}
	return maxID, nil
}

// generateAndAddNewTaskID 生成并添加一个新的任务ID
func generateAndAddNewTaskID() {

	// 1. 从数据库获取最大ID
	maxDbID, err := getLatestActivityIDFromDB()
	if err != nil {
		log.Printf("错误: 无法从数据库获取最大任务ID: %v", err)
		return
	}

	// 2. 从 Todo 队列获取最大ID
	maxTodoID, err := getLatestTaskIDFromTodoQueue()
	if err != nil {
		log.Printf("错误: 无法从 Todo 获取最大任务ID: %v", err)
		return
	}

	// 3. 从 Processing 表中获取最大ID
	maxProcessingID, err := getLatestTaskIDFromProcessingQueue()
	if err != nil {
		log.Printf("错误: 无法从 Processing 获取最大任务ID: %v", err)
		return
	}

	// 4. 决定下一个ID
	nextID := 0
	latestID := max(maxDbID, maxTodoID)
	latestID = max(latestID, maxProcessingID)

	if latestID == 0 {
		// 如果两边都没有，从配置的起始值开始
		nextID = taskStartID
	} else {
		nextID = latestID + 1
	}

	// 5. 将新ID添加到任务队列
	err = swordRdb.LPush(ctx, taskQueueTodo, nextID).Err()
	if err != nil {
		log.Printf("错误: 无法将新任务ID %d 添加到队列: %v", nextID, err)
		return
	}

	log.Printf("成功生成并添加新任务ID: %d", nextID)
}

// startTaskGenerator 启动后台任务生成器
func startTaskGenerator(ctx context.Context) {
	log.Println("后台任务生成器已启动...")

	// 核心改造：使用 for-select 替代递归闭包
	for {
		select {
		case <-ctx.Done():
			// 【优雅退出】收到取消信号，直接结束整个协程
			log.Println("后台任务生成器已安全停止。")
			return

		default:
			// 【执行业务逻辑】立刻执行一次任务生成
			generateAndAddNewTaskID()

			// 【动态计算间隔】检查队列长度，决定下一次运行时间
			queueLen, err := getTaskQueueTodoLength()
			sleepDuration := normalGenInterval

			if err != nil {
				log.Printf("警告: 无法获取任务队列长度，将使用默认间隔: %v", err)
			} else {
				if queueLen < fastGenThreshold {
					sleepDuration = fastGenInterval
				}
			}
			log.Printf("任务队列当前长度: %d。下次任务生成将在 %v 后进行。", queueLen, sleepDuration)

			// 【精准休眠】使用 select + time.After 实现带超时/可中断的睡眠
			// 如果在休眠期间收到了 ctx.Done() 信号，会立即跳出 select 进入下一轮循环并退出
			select {
			case <-time.After(sleepDuration):
				// 正常睡够了，继续下一轮 for 循环
			case <-ctx.Done():
				// 睡觉时被叫醒（收到退出信号），准备退出
			}
		}
	}
}

// 为指定用户添加与活动的关联
func addUserActivity(userKey string, activityID int) error {
	sql := `
		INSERT INTO user_activities (user_key, activity_id) 
		VALUES ($1, $2)
		ON CONFLICT (user_key, activity_id) DO NOTHING
	`
	_, err := dbPool.Exec(context.Background(), sql, userKey, activityID)
	return err
}

func getUserActivitiesInts(userKey string) ([]int, error) {
	var activities []int
	sql := `SELECT activity_id FROM user_activities WHERE user_key = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), sql, userKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var activityID int
		if err := rows.Scan(&activityID); err != nil {
			return nil, err
		}
		activities = append(activities, activityID)
	}
	return activities, nil
}

// --- APK ---
func getGradlewJobStatus(apkInfo ApkInfo) string {
	cacheKey := fmt.Sprintf("apk:%s:%s:%s", apkInfo.ApplicationId, apkInfo.VersionName, apkInfo.VersionCode)
	return apkRdb.HGet(ctx, cacheKey, "status").Val()
}

func getAPKPath(apkInfo ApkInfo) string {
	cacheKey := fmt.Sprintf("apk:%s:%s:%s", apkInfo.ApplicationId, apkInfo.VersionName, apkInfo.VersionCode)
	return apkRdb.HGet(ctx, cacheKey, "path").Val()
}

// --- WOO ---
// 通过关键词搜索相关活动
func getBoxFilter(keyword string) (hds []HDInfo) {

	for _, v := range HDIsLatest {
		if strings.Contains(v.Title, keyword) {
			hds = append(hds, v)
		}
	}

	return
}

// 从接口获取奖品信息及中奖者
func getBoxPrizeAndWinnerList(tag string) (si SubscribeInfo) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://huodong.4399.cn/game/api/huodong/tpl/%s/yxhGameSubscribe.html?scookie=&udid=&deviceId=", tag), nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0")
	req.Header.Add("Referer", "https://huodong.4399.cn/game/maintain/serve/longTermSub/index?hd="+tag)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	rbs, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	json.Unmarshal(rbs, &si)
	if si.Code == 101 {
		return SubscribeInfo{}
	}
	return
}
