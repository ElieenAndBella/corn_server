package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var _ = redis.Nil // Acknowledge redis import is needed for swordRdb's type

// handleAuthentication 处理长期 Key 的验证、IP 绑定并签发 JWT
func handleAuthentication(c *gin.Context) {
	longTermKey := c.GetHeader("X-Token")
	if longTermKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Token header is required"})
		return
	}

	// 获取用户端使用的功能 e.g. useCyber
	use := c.GetHeader("X-Def")
	if use == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "X-Def header is required"})
		return
	}

	// 1. 检查长期 Key 的基本有效性和封禁状态
	keyData, err := swordRdb.HGetAll(ctx, longTermKey).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error on key check"})
		return
	}
	if len(keyData) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid X-Token"})
		return
	}

	if _, ok := keyData[use]; !ok {
		log.Printf("Key '%s' 在访问不具备权限的功能。", longTermKey)
		c.JSON(http.StatusForbidden, gin.H{"error": "You're not allowed to use this software."})
		return
	}

	if status, ok := keyData["status"]; ok && status == "banned" {
		log.Printf("Key '%s' 已被封禁，拒绝访问。", longTermKey)
		c.JSON(http.StatusForbidden, gin.H{"error": "This key has been banned due to security policy violations."})
		return
	}

	// 2. IP 及地区风控
	clientIP := c.ClientIP()
	go func() {
		swordRdb.SAdd(ctx, "record:"+longTermKey, clientIP)
	}()
	geoInfo, err := getGeoInfoForIP(clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("IP geolocation failed: %v", err)})
		return
	}
	currentProvince := geoInfo.RegionName
	currentCity := geoInfo.City

	storedProvinces := keyData["provinces"]
	storedCities := keyData["cities"]
	isWhitelisted := keyData["whitelisted"] == "true"

	// --- 核心风控逻辑 (V2) ---
	var provinceList []string
	if storedProvinces != "" {
		provinceList = strings.Split(storedProvinces, ",")
	}

	var cityList []string
	if storedCities != "" {
		cityList = strings.Split(storedCities, ",")
	}

	if isWhitelisted {
		// 白名单用户: 记录所有使用过的省市，不封禁
		log.Printf("Key '%s' 是白名单用户，跳过IP风控检查。", longTermKey)
		needsUpdate := false
		if !slices.Contains(provinceList, currentProvince) {
			if currentProvince != "" {
				provinceList = append(provinceList, currentProvince)
				needsUpdate = true
			}
		}
		if !slices.Contains(cityList, currentCity) {
			if currentCity != "" { // 城市为空的情况
				cityList = append(cityList, currentCity)
				needsUpdate = true
			}
		}

		if needsUpdate {
			newProvinces := strings.Join(provinceList, ",")
			newCities := strings.Join(cityList, ",")
			fields := map[string]any{"provinces": newProvinces, "cities": newCities}
			if err := swordRdb.HSet(ctx, longTermKey, fields).Err(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update location for whitelisted key"})
				return
			}
			log.Printf("Whitelisted key '%s' 已更新位置信息。省份: [%s], 城市: [%s]", longTermKey, newProvinces, newCities)
		}
	} else {
		// 非白名单用户: 严格执行原始风控逻辑
		if len(provinceList) == 0 { // a. 首次使用，绑定地区
			fields := map[string]any{"provinces": currentProvince, "cities": currentCity}
			if err := swordRdb.HSet(ctx, longTermKey, fields).Err(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to bind location"})
				return
			}
			log.Printf("Key '%s' 首次使用，已绑定省份: %s, 城市: %s", longTermKey, currentProvince, currentCity)

		} else if provinceList[0] != currentProvince && currentProvince != "" { // b. 省份不匹配 (只认第一个省份)，封禁
			log.Printf("安全警报: Key '%s' 尝试跨省使用。绑定省份: '%s', 当前省份: '%s'。执行封禁。", longTermKey, provinceList[0], currentProvince)
			swordRdb.HSet(ctx, longTermKey, "status", "banned")
			c.JSON(http.StatusForbidden, gin.H{"error": "Security risk: Access from a different province is not allowed. This key has been banned."})
			return
		} else { // c. 省份匹配，检查城市
			if currentCity != "" { // 城市为空的情况
				isKnownCity := slices.Contains(cityList, currentCity)
				if !isKnownCity { // 发现新城市
					if len(cityList) < 3 { // c1. 城市数量未满3个，添加新城市
						log.Printf("Key '%s' 在新城市 '%s' 使用。当前城市列表: [%s]。允许访问。", longTermKey, currentCity, storedCities)
						newCityList := append(cityList, currentCity)
						newCities := strings.Join(newCityList, ",")
						if err := swordRdb.HSet(ctx, longTermKey, "cities", newCities).Err(); err != nil {
							c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update city list"})
							return
						}
					} else { // c2. 城市数量已满，封禁
						log.Printf("安全警报: Key '%s' 尝试在第四个城市 '%s' 使用。已绑定城市: [%s]。执行封禁。", longTermKey, currentCity, storedCities)
						swordRdb.HSet(ctx, longTermKey, "status", "banned")
						c.JSON(http.StatusForbidden, gin.H{"error": "Security risk: Access from more than 3 cities is not allowed. This key has been banned."})
						return
					}
				}
			}
		}
	}

	// 3. 生成 JWT (逻辑保持不变)
	claims := jwt.MapClaims{
		"sub": longTermKey,
		"exp": time.Now().Add(tokenLifetime).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	c.Header("server-timestamp", timestamp)
	c.JSON(http.StatusOK, gin.H{"jwt": tokenString, "sign": MD5String(timestamp + "golang")})
}

// handleGateway is a generic endpoint for fetching UI components like menus.
// It uses an obfuscated request body to determine what to return.
func handleGateway(c *gin.Context) {

	var reqBody struct {
		Target string   `json:"target"`
		Param  string   `json:"p,omitempty"`      // Optional parameter
		Params []string `json:"params,omitempty"` // New field for variable-length string array parameters
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var dataToEncrypt any

	// The "target" field determines what to fetch.
	// All target codes are intentionally obfuscated.
	switch reqBody.Target {

	case "cupboards":
		useTaie, _ := c.Get("useTaie")
		useShop, _ := c.Get("useShop")
		useLight, _ := c.Get("useLight")

		console := []string{}

		if useTaie.(bool) {
			// "转盘",
			// , "快爆小游戏"
			console = append(console, []string{"实", "虚", "转盘v2", "商店抽奖"}...)
		}

		if useShop.(bool) {
			console = append(console, []string{"玉米农场"}...)
		}

		if useLight.(bool) {
			console = append(console, "亮评")
		}

		console = append(console, "退出")

		dataToEncrypt = console

	case "leave":
		switch reqBody.Param {
		case "sign":
			dataToEncrypt = []string{"获取并添加所有转盘信息", "添加单个转盘(暂不可用)", "删除单个转盘", "删除随机数量转盘", "领取所有转盘次数", "现在抽", "凌晨零点抽", "凌晨一点抽", "凌晨两点抽", "凌晨三点抽", "返回上一级"}
		// Add other sub-menus here as needed.
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown module parameter"})
			return
		}

	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "Unknown target"})
		return
	}

	c.Set("dataToEncrypt", dataToEncrypt)
}

func handleLucy(c *gin.Context) {

	var reqBody struct {
		Target string   `json:"target"`
		Param  string   `json:"p,omitempty"`      // Optional parameter
		Params []string `json:"params,omitempty"` // New field for variable-length string array parameters
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var dataToEncrypt any

	// The "target" field determines what to fetch.
	// All target codes are intentionally obfuscated.
	switch reqBody.Target {

	// 实
	case "sd":
		dataToEncrypt = []string{
			"https://shop.3839.com/index.php?c=DetailInkind&a=choose",
			"https://shop.3839.com/index.php?c=OrderInkind&a=checkOrder",
			"https://shop.3839.com/index.php?c=OrderInkind&a=createOrder",
		}

	// 虚
	case "gb":
		dataToEncrypt = []string{
			"https://shop.3839.com/index.php?c=DetailVirtual&a=choose",
			"https://shop.3839.com/index.php?c=OrderVirtual&a=checkOrder",
			"https://shop.3839.com/index.php?c=OrderVirtual&a=createOrder",
		}

	case "dg":
		dataToEncrypt = map[string]struct {
			ID string `json:"id"`
			LK string `json:"lk"`
		}{}

	case "pp":
		dataToEncrypt = map[string]struct {
			ID string `json:"id"`
			LK string `json:"lk"`
		}{
			"异环月卡（爆布斯专属）": {
				ID: "14780",
				LK: "https://shop.3839.com?id=14780&imm=1",
			},
			"异环6元充值助力金": {
				ID: "14776",
				LK: "https://shop.3839.com?id=14776&imm=1",
			},
			"火影忍者月卡(新人专属)": {
				ID: "6429",
				LK: "https://shop.3839.com/?id=6429&imm=1",
			},
			"王者荣耀188战令进阶卡(新人专属)": {
				ID: "13211",
				LK: "https://shop.3839.com/?id=13211&imm=1",
			},
			"火影忍者秘藏忍法帖(新人专属)": {
				ID: "6428",
				LK: "https://shop.3839.com/?id=6428&imm=1",
			},
			"王者荣耀288点券皮肤(新人专属)": {
				ID: "4653",
				LK: "https://shop.3839.com/?id=4653&imm=1",
			},
			"使命召唤手游使命手册普通版": {
				ID: "4266",
				LK: "https://shop.3839.com/?id=4266&imm=1",
			},
			"火影忍者月卡": {
				ID: "6408",
				LK: "https://shop.3839.com/?id=6408&imm=1",
			},
			"王者荣耀188战令进阶卡": {
				ID: "13210",
				LK: "https://shop.3839.com/?id=13210&imm=1",
			},
			"火影忍者秘藏忍法帖": {
				ID: "6409",
				LK: "https://shop.3839.com/?id=6409&imm=1",
			},
			"5Q币": {
				ID: "12987",
				LK: "https://shop.3839.com/?id=12987&imm=1",
			},
			"5Q币(老爆er专属)": {
				ID: "12989",
				LK: "https://shop.3839.com/?id=12989&imm=1",
			},
			"5Q币（老爆er lv5专属）": {
				ID: "12990",
				LK: "https://shop.3839.com/?id=12990&imm=1",
			},
			"5Q币（老爆er lv6专属）": {
				ID: "12991",
				LK: "https://shop.3839.com/?id=12991&imm=1",
			},
			"15Q币": {
				ID: "12993",
				LK: "https://shop.3839.com/?id=12993&imm=1",
			},
			"15Q币(老爆er专属)": {
				ID: "12994",
				LK: "https://shop.3839.com/?id=12994&imm=1",
			},
			"15Q币（老爆er lv5专属）": {
				ID: "12995",
				LK: "https://shop.3839.com/?id=12995&imm=1",
			},
			"15Q币（老爆er lv6专属）": {
				ID: "12996",
				LK: "https://shop.3839.com/?id=12996&imm=1",
			},
			"30Q币": {
				ID: "12998",
				LK: "https://shop.3839.com/?id=12998&imm=1",
			},
			"30Q币(老爆er专属)": {
				ID: "12999",
				LK: "https://shop.3839.com/?id=12999&imm=1",
			},
			"30Q币（老爆er lv5专属）": {
				ID: "13000",
				LK: "https://shop.3839.com/?id=13000&imm=1",
			},
		}

	case "love":
		dataToEncrypt = `<div
    style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px; color: #1e293b;">
    <div
        style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div style="flex: 1 1 250px; min-width: 200px; margin-bottom: 16px;">
            <h1 style="font-size: 24px; font-weight: bold; margin: 0;">玉米农场数据统计 📊</h1>
            <p style="margin: 4px 0 0 0; color: #64748b;">您的爆米花获取情况分析</p>
        </div>
        <div style="display: flex; flex: 0 0 auto;">
            <img src="{{.User.Result.Data.BaseInfo.Avatar}}" alt="avatar"
                style="width: 48px; height: 48px; border-radius: 50%; margin-right: 10px;">
            <div style="display: flex;align-items: start;flex-direction: column;justify-content: space-around;">
                <div><b>{{.User.Result.Data.BaseInfo.NickName}}</b></div>
                <img src="{{.User.Result.Data.BaseInfo.UserAchievement.ShowCollect.Icon}}" alt="icon"
                    style="height: 16px !important; display: inline-block;">
            </div>
        </div>
    </div>
    <div
        style="background: #fff; border-radius: 20px; box-shadow: 0 6px 16px rgba(0,0,0,0.06); padding: 28px; margin-bottom: 28px;">
        <p style="font-size: 18px; font-weight: 600; margin: 0 0 6px 0;">🍿 当前爆米花</p>
        <p style="font-size: 34px; font-weight: 700; margin: 0 0 20px 0; line-height: 1;">{{comma .Ecd.PopcornTotal}}
        </p>
        <div style="height:1px;background:#e2e8f0;margin:24px 0;"></div>
        <p style="font-size: 18px; font-weight: 600; margin: 0 0 18px 0;">📈 本次统计详情</p>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">完成任务数量</div>
                <div style="font-size:20px;font-weight:700;">{{.Ecd.TaskNum}}</div>
            </div>
            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次获得成熟度</div>
                <div style="font-size:20px;font-weight:700;">{{.Ecd.CsdGained}}</div>
            </div>
            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次获得玉米</div>
                <div style="font-size:20px;font-weight:700;">{{.Ecd.CornGained}}</div>
            </div>
            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次额外爆米花</div>
                <div style="font-size:20px;font-weight:700;">{{.Ecd.PopcornGained}}</div>
            </div>
        </div>
    </div>
    <p style="text-align: center; font-size: 12px; color: #94a3b8;">数据统计时间：{{.Ecd.GeneratedAt}}</p>
</div>`
	case "face":
		dataToEncrypt = `<div
    style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px; color: #1e293b;">
    <div
        style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div style="flex: 1 1 250px; min-width: 200px; margin-bottom: 16px;">
            <h1 style="font-size: 24px; font-weight: bold; margin: 0;">转盘数据统计 📊</h1>
            <p style="margin: 4px 0 0 0; color: #64748b;">您的爆米花获取情况分析</p>
        </div>
        <div style="display: flex; flex: 0 0 auto;">
            <img src="{{.User.Result.Data.BaseInfo.Avatar}}" alt="avatar"
                style="width: 48px; height: 48px; border-radius: 50%; margin-right: 10px;">
            <div style="display: flex;align-items: start;flex-direction: column;justify-content: space-around;">
                <div><b>{{.User.Result.Data.BaseInfo.NickName}}</b></div>
                <img src="{{.User.Result.Data.BaseInfo.UserAchievement.ShowCollect.Icon}}" alt="icon"
                    style="height: 16px !important; display: inline-block;">
            </div>
        </div>
    </div>
    <!-- 统计卡片 -->
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">🍿 当前爆米花</p>
        <p style="font-size: 28px; font-weight: bold;">{{comma .Ed.PopcornTotal}}</p>
    </div>
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">🎰 本次获取的转盘数</p>
        <p style="font-size: 28px; font-weight: bold;">{{.Ed.RoundCount}}</p>
    </div>
	<div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">🎰 本次抽取的转盘数</p>
        <p style="font-size: 28px; font-weight: bold;">{{.Ed.RealRoundCount}}</p>
    </div>
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">+ 本次获得的爆米花</p>
        <p style="font-size: 28px; font-weight: bold;">{{.Ed.PopcornGained}}</p>
    </div>
    <!-- 抽取分析 -->
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">📈 抽取分析</p>
        <p style="color: #6b7280;">抽取次数</p>
        <p style="font-weight: bold;">{{.Ed.DrawCount}}</p>
        <p style="color: #6b7280;">平均获得的爆米花</p>
        <p style="font-weight: bold;">{{printf "%.2f" .Ed.AveragePerDraw}}</p>
        <p style="color: #6b7280;">耗费时间</p>
        <p style="font-weight: bold;">{{.Ed.DurationMinutes}} 分钟</p>
    </div>
    {{if .Ed.Rewards}}
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <p style="font-size: 16px; font-weight: bold;">🎁 额外获得奖品</p>
        {{range .Ed.Rewards}}
        <div style="margin-bottom: 10px; background: #faf5ff; padding: 10px; border-radius: 10px;">
            <p style="margin: 0;"><strong>{{.Name}}</strong><br><span style="font-size: 12px; color: #6b7280;">来源:
                    {{.Source}}</span></p>
        </div>
        {{end}}
    </div>
    {{else}}
    <div
        style="background: #fff; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px;">
        <div style="padding: 32px; text-align: center;">
            <div
                style="width: 64px; height: 64px; margin: 0 auto 16px; border-radius: 50%; background-color: #f3f4f6; color: #9ca3af; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                🎁
            </div>
            <h4 style="font-size: 18px; font-weight: 500; color: #4b5563; margin-bottom: 4px;">本次未含有额外奖品</h4>
            <p style="font-size: 14px; color: #6b7280;">继续参与活动有机会获得更多奖励</p>
        </div>
    </div>
    {{end}}
    <p style="text-align: center; font-size: 12px; color: #94a3b8;">数据统计时间：{{.Ed.GeneratedAt}}</p>
</div>`
	case "fade":
		dataToEncrypt = `<div
    style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px; color: #1e293b;">
    <div
        style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div style="flex: 1 1 250px; min-width: 200px; margin-bottom: 16px;">
            <h1 style="font-size: 24px; font-weight: bold; margin: 0;">小游戏数据统计 📊</h1>
            <p style="margin: 4px 0 0 0; color: #64748b;">小游戏收益情况分析</p>
        </div>
        <div style="display: flex; flex: 0 0 auto;">
            <img src="{{.User.Result.Data.BaseInfo.Avatar}}" alt="avatar"
                style="width: 48px; height: 48px; border-radius: 50%; margin-right: 10px;">
            <div style="display: flex;align-items: start;flex-direction: column;justify-content: space-around;">
                <div><b>{{.User.Result.Data.BaseInfo.NickName}}</b></div>
                <img src="{{.User.Result.Data.BaseInfo.UserAchievement.ShowCollect.Icon}}" alt="icon"
                    style="height: 16px !important; display: inline-block;">
            </div>
        </div>
    </div>
    <div
        style="background: #fff; border-radius: 20px; box-shadow: 0 6px 16px rgba(0,0,0,0.06); padding: 28px; margin-bottom: 28px;">

        <p style="font-size: 18px; font-weight: 600; margin: 0 0 6px 0;">🍿 当前爆米花</p>
        <p style="font-size: 34px; font-weight: 700; margin: 0 0 20px 0; line-height: 1;">{{comma .Egd.PopcornTotal}}
        </p>

        <div style="height:1px;background:#e2e8f0;margin:24px 0;"></div>

        <p style="font-size: 18px; font-weight: 600; margin: 0 0 18px 0;">📈 本次统计详情</p>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">

            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">游玩数量</div>
                <div style="font-size:20px;font-weight:700;">{{.Egd.GameNum}}</div>
            </div>

            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次获得金坷垃</div>
                <div style="font-size:20px;font-weight:700;">{{.Egd.JklGained}}</div>
            </div>

            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次获得成熟度</div>
                <div style="font-size:20px;font-weight:700;">{{.Egd.CsdGained}}</div>
            </div>

            <div style="background:#f8fafc; border-radius:12px; padding:14px 16px;">
                <div style="font-size:13px;color:#64748b;margin-bottom:4px;">本次额外爆米花</div>
                <div style="font-size:20px;font-weight:700;">{{.Egd.PopcornGained}}</div>
            </div>

        </div>
    </div>
    <p style="text-align: center; font-size: 12px; color: #94a3b8;">数据统计时间：{{.Egd.GeneratedAt}}</p>
</div>`
	// Fetches the remote configuration URLs for the client.
	case "evening":
		dataToEncrypt = map[string]string{
			"universal": universalUrl,
			"wanneng":   wannengUrl,
		}
	// Fetches the remote farm configuration Extract for the client.
	case "sitting":
		switch reqBody.Param {
		case "reading":
			dataToEncrypt = extractRe
		case "lines":
			dataToEncrypt = extractS
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown module parameter"})
			return
		}
	// Fetches the remote farm configuration URLs for the client.
	case "time":
		dataToEncrypt = farmUrls
	// Fetches the gameUrls for client.
	case "reason":
		dataToEncrypt = gameUrls
	// Fetches the GameParams for client.
	case "really":
		dataToEncrypt = gameParams
	// Fetches a secret key/value pair for client-side use.
	case "oh":
		dataToEncrypt = map[string]string{
			"key":   clientSecretKey,
			"value": clientSecretValue,
		}
	// Processes a map of parameters and returns its sorted keys plus "secret".
	case "tell":
		if reqBody.Params == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'params' in request body for target 'g7'"})
			return
		}
		keys := make([]string, 0, len(reqBody.Params)+1)
		keys = append(keys, reqBody.Params...)
		keys = append(keys, "secret")
		sort.Strings(keys)
		dataToEncrypt = keys
	// Fetches another secret string.
	case "going":
		dataToEncrypt = anotherSecretString
	// Fetches act, onclick query string.
	case "stay":
		dataToEncrypt = actOnClickString
	// Fetches pageToken, pageRandomStr, xiaoyouxiInfo string.
	case "compromise":
		dataToEncrypt = []string{pageTokenString, pageRandomStrString, xiaoyouxiInfoString}
	// Fetches getVarJsonValue Regexp string.
	case "know":
		dataToEncrypt = []string{getVarJsonValueUnQuoted}
	// Fetches getVarValue Regexp string.
	case "control":
		dataToEncrypt = []string{getVarValueQuoted, getVarValueUnQuoted}
	// Fetches and processes external round data.
	case "point":
		var roundType string
		// The "p" (param) field identifies the round type.
		switch reqBody.Param {
		// p="u1" corresponds to the "universal" type.
		case "of":
			roundType = "universal"
		// p="w1" corresponds to the "wanneng" type.
		case "view":
			roundType = "wanneng"
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown round parameter"})
			return
		}

		validRounds, err := GetRound(roundType)
		if err != nil {
			// Log the detailed error on the server, but return a generic error to the client.
			log.Printf("GetRound failed for type '%s': %v", roundType, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process round data"})
			return
		}
		dataToEncrypt = validRounds
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "Unknown target"})
		return
	}

	c.Set("dataToEncrypt", dataToEncrypt)
}

func handleDavid(c *gin.Context) {

	var reqBody struct {
		Target string   `json:"target"`
		Param  string   `json:"p,omitempty"`      // Optional parameter
		Params []string `json:"params,omitempty"` // New field for variable-length string array parameters
	}

	if err := c.ShouldBindJSON(&reqBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var dataToEncrypt any

	switch reqBody.Target {
	case "feature":
		dataToEncrypt = `<div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px; color: #1e293b;">
    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div style="flex: 1 1 250px; min-width: 200px; margin-bottom: 16px;">
            <h1 style="font-size: 24px; font-weight: bold; margin: 0;">奖券获取数据统计 📊</h1>
            <p style="margin: 4px 0 0 0; color: #64748b;">奖券获取结果详情</p>
        </div>
        <div style="display: flex; flex: 0 0 auto;">
            <img src="{{.User.Result.Data.BaseInfo.Avatar}}" alt="avatar"
                style="width: 48px; height: 48px; border-radius: 50%; margin-right: 10px; object-fit: cover;">
            <div style="display: flex;align-items: start;flex-direction: column;justify-content: space-around;">
                <div><b>{{.User.Result.Data.BaseInfo.NickName}}</b></div>
                <img src="{{.User.Result.Data.BaseInfo.UserAchievement.ShowCollect.Icon}}" alt="icon"
                    style="height: 16px !important; display: inline-block;">
            </div>
        </div>
    </div>
    <div style="background: #fff; border-radius: 20px; box-shadow: 0 6px 16px rgba(0,0,0,0.06); padding: 22px; margin-bottom: 16px;">
		<div style="display: flex; flex-direction: column; gap: 12px;">
			{{range .Eld.LD}}
			<div style="display: flex; align-items: center; background: #f8fafc; border-radius: 12px; padding: 12px;">
				<div style="width: 50px; height: 50px; margin-right: 12px; flex-shrink: 0; display: flex; align-items: center; justify-content: center;">
					<img src="https:{{.Pic}}" alt="{{.Name}}" 
						style="max-width: 100%; max-height: 100%; object-fit: contain; border-radius: 6px;">
				</div>
				<div style="flex: 1; min-width: 0;">
					<div style="font-size: 16px; font-weight: 600; word-wrap: break-word; line-height: 1.4;">{{.Name}}</div>
				</div>
				<div style="font-size: 18px; font-weight: 700; color: #3b82f6; flex-shrink: 0; margin-left: 10px;">x{{.Num}}</div>
			</div>
			{{end}}
		</div>
    </div>
    <p style="text-align: center; font-size: 12px; color: #94a3b8;">数据统计时间：{{.Eld.GeneratedAt}}</p>
</div>`
	case "house":
		dataToEncrypt = []string{"LotteryTask", "receivePrize"}
	case "handshake":
		validLottery, err := GetLottery()
		if err != nil {
			log.Printf("GetLottery failed for: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process lottery data"})
			return
		}
		dataToEncrypt = validLottery
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "Unknown target"})
		return
	}

	c.Set("dataToEncrypt", dataToEncrypt)
}

// getNextTaskHandler handles the request for a new task.
func getNextTaskHandler(c *gin.Context) {
	taskID, err := getNextTaskID()
	if err != nil {
		log.Printf("获取任务失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get a new task"})
		return
	}

	if taskID == "" {
		c.JSON(http.StatusOK, gin.H{"message": "No more tasks available"})
		return
	}

	key, _ := c.Get("longTermKey")
	log.Println(taskID, "被", key, "取走")
	c.JSON(http.StatusOK, gin.H{"task_id": taskID})
}

// submitTaskHandler handles the submission of task results.
func submitTaskHandler(c *gin.Context) {
	// We need a wrapper struct because the task_id is not part of the ActivityResp
	var submission struct {
		TaskID string       `json:"task_id"`
		Data   ActivityResp `json:"data"`
	}

	if err := c.ShouldBindJSON(&submission); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if submission.TaskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task_id is required"})
		return
	}

	if err := saveActivityResult(submission.Data, submission.TaskID); err != nil {
		log.Printf("保存任务 %s 结果失败: %v", submission.TaskID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save task result"})
		return
	}

	key, _ := c.Get("longTermKey")
	log.Println(submission.TaskID, "被", key, "提交")
	c.JSON(http.StatusOK, gin.H{"message": "Task result submitted successfully"})
}

// 获取活动
func getActivitiesHandler(c *gin.Context) {
	statusStr := c.Query("status")
	if statusStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status parameter is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "5")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit parameter"})
		return
	}

	if limit > 10 {
		limit = 10
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid offset parameter"})
		return
	}

	var activities []Activity

	switch statusStr {
	case "opened":
		activities, err = getActivitiesOpened(limit, offset)
	case "closed":
		activities, err = getActivitiesClosed(limit, offset)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status parameter"})
		return
	}
	if err != nil {
		log.Printf("获取活动列表失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve activities"})
		return
	}

	c.Set("dataToEncrypt", activities)
}

// 为用户添加活动
func addUserActivityHandler(c *gin.Context) {
	aidStr := c.Query("aid")
	if aidStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "aid parameter is required"})
		return
	}
	aid, err := strconv.Atoi(aidStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "aid parameter is wrong"})
		return
	}
	key, _ := c.Get("longTermKey")
	err = addUserActivity(key.(string), aid)

	if err != nil {
		log.Printf("%v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "log can't save"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"error": ""})
}

// 用户所有参与的活动 (整型数组)
func getUserActivitiesIntsHandler(c *gin.Context) {
	key, _ := c.Get("longTermKey")
	activities, err := getUserActivitiesInts(key.(string))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "get activities error"})
		return
	}
	c.JSON(http.StatusOK, activities)
}

// 根据关键词搜索活动
func searchActivitiesHandler(c *gin.Context) {
	keyword := c.Query("kw")
	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kw is required"})
		return
	}

	status := c.Query("status")
	if status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "5")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit parameter"})
		return
	}

	if limit > 10 {
		limit = 10
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid offset parameter"})
		return
	}

	var activities []Activity

	switch status {
	case "opened":
		activities, err = searchActivitiesOpened(keyword, limit, offset)
	case "ended":
		activities, err = searchActivitiesClosed(keyword, limit, offset)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status parameter"})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "some bad things happen!"})
	}
	c.Set("dataToEncrypt", activities)
}

// 获取用户参与的活动
func getUserActivitiesHandler(c *gin.Context) {
	key, exists := c.Get("longTermKey")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户未认证"})
		return
	}
	userKey := key.(string)

	status := c.Query("status")
	if status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "5")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit parameter"})
		return
	}

	if limit > 10 {
		limit = 10
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid offset parameter"})
		return
	}

	var activities []Activity

	switch status {
	case "opened":
		activities, err = getUserActivitiesOpened(userKey, limit, offset)
	case "ended":
		activities, err = getUserActivitiesClosed(userKey, limit, offset)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status parameter"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户活动失败: " + err.Error()})
		return
	}

	c.Set("dataToEncrypt", activities)
}

func loadSearchCache(c *gin.Context) {
	var req SearchRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameters: " + err.Error(),
		})
		return
	}

	var allResults []GameBasicInfo

	for _, platform := range req.Platforms {
		cacheKey := fmt.Sprintf("search:%s:%s", req.Keyword, platform)
		if results, found := getSearchCache(cacheKey); found {
			allResults = append(allResults, results...)
		}
	}

	c.JSON(http.StatusOK, allResults)
}

func submitSearchCache(c *gin.Context) {
	keyword := c.Query("keyword")
	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameter: keyword",
		})
		return
	}

	var req struct {
		Data map[string][]GameBasicInfo `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid cache data: " + err.Error(),
		})
		return
	}

	if len(req.Data) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Data cannot be empty",
		})
		return
	}

	successCount := 0
	for platform, gameData := range req.Data {
		if len(gameData) == 0 {
			continue // 跳过空数据
		}

		cacheKey := fmt.Sprintf("search:%s:%s", keyword, platform)
		if err := setSearchCache(cacheKey, gameData); err == nil {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Cache submitted successfully",
		"successCount":   successCount,
		"totalPlatforms": len(req.Data),
	})
}

// submitGradlewJob 提交构建应用包请求
func submitGradlewJob(c *gin.Context) {
	var apkInfo ApkInfo
	if err := c.ShouldBindQuery(&apkInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameters",
		})
		return
	}

	status := getGradlewJobStatus(apkInfo)
	if status == "SUCCESS" || status == "WAITING" || status == "BUILDING" || status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{
			"status": status,
		})
		return
	}

	if err := addGradlewJob(apkInfo); err != nil {
		log.Printf("添加 gradlew 任务失败: %v", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Adding job faily",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func downloadApk(c *gin.Context) {
	var apkInfo ApkInfo
	if err := c.ShouldBindQuery(&apkInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameters",
		})
		return
	}

	status := getGradlewJobStatus(apkInfo)
	log.Println(status)
	if status != "SUCCESS" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no ready",
		})
		return
	}

	url := getAPKPath(apkInfo)
	if url == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "something wrong"})
		return
	}

	// 下载远程 APK（流方式）
	resp, err := http.Get(url)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "download failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream error"})
		return
	}

	// 取得文件名（含中文）
	fileName := filepath.Base(url)

	// 设置下载头
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))

	// 内容长度（如果上游返回）
	if resp.ContentLength > 0 {
		c.Header("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}

	// 将远程内容直接流给客户端
	io.Copy(c.Writer, resp.Body)
}

func OperationsProxy(proxy gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Params = append(c.Params, gin.Param{
			Key:   "path",
			Value: "/operations",
		})
		proxy(c)
	}
}

func OperationAppsProxy(proxy gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := "/operations/" + c.Param("operation_id") + "/apps"

		c.Params = append(c.Params, gin.Param{
			Key:   "path",
			Value: path,
		})
		proxy(c)
	}
}

func TapStockProxy(proxy gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := "/stock/" + c.Param("lottery_id")

		c.Params = append(c.Params, gin.Param{
			Key:   "path",
			Value: path,
		})
		proxy(c)
	}
}

// 4399 游戏盒
func searchBoxActs(c *gin.Context) {
	keyword := c.Query("kw")
	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kw is required"})
		return
	}

	u, err := url.Parse(keyword)
	if err != nil || u.Scheme == "" || u.Host == "" {
		hds := getBoxFilter(keyword)
		var ssi []SubscribeInfo
		for _, hd := range hds {
			log.Println("搜索所获得的链接", hd.CUrl)
			u, _ := url.Parse(hd.CUrl)
			tag := u.Query().Get("hd")
			ssi = append(ssi, getBoxPrizeAndWinnerList(tag))
		}
		if len(ssi) == 0 {
			c.JSON(http.StatusOK, []SubscribeInfo{})
			return
		}
		c.JSON(http.StatusOK, ssi)
		return
	}

	var ssi []SubscribeInfo
	tag := u.Query().Get("hd")
	ssi = append(ssi, getBoxPrizeAndWinnerList(tag))
	c.JSON(http.StatusOK, ssi)
}

// 4399 游戏盒
