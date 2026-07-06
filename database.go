package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func initDB() {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		postgresUser,
		postgresPassword,
		postgresHost,
		postgresPort,
		postgresDbname)

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("无法连接到 PostgreSQL: %v", err)
	}

	dbPool = pool
	log.Println("成功连接到 PostgreSQL 数据库")

	// 自动创建表和索引
	if err := setupSchema(); err != nil {
		log.Fatalf("数据库 schema 初始化失败: %v", err)
	}
}

func setupSchema() error {
	tables := map[string]string{
		"activity_results": `
			CREATE TABLE IF NOT EXISTS activity_results (
				id SERIAL PRIMARY KEY,
				activity_id INT UNIQUE,
				article_id BIGINT,
				awards JSONB,
				conditions JSONB,
				title TEXT,
				link_title TEXT,
				game_name TEXT,
				author_name TEXT,
				cover TEXT,
				draw_time TIMESTAMPTZ,
				publish_time TIMESTAMPTZ,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);`,
		"user_activities": `
			CREATE TABLE IF NOT EXISTS user_activities (
				id SERIAL PRIMARY KEY,
				user_key VARCHAR(32) NOT NULL,         -- 用户KEY，32位长度
				activity_id INT NOT NULL,              -- 活动ID
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				UNIQUE(user_key, activity_id)          -- 防止重复关系
			);`,
		"user_records": `
			CREATE TABLE IF NOT EXISTS user_records (
				id SERIAL PRIMARY KEY,
				user_key VARCHAR(32) NOT NULL,
				tap_uid BIGINT NOT NULL,
				tap_name TEXT,
				tap_avatar TEXT,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				UNIQUE(user_key, tap_uid)
			);`,
		"tap_user_records": `
			CREATE TABLE IF NOT EXISTS tap_user_records (
				id SERIAL PRIMARY KEY,
				tap_uid BIGINT NOT NULL,
				article_id BIGINT NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				UNIQUE(tap_uid, article_id)
			);`,
	}

	// 创建所有表
	for tableName, sql := range tables {
		_, err := dbPool.Exec(context.Background(), sql)
		if err != nil {
			return fmt.Errorf("创建 %s 表失败: %w", tableName, err)
		}
		log.Printf("表 %s 创建/检查完成", tableName)
	}

	// 创建索引
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_activity_results_draw_time ON activity_results (draw_time);`,
		`CREATE INDEX IF NOT EXISTS idx_user_activities_user_key ON user_activities (user_key);`,
		`CREATE INDEX IF NOT EXISTS idx_user_activities_activity_id ON user_activities (activity_id);`,
		`CREATE INDEX IF NOT EXISTS idx_user_activities_created_at ON user_activities (created_at);`,

		// 新增的搜索相关索引
		`CREATE EXTENSION IF NOT EXISTS pg_trgm;`, // 确保启用trigram扩展

		// 为title字段添加GIN索引（支持模糊搜索）
		`CREATE INDEX IF NOT EXISTS idx_activity_results_title_gin ON activity_results USING gin (title gin_trgm_ops);`,

		// 为link_title字段添加GIN索引
		`CREATE INDEX IF NOT EXISTS idx_activity_results_link_title_gin ON activity_results USING gin (link_title gin_trgm_ops);`,

		// 新增 user_tap 索引
		`CREATE INDEX IF NOT EXISTS idx_user_records_tap_uid ON user_records (tap_uid);`,
		`CREATE INDEX IF NOT EXISTS idx_tap_user_records_tap_uid ON tap_user_records (tap_uid);`,
		`CREATE INDEX IF NOT EXISTS idx_tap_user_records_article_id ON tap_user_records (article_id);`,
	}

	for _, sql := range indexes {
		_, err := dbPool.Exec(context.Background(), sql)
		if err != nil {
			return fmt.Errorf("创建索引失败: %w", err)
		}
	}

	log.Println("数据库 schema 初始化完成，所有表和索引已就绪。")
	return nil
}

func closeDB() {
	if dbPool != nil {
		dbPool.Close()
		log.Println("数据库连接已关闭")
	}
}

func getActivitiesOpened(limit, offset int) ([]Activity, error) {
	now := time.Now()
	year, month, day := now.Date()
	TodayOfDay := time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	endOfDay := TodayOfDay.AddDate(0, 0, 21)

	query := `
		SELECT activity_id, article_id::text as article_id, awards, conditions, title, link_title, game_name, author_name, cover, draw_time, publish_time
		FROM activity_results
		WHERE draw_time >= $1 AND draw_time < $2
		ORDER BY draw_time ASC
		LIMIT $3 OFFSET $4
	`

	rows, err := dbPool.Query(context.Background(), query, now, endOfDay, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions, &act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover, &act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}

func getActivitiesClosed(limit, offset int) ([]Activity, error) {
	now := time.Now()
	year, month, day := now.Date()
	TodayOfDay := time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	startOfDay := TodayOfDay.AddDate(0, 0, -7)

	query := `
		SELECT activity_id, article_id::text as article_id, awards, conditions, title, link_title, game_name, author_name, cover, draw_time, publish_time
		FROM activity_results
		WHERE draw_time >= $1 AND draw_time < $2
		ORDER BY draw_time DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := dbPool.Query(context.Background(), query, startOfDay, now, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions, &act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover, &act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}

func searchActivitiesOpened(keyword string, limit, offset int) ([]Activity, error) {
	now := time.Now()

	query := `
        SELECT activity_id, article_id::text as article_id, awards, conditions, title, link_title, game_name, author_name, cover, draw_time, publish_time
        FROM activity_results
        WHERE (title ILIKE $1 
           OR link_title ILIKE $1 
           OR awards::text ILIKE $1)
		   AND draw_time > $2
        ORDER BY draw_time ASC
        LIMIT $3 OFFSET $4
    `

	searchPattern := "%" + keyword + "%"

	rows, err := dbPool.Query(context.Background(), query, searchPattern, now, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("搜索活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions, &act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover, &act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}

func searchActivitiesClosed(keyword string, limit, offset int) ([]Activity, error) {
	now := time.Now()

	query := `
        SELECT activity_id, article_id::text as article_id, awards, conditions, title, link_title, game_name, author_name, cover, draw_time, publish_time
        FROM activity_results
        WHERE (title ILIKE $1 
           OR link_title ILIKE $1 
           OR awards::text ILIKE $1)
		   AND draw_time < $2
        ORDER BY draw_time DESC
        LIMIT $3 OFFSET $4
    `

	searchPattern := "%" + keyword + "%"

	rows, err := dbPool.Query(context.Background(), query, searchPattern, now, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("搜索活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions, &act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover, &act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}

// 获取用户参与的未开奖活动
func getUserActivitiesOpened(userKey string, limit, offset int) ([]Activity, error) {
	now := time.Now()

	query := `
		SELECT ar.activity_id, ar.article_id::text as article_id, ar.awards, ar.conditions, 
		       ar.title, ar.link_title, ar.game_name, ar.author_name, ar.cover, 
		       ar.draw_time, ar.publish_time
		FROM activity_results ar
		INNER JOIN user_activities ua ON ar.activity_id = ua.activity_id
		WHERE ua.user_key = $1 
		  AND ar.draw_time > $2
		ORDER BY ar.draw_time ASC
		LIMIT $3 OFFSET $4
	`

	rows, err := dbPool.Query(context.Background(), query, userKey, now, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询用户未开奖活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions,
			&act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover,
			&act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}

// 获取用户参与的已开奖活动
func getUserActivitiesClosed(userKey string, limit, offset int) ([]Activity, error) {
	now := time.Now()

	query := `
		SELECT ar.activity_id, ar.article_id::text as article_id, ar.awards, ar.conditions, 
		       ar.title, ar.link_title, ar.game_name, ar.author_name, ar.cover, 
		       ar.draw_time, ar.publish_time
		FROM activity_results ar
		INNER JOIN user_activities ua ON ar.activity_id = ua.activity_id
		WHERE ua.user_key = $1 
		  AND ar.draw_time < $2
		ORDER BY ar.draw_time DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := dbPool.Query(context.Background(), query, userKey, now, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询用户已开奖活动失败: %w", err)
	}
	defer rows.Close()

	var activities []Activity
	for rows.Next() {
		var act Activity
		if err := rows.Scan(&act.ActivityID, &act.ArticleID, &act.Awards, &act.Conditions,
			&act.Title, &act.LinkTitle, &act.GameName, &act.AuthorName, &act.Cover,
			&act.DrawTime, &act.PublishTime); err != nil {
			return nil, fmt.Errorf("扫描活动数据失败: %w", err)
		}
		activities = append(activities, act)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("处理查询结果时出错: %w", rows.Err())
	}

	return activities, nil
}
