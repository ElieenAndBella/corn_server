package main

import (
	"time"

	"github.com/robfig/cron/v3"
)

// CronJobManager 用于集中管理 cron 实例
type CronJobManager struct {
	cron *cron.Cron
}

// NewCronJobManager 创建并返回一个新的 CronJobManager
func NewCronJobManager() *CronJobManager {
	return &CronJobManager{
		cron: cron.New(cron.WithLocation(time.Local)),
	}
}

// Start 开始执行定时任务
func (m *CronJobManager) Start() {
	m.cron.Start()
}

// Stop 停止执行定时任务
func (m *CronJobManager) Stop() {
	m.cron.Stop()
}

// AddTask 添加一个新的定时任务
func (m *CronJobManager) AddTask(schedule string, task func()) (cron.EntryID, error) {
	return m.cron.AddFunc(schedule, task)
}

func (m *CronJobManager) AddTaskWithImmediate(spec string, cmd func()) (cron.EntryID, error) {
	go cmd()
	return m.cron.AddFunc(spec, cmd)
}
