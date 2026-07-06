package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
)

func MD5String(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// proxy 反代
func ReverseProxy(target string) gin.HandlerFunc {
	targetURL, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	return func(c *gin.Context) {
		// 修改请求
		c.Request.URL.Scheme = targetURL.Scheme
		c.Request.URL.Host = targetURL.Host

		// 保留原始路径
		c.Request.URL.Path = c.Param("path")

		// 设置 Host（有些后端会校验）
		c.Request.Host = targetURL.Host

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}
