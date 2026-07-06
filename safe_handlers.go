package main

import (
	"encoding/base64"
	"log"
	"net/url"

	"github.com/gin-gonic/gin"
)

func logSubmit(c *gin.Context) {
	key, _ := c.Get("longTermKey")
	info := c.GetHeader("X-Info")

	log_content, _ := base64.StdEncoding.DecodeString(info)
	decoded, _ := url.QueryUnescape(string(log_content))
	log.Println(key, ":", decoded)
}
