package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"vuln-info-backend/service/core"
)

func RunParser(c *gin.Context) {

	core.CheckFeed(core.GetRSSLink())

	c.JSON(http.StatusOK, gin.H{"data": "ok"})

}

func CheckCPEs(c *gin.Context) {

	from, fromExists := c.GetQuery("from")
	to, toExists := c.GetQuery("to")

	if fromExists && toExists {

		fromInt, err1 := strconv.Atoi(from)
		toInt, err2 := strconv.Atoi(to)

		if err1 != nil || err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": "Invalid Parameters"})
			return
		}
		if fromInt > 0 || toInt > -1 {
			c.JSON(http.StatusBadRequest, gin.H{"data": "from must be < 1; to must be < 0"})
			return
		}
		core.MatchCPEs(fromInt, toInt)
		c.JSON(http.StatusOK, gin.H{"data": "ok"})

	} else {
		core.MatchCPEs(0, -7)

		c.JSON(http.StatusOK, gin.H{"data": "ok"})

	}

}
