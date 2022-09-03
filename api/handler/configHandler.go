package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"vuln-info-backend/service/core"
)

// RunParser godoc
// @summary Fetch RSS
// @description Fetches the RSS Feed and runs the Parser, if new entries are available.
// @tags Config
// @Security ApiKeyAuth
// @response 200 {string} string "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /config/rss [get]
func RunParser(c *gin.Context) {

	core.CheckFeed(core.GetRSSLink())

	c.JSON(http.StatusOK, "ok")

}

// CheckCPEs godoc
// @summary Check components for vulnerabilities
// @description Checks the components against vulnerabilities for a given time period.
// @description E.g.: '.../match?from=0?to=-10' covers Notifications created between today and 10 days ago.
// @tags Config
// @Security ApiKeyAuth
// @Param    from    query     int  true  "From days back: '0' = today. Must be < 1."
// @Param    to    query     int  true  "To days back. Must be < 0."
// @response 200 {string} string "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /config/match [get]
func CheckCPEs(c *gin.Context) {

	from, fromExists := c.GetQuery("from")
	to, toExists := c.GetQuery("to")

	if fromExists && toExists {

		fromInt, err1 := strconv.Atoi(from)
		toInt, err2 := strconv.Atoi(to)

		if err1 != nil || err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Parameters"})
			return
		}
		if fromInt > 0 || toInt > -1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "from must be < 1; to must be < 0"})
			return
		}
		core.MatchCPEs(fromInt, toInt)
		c.JSON(http.StatusOK, "ok")

	} else {
		core.MatchCPEs(0, -7)

		c.JSON(http.StatusOK, "ok")

	}

}
