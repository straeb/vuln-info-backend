package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var notification crud.NotificationCRUD

// GetAllNotifications godoc
// @summary Get All notifications
// @description Returns all listed notifications.
// @tags Notifications
// @Security ApiKeyAuth
//@produce json
// @Param    link    query     string  false  "Get notifications for a DFN-Link."
// @Param    cvss_base    query     string  false  "Get all Notifications for a specific CVSS base score."
// @Param    cvss_exploitability    query     string  false  "Get all Notifications for a specific CVSS exploitability score."
// @Param    cvss_impact    query     string  false  "Get all Notifications for a specific CVSS impact score."
// @Param    cvss_temp    query     string  false  "Get all Notifications for a specific CVSS temporal score."
// @Param    cve_id    query     string  false  "Get all Notifications associated with a specific CVE-ID. Will not succeed in combination with 'cve_id' or 'for'."
// @Param    cve    query     boolean  false  "Get all Notifications associated with or without a CVEs. Will not succeed in combination with 'cve' or 'for'."
// @Param    for    query     string  false  "Get all Notifications that match components of a username (e-mail). Will not succeed in combination with 'cve' or 'cve_id'."
// @response 200 {array} models.Notification "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /notifications [get]
func GetAllNotifications(c *gin.Context) {

	input := models.Notification{
		Link:       c.Query("link"),
		CVSSbase:   c.Query("cvss_base"),
		CVSSEx:     c.Query("cvss_exploitability"),
		CVSSimpact: c.Query("cvss_impact"),
		CVSStemp:   c.Query("cvss_temp"),
	}

	cve, cveExists := c.GetQuery("cve")
	cveID, cveIDExists := c.GetQuery("cve_id")
	user, userExists := c.GetQuery("for")

	if cveIDExists {
		notifications, err := notification.GetForCVE(&input, cveID)
		helper.AnswerGetAll(notifications, err, c)

	} else if cveExists {
		if cve == "true" {
			notifications, err := notification.GetWithOrWithoutCVEs(&input, true)
			helper.AnswerGetAll(notifications, err, c)

		} else if cve == "false" {
			notifications, err := notification.GetWithOrWithoutCVEs(&input, false)
			helper.AnswerGetAll(notifications, err, c)
		}

	} else if userExists {
		notifications, err := notification.GetForUser(&input, user)
		helper.AnswerGetAll(notifications, err, c)

	} else {
		notifications, err := notification.GetAll(&input)
		helper.AnswerGetAll(notifications, err, c)

	}

}

// SearchNotification godoc
// @summary Search notifications
// @description Search notifications by title.
// @tags Notifications
// @Security ApiKeyAuth
//@produce json
// @Param    q    query     string  true  "Search notifications by title."
// @response 200 {array} models.Notification "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /notifications/search [get]
func SearchNotification(c *gin.Context) {
	searchQuery, serachExists := c.GetQuery("q")

	if serachExists {
		notifications, err := notification.Search(searchQuery)
		helper.AnswerGetAll(notifications, err, c)
		return

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query not provided"})
	}
}

// GetNotificationById godoc
// @summary Get notification by ID
// @description Returns notification for a specific ID.
// @tags Notifications
// @Security ApiKeyAuth
// @produce json
// @Param        id   path      int  true  "notification ID"
// @response 200 {object} models.Notification "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /notifications/{id} [get]
func GetNotificationById(c *gin.Context) {

	notification, err := notification.GetById(c.Param("id"))
	helper.Answer(notification, err, c)
}
