package handler

import (
	"github.com/gin-gonic/gin"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var notification crud.NotificationCRUD

func GetAllNotifications(c *gin.Context) {

	input := models.Notification{
		Link:       c.Query("link"),
		CVSSbase:   c.Query("cvss_base"),
		CVSSEx:     c.Query("cvss_exploitability"),
		CVSSimpact: c.Query("cvss_impact"),
		CVSStemp:   c.Query("cvss_temp"),
	}

	cve, cveExists := c.GetQuery("cve")
	user, userExists := c.GetQuery("for")
	searchQuery, serachExists := c.GetQuery("search")

	if serachExists {
		notifications, err := notification.Search(&input, searchQuery)
		helper.AnswerGetAll(notifications, err, c)
		return

	}

	if cveExists {
		if cve == "true" {
			notifications, err := notification.GetWithOrWithoutCVEs(&input, true)
			helper.AnswerGetAll(notifications, err, c)

		} else if cve == "false" {
			notifications, err := notification.GetWithOrWithoutCVEs(&input, false)
			helper.AnswerGetAll(notifications, err, c)

		} else {
			notifications, err := notification.GetForCVE(&input, cve)
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

func GetNotificationById(c *gin.Context) {

	notification, err := notification.GetById(c.Param("id"))
	helper.Answer(notification, err, c)
}
