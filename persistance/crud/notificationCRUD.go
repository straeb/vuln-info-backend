package crud

import (
	"errors"
	"gorm.io/gorm"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"vuln-info-backend/models"
	db "vuln-info-backend/persistance/database"
)

type NotificationCRUD struct{}

var thisNotification NotificationCRUD

var rssLog = log.New(os.Stdout, "[RSS] ", log.Ldate|log.Ltime)

func (NotificationCRUD) GetAll(params *models.Notification) ([]models.Notification, error) {
	var notifications []models.Notification

	if err := db.DB.Model(&notifications).
		Preload("Vulnerabilities").
		Where(&params).
		Find(&notifications).Error; err != nil {
		return nil, db.Errs(err)
	}

	return notifications, nil
}

func (NotificationCRUD) Search(searchQuery string) ([]models.Notification, error) {
	searchQuery = strings.ReplaceAll(searchQuery, "?/\\=;", "")
	var notifications []models.Notification
	if len(searchQuery) > 0 {

		if err := db.DB.Model(&notifications).
			Preload("Vulnerabilities").
			Where("title LIKE ?", "%"+searchQuery+"%").
			Find(&notifications).Error; err != nil {
			return nil, db.Errs(err)
		}
		return notifications, nil
	}
	return notifications, nil
}

func (NotificationCRUD) GetForUser(params *models.Notification, mail string) ([]models.Notification, error) {

	var notifications []models.Notification

	userObj, err := thisUser.GetByMail(mail)
	if err != nil {
		return nil, errors.New("User not found")
	}

	/*
		SELECT *
		FROM notifications
		WHERE notifications.id IN (
		    SELECT notification_id
		    from notification_vulnerabilities
		    WHERE vulnerability_cve_id IN (
		        SELECT vulnerability_cve_id
		        FROM component_vulnerabilities
		        WHERE component_id IN (
		            SELECT components.id
		            FROM components
		            WHERE components.id In (
		                SELECT component_id
		                FROM component_owners
		                WHERE user_id = userObj.Id
		            )
		        )
		    )
		);
	*/

	subQuery4 := db.DB.Table("component_owners").
		Select("component_id").
		Where("user_id = ?", userObj.Id)

	subQuery3 := db.DB.Table("components").
		Select("components.id").
		Where("components.id IN (?)", subQuery4)

	subQuery2 := db.DB.Table("component_vulnerabilities").
		Select("vulnerability_cve_id").
		Where("component_id IN (?)", subQuery3)

	subQuery1 := db.DB.Table("notification_vulnerabilities").
		Select("notification_id").
		Where("vulnerability_cve_id IN (?)", subQuery2)

	if err := db.DB.Model(&notifications).
		Preload("Vulnerabilities").
		Where("id IN (?)", subQuery1).
		Where(&params).
		Find(&notifications).Error; err != nil {
		return nil, db.Errs(err)
	}

	return notifications, nil

}

func (NotificationCRUD) GetForCVE(params *models.Notification, cve string) ([]models.Notification, error) {
	var notifications []models.Notification

	//escape harmful inputs
	cve = strings.ReplaceAll(cve, "&%;/\\=", "")

	subQuery := db.DB.Table("notification_vulnerabilities").
		Select("notification_id").
		Where("vulnerability_cve_id", cve)

	if err := db.DB.Model(&notifications).
		Preload("Vulnerabilities").
		Where("id IN (?)", subQuery).
		Where(&params).
		Find(&notifications).Error; err != nil {
		return nil, db.Errs(err)
	}
	return notifications, nil
}

func (NotificationCRUD) GetWithOrWithoutCVEs(params *models.Notification, cve bool) ([]models.Notification, error) {

	var notifications []models.Notification

	subQuery := db.DB.Table("notification_vulnerabilities").
		Select("notification_id")

	if cve {
		if err := db.DB.Model(&notifications).
			Preload("Vulnerabilities").
			Where("id IN (?)", subQuery).
			Where(&params).
			Find(&notifications).Error; err != nil {
			return nil, db.Errs(err)
		}
		return notifications, nil
	}

	if err := db.DB.Model(&notifications).
		Preload("Vulnerabilities").
		Not("id IN (?)", subQuery).
		Where(&params).
		Find(&notifications).Error; err != nil {
		return nil, db.Errs(err)
	}
	return notifications, nil
}

func (NotificationCRUD) GetById(id string) (*models.Notification, error) {

	idInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, db.InvIdErr
	}

	var notification *models.Notification

	if err := db.DB.Preload("Vulnerabilities").
		Model(&notification).
		First(&notification, idInt).
		Error; err != nil {
		return nil, db.Errs(err)
	}

	return notification, nil

}

func (NotificationCRUD) Create(input models.CreateNotificationInput) (*models.Notification, error) {

	notification := input.TurnToNotification()

	if err := db.DB.Model(&models.Notification{}).
		Create(&notification).
		Preload("Vulnerabilities").
		Find(&notification).
		Error; err != nil {
		return nil, db.Errs(err)
	}

	rssLog.Printf("Created notification Id: %v: \"%v\"\n", notification.Id, notification.Title)
	if len(input.Vulnerabilities) > 0 {
		rssLog.Printf("Notification Id: %v covers: \n", notification.Id)
	}
	for _, vulnerability := range input.Vulnerabilities {
		rssLog.Printf("\t - %s\n", vulnerability.CVEId)
	}
	return notification, nil

}

func (NotificationCRUD) UpdateOrCreate(input models.CreateNotificationInput) (*models.Notification, error) {

	var notification *models.Notification

	//Check for Notification via link, because it identifies entries
	err := db.DB.Model(&models.Notification{}).
		Where("link = ?", input.Link).
		First(&notification).Error

	//If there is no such record, it's new -> Create record
	if errors.Is(err, gorm.ErrRecordNotFound) {

		notification, err := thisNotification.Create(input)
		if err != nil {
			return nil, db.Errs(err)
		}
		return notification, nil
	}

	//if the publish Ddate changed is canged, it's an update. DFN does not
	//use the "Updated" RSS Value
	if notification.PubDate != input.PubDate {

		// Create the updated entry
		notification := input.TurnToNotification()

		if err := db.DB.Session(&gorm.Session{
			FullSaveAssociations: true,
		}).Model(&models.Notification{}).
			Where("id = ?", notification.Id).
			Updates(&notification).
			Preload("Vulnerabilities").
			Find(&notification).Error; err != nil {
			return nil, db.Errs(err)
		}
		return notification, nil

	} else { // Do nothing. Record exits and has not changed
		return nil, nil
	}

}

func (NotificationCRUD) GetTimeOfLastPub() (time.Time, error) {
	var notification *models.Notification
	var latest time.Time

	if err := db.DB.Model(&models.Notification{}).
		Order("pub_date desc").
		First(&notification).Error; err != nil {
		return time.Time{}, db.Errs(err)
	}
	latest = *notification.PubDate
	return latest, nil

}
