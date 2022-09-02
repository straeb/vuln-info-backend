package models

import "time"

type Notification struct {
	Id              uint            `json:"id" gorm:"primary_key"`
	PubDate         *time.Time      `json:"pub_date"`
	Title           string          `json:"title"`
	Link            string          `json:"link" gorm:"unique"`
	CVSSbase        string          `json:"cvss_base"`
	CVSSEx          string          `json:"cvss_exploitability"`
	CVSSimpact      string          `json:"cvss_impact"`
	CVSStemp        string          `json:"cvss_temp"`
	Message         string          `json:"message"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" gorm:"many2many:notification_vulnerabilities;"`
	CreatedAt       time.Time       `json:"-"`
	UpdatedAt       time.Time       `json:"-"`
}

type CreateNotificationInput struct {
	PubDate         *time.Time      `json:"pub_date"`
	Title           string          `json:"title"`
	Link            string          `json:"notes"`
	CVSSbase        string          `json:"cvss_base"`
	CVSSEx          string          `json:"cvss_exploitability"`
	CVSSimpact      string          `json:"cvss_impact"`
	CVSStemp        string          `json:"cvss_temp"`
	Message         string          `json:"message"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" gorm:"many2many:notification_vulnerabilities;"`
}

func (n CreateNotificationInput) TurnToNotification() *Notification {
	return &Notification{
		PubDate:         n.PubDate,
		Title:           n.Title,
		Link:            n.Link,
		CVSSbase:        n.CVSSbase,
		CVSSEx:          n.CVSSEx,
		CVSSimpact:      n.CVSSimpact,
		CVSStemp:        n.CVSStemp,
		Message:         n.Message,
		Vulnerabilities: n.Vulnerabilities,
	}

}
