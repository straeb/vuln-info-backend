package core

import (
	"gopkg.in/robfig/cron.v2"
	"log"
	"os"
	"strconv"
)

/*
InitCronJobs sets up the corn jobs with the given temporal
configs of the env file:

CheckFeed fetches the RSS feed
MatchCPEs matches the API found CPEs against the CPEs from the
component database. There are three of them to separate between
old and new entries.
*/
func InitCronJobs() {

	var CronString1 = os.Getenv("CRON_STRING_1")

	var FromDays1 = os.Getenv("FROM_DAYS_1")
	fromDays1, err := strconv.Atoi(FromDays1)
	errLogger(err)

	var ToDays1 = os.Getenv("TO_DAYS_1")
	toDays1, err := strconv.Atoi(ToDays1)
	errLogger(err)

	var CronString2 = os.Getenv("CRON_STRING_2")

	var FromDays2 = os.Getenv("FROM_DAYS_2")
	fromDays2, err := strconv.Atoi(FromDays2)
	errLogger(err)

	var ToDays2 = os.Getenv("TO_DAYS_2")
	toDays2, err := strconv.Atoi(ToDays2)
	errLogger(err)

	var CronString3 = os.Getenv("CRON_STRING_3")

	var FromDays3 = os.Getenv("FROM_DAYS_3")
	fromDays3, err := strconv.Atoi(FromDays3)
	errLogger(err)

	var ToDays3 = os.Getenv("TO_DAYS_3")
	toDays3, err := strconv.Atoi(ToDays3)
	errLogger(err)

	c := cron.New()

	//RSS Feed
	_, err1 := c.AddFunc(os.Getenv("RSS_CRON_STRING"), func() {
		CheckFeed(GetRSSLink())
	})
	errLogger(err1)
	// CPE Matching
	_, err1 = c.AddFunc(CronString1, func() {
		MatchCPEs(fromDays1, toDays1)
	})
	errLogger(err1)

	_, err1 = c.AddFunc(CronString2, func() {
		MatchCPEs(fromDays2, toDays2)
	})
	errLogger(err1)

	_, err1 = c.AddFunc(CronString3, func() {
		MatchCPEs(fromDays3, toDays3)
	})
	errLogger(err1)

	c.Start()
}

/*
GetDSN to make the DB config accessible in initDatabase.go
*/
func GetDSN() string {

	var MysqlUser = os.Getenv("MYSQL_USER")
	var MysqlPassword = os.Getenv("MYSQL_PASSWORD")
	var MysqlDatabase = os.Getenv("MYSQL_DATABASE")
	var MysqlIp = os.Getenv("MYSQL_IP")
	var MysqlPort = os.Getenv("MYSQL_PORT")

	var dsn = MysqlUser + ":" + MysqlPassword + "@tcp(" + MysqlIp + ":" + MysqlPort + ")/" + MysqlDatabase + "?charset=utf8mb4&parseTime=True"
	return dsn
}

/*
GetRSSLink returns the link from the env file.
*/
func GetRSSLink() string {
	return os.Getenv("DFN_FEED_LINK")
}

func errLogger(err error) {
	if err != nil {
		log.Printf(err.Error())
	}
}
