package core

import (
	"github.com/joho/godotenv"
	"gopkg.in/robfig/cron.v2"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
)

func errLogger(err error) {
	if err != nil {
		log.Printf(err.Error())
	}
}

/*
ReadConfig reads the .yml config file and unmarshal it
to a map
*/
func ReadConfig(debug bool) (map[interface{}]interface{}, error) {

	data := make(map[interface{}]interface{})

	var yFile []byte
	var err error

	if debug {
		yFile, err = ioutil.ReadFile("cron-config.yml")
	} else {
		yFile, err = ioutil.ReadFile("/cron-config.yml")
	}
	if err != nil {
		return data, err

	}

	err = yaml.Unmarshal(yFile, &data)
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
InitCronJobs sets up the corn jobs with the given temporal
configs of the config file:

CheckFeed fetches the RSS feed
MatchCPEs matches the API found CPEs against the CPEs from the
component database. There are three of them to separate between
old and new entries.
*/
func InitCronJobs(data map[interface{}]interface{}) error {

	c := cron.New()

	//RSS Feed
	_, err := c.AddFunc(data["RSS_CRON_STRING"].(string), func() {
		CheckFeed(GetRSSLink())
	})
	if err != nil {
		return err
	}

	// CPE Matching
	_, err = c.AddFunc(data["1_CRON_STRING"].(string), func() {
		MatchCPEs(data["1_FROM_DAYS"].(int),
			data["1_TO_DAYS"].(int))
	})
	if err != nil {
		return err
	}

	_, err = c.AddFunc(data["2_CRON_STRING"].(string), func() {
		MatchCPEs(data["2_FROM_DAYS"].(int),
			data["2_TO_DAYS"].(int))
	})
	if err != nil {
		return err
	}
	_, err = c.AddFunc(data["3_CRON_STRING"].(string), func() {
		MatchCPEs(data["3_FROM_DAYS"].(int),
			data["3_TO_DAYS"].(int))
	})
	if err != nil {
		return err
	}

	c.Start()

	return nil

}

/*
GetDSN is a Getter to make the DB config accessible in initDatabase.go
*/
func GetDSN(debug bool) string {

	var err error
	if debug {
		err = godotenv.Load(".env")
	} else {
		err = godotenv.Load("/.env")
	}

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var MysqlUser = os.Getenv("MYSQL_USER")
	var MysqlPassword = os.Getenv("MYSQL_PASSWORD")
	var MysqlDatabase = os.Getenv("MYSQL_DATABASE")
	var MysqlIp = os.Getenv("MYSQL_IP")
	var MysqlPort = os.Getenv("MYSQL_PORT")

	var dsn = MysqlUser + ":" + MysqlPassword + "@tcp(" + MysqlIp + ":" + MysqlPort + ")/" + MysqlDatabase + "?charset=utf8mb4&parseTime=True"
	return dsn
}

/*
GetRSSLink returns the link from the config file.
*/
func GetRSSLink() string {
	return os.Getenv("DFN_FEED_LINK")
}
