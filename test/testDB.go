package test

import "vuln-info-backend/persistance/database"

var MysqlUser = "testuser"
var MysqlPassword = "test"
var MysqlDatabase = "vulninfotest"
var MysqlIp = "127.0.0.1"
var MysqlPort = "3306"

var dsn = MysqlUser + ":" + MysqlPassword + "@tcp(" + MysqlIp + ":" + MysqlPort + ")/" + MysqlDatabase + "?charset=utf8mb4&parseTime=True&loc=Local"

func SetUp() {

	database.ConnectDB(dsn, true)
	println("set up test DB")
}

func TearDown() {
	database.DropDB()
	println("drop test DB")
}
