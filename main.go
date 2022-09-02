package main

import (
	"vuln-info-backend/api/handler"
	_ "vuln-info-backend/docs"
	"vuln-info-backend/persistance/database"
	"vuln-info-backend/service/core"
)

// @title           Vulnerability API
// @version         1.0
// @description     This is the endpoint for component operations
// @BasePath  /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Bearer <Add access token here>

func main() {

	//Switch between Prod & Debug
	var DEBUG bool = true

	dsn := core.GetDSN(DEBUG)

	data, err := core.ReadConfig(DEBUG)
	if err == nil {
		if err := core.InitCronJobs(data); err != nil {
			panic(err.Error())
		}
		database.ConnectDB(dsn, DEBUG)
		handler.InitRouting(DEBUG)

	} else {
		panic(err.Error())
	}

}
