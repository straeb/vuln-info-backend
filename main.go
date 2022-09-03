package main

import (
	"vuln-info-backend/api/handler"
	_ "vuln-info-backend/docs"
	"vuln-info-backend/persistance/database"
	"vuln-info-backend/service/core"
)

// @title           Vulnerability-Info-API
// @version         1.0
// @description.markdown
// @BasePath  /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @description Use this token format: 'Bearer {key}'
// @in header
// @name Authorization

func main() {

	//Switch between Prod (Docker) & Debug
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
