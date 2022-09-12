package main

import (
	"github.com/joho/godotenv"
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
	var DEBUG bool = false

	if DEBUG {
		godotenv.Load(".env")
	}

	dsn := core.GetDSN()
	core.InitCronJobs()
	database.ConnectDB(dsn, DEBUG)

	handler.InitRouting(DEBUG)

}
