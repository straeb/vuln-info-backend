package handler

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"vuln-info-backend/api/helper"
)

func InitRouting(debug bool) {

	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("*")
	router.Use(cors.New(config))

	helper.AddCustomValidators()

	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	//Auth
	router.POST("api/v1/login", Login)
	router.POST("api/v1/signup", SignUp)

	//Components
	components := router.Group("api/v1/components")
	components.Use(helper.AuthorizeJWT())

	components.GET("", GetAllComponents)
	components.GET("/:id/vulnerabilities", GetAllComponentVulnerabilities)
	components.GET("/:id", GetComponentById)
	components.POST("", CreateComponent)
	components.POST("/:id", OwnerComponentActions)
	components.PATCH("/:id", UpdateComponent)
	components.DELETE("/:id", DeleteComponent)

	//Vendors
	vendors := router.Group("api/v1/vendors")
	vendors.Use(helper.AuthorizeJWT())

	vendors.GET("", GetAllVendors)
	vendors.GET("/:id", GetVendorById)
	vendors.PATCH("/:id", UpdateVendor)
	vendors.DELETE("/:id", DeleteVendor)
	vendors.POST("", CreateVendor)

	//Vulnerabilities
	vuln := router.Group("api/v1/vulnerabilities")
	vuln.Use(helper.AuthorizeJWT())

	vuln.GET("/cpe", GetAllVulnerabilitiesCpe)
	vuln.GET("/cpe/:id", GetVulnerabilitiesByIdCpe)
	vuln.GET("", GetAllVulnerabilities)
	vuln.GET("/:id", GetVulnerabilityById)
	//vuln.POST("", CreateVulnerability)
	//vuln.PATCH("/:id", UpdateVulnerability)
	//vuln.DELETE("/:id", DeleteVulnerability)

	//Notifciations
	notification := router.Group("api/v1/notifications")
	notification.Use(helper.AuthorizeJWT())

	notification.GET("", GetAllNotifications)
	notification.GET("/:id", GetNotificationById)

	//config
	configEndpoint := router.Group("api/v1/config")
	configEndpoint.Use(helper.AuthorizeJWT())

	configEndpoint.GET("/rss", RunParser)
	configEndpoint.GET("/match", CheckCPEs)
	router.Run(":8080")

}
