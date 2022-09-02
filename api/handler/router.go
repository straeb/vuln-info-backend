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

	var apiVersion = "api/v1"

	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("*")
	router.Use(cors.New(config))

	helper.AddCustomValidators()

	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	//Auth
	router.POST(apiVersion+"auth/login", Login)
	router.POST(apiVersion+"auth/signup", SignUp)

	//Components
	components := router.Group(apiVersion + "/components")
	components.Use(helper.AuthorizeJWT())

	components.GET("", GetAllComponents)
	components.GET("/search", SearchComponents)
	components.GET("/:id/vulnerabilities", GetAllComponentVulnerabilities)
	components.GET("/:id", GetComponentById)
	components.POST("", CreateComponent)
	components.POST("/:id/subscribe", SubscribeUserToComponent)
	components.POST("/:id/unsubscribe", UnsubscribeUserToComponent)
	components.PATCH("/:id", UpdateComponent)
	components.DELETE("/:id", DeleteComponent)

	//Vendors
	vendors := router.Group(apiVersion + "/vendors")
	vendors.Use(helper.AuthorizeJWT())

	vendors.GET("", GetAllVendors)
	vendors.GET("/search", SearchVendor)
	vendors.GET("/:id", GetVendorById)
	vendors.PATCH("/:id", UpdateVendor)
	vendors.DELETE("/:id", DeleteVendor)
	vendors.POST("", CreateVendor)

	//Vulnerabilities
	vuln := router.Group(apiVersion + "/vulnerabilities")
	vuln.Use(helper.AuthorizeJWT())

	vuln.GET("/cpe", GetAllVulnerabilitiesCpe)
	vuln.GET("/cpe/:id", GetVulnerabilitiesByIdCpe)
	vuln.GET("", GetAllVulnerabilities)
	vuln.GET("/:id", GetVulnerabilityById)
	//vuln.POST("", CreateVulnerability)
	//vuln.PATCH("/:id", UpdateVulnerability)
	//vuln.DELETE("/:id", DeleteVulnerability)

	//Notifciations
	notifi := router.Group(apiVersion + "/notifications")
	notifi.Use(helper.AuthorizeJWT())

	notifi.GET("", GetAllNotifications)
	notifi.GET("/:id", GetNotificationById)

	//config
	configEndpoint := router.Group(apiVersion + "/config")
	configEndpoint.Use(helper.AuthorizeJWT())

	configEndpoint.GET("/rss", RunParser)
	configEndpoint.GET("/match", CheckCPEs)
	router.Run(":8080")

}
