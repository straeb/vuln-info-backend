package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/service/auth"
)

type LoginSuccess struct {
	Token string `json:"token"`
}

// Login godoc
// @summary Login Endpoint
// @description Login Endpoint takes username and password and returns a JWT-Token if authorized.
// @tags Authorization
// @accept json
// @Param  Credentials  body  models.CreateUpdateUserInput  true  "Login Credentials"
// @response 200 {object} LoginSuccess "OK"
// @failure 401 {string} string "Unauthorized"
// @failure 400 {object} ApiError "Bad Request"
// @failure 404 {string} string "Not Found"
//@Router /login [post]
func Login(ctx *gin.Context) {
	var credential models.CreateUpdateUserInput
	err := helper.BindJSON(&credential, ctx)
	if err != nil {
		return
	}
	isUserAuthenticated := auth.LoginUser(credential.EMail, credential.Password)
	if isUserAuthenticated {
		token := auth.GenerateToken(credential.EMail, true)
		if token != "" {
			ctx.JSON(http.StatusOK, gin.H{
				"token": token,
			})
			return
		} else {
			ctx.JSON(http.StatusUnauthorized, "Unauthorized")
			return
		}

	}
	ctx.JSON(http.StatusUnauthorized, "Unauthorized")
}
