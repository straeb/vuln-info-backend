package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var user crud.UserCRUD

func GetAllUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": user.GetAll()})
}

// SignUp godoc
// @summary Sign Up Endpoint
// @description SingUp Endpoint takes username and password and returns a user object.
// @tags Authorization
// @accept json
// @Param  Credentials  body  models.CreateUpdateUserInput  true  "username and password"
// @response 200 {object} models.User "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 404 {string} string "Not Found"
//@Router /auth/signup [post]
func SignUp(c *gin.Context) {
	var input models.CreateUpdateUserInput

	if err := helper.BindJSON(&input, c); err == nil {
		newUser, err := user.Create(input)
		helper.Answer(newUser, err, c)
	}
}

func UpdateUser(c *gin.Context) {
	var input models.CreateUpdateUserInput
	usr := helper.GetUserStringFromToken(c)

	if err := helper.BindJSON(&input, c); err == nil {
		updatedUser, err := user.Update(usr, input)
		helper.Answer(updatedUser, err, c)
	}
}

func DeleteUser(c *gin.Context) {
	usr := helper.GetUserStringFromToken(c)
	if err := user.Delete(usr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": "Deleted"})

}
