package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var component crud.ComponentCRUD

// GetAllComponents godoc
// @summary Get All Components
// @description Returns all listed components.
// @tags Components
// @Security ApiKeyAuth
//@produce json
// @Param    vendor    query     string  false  "Get components by vendor name."
// @Param    for    query     string  false  "Get components assigned to specific username (e-mail)."
// @response 200 {array} models.Component "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components [get]
func GetAllComponents(c *gin.Context) {

	var input models.Component

	vendorName, vendorExists := c.GetQuery("vendor")
	mail, userExists := c.GetQuery("for")

	//find vendorID in DB
	if vendorExists && len(vendorName) > 0 {
		vendors, err := vendor.GetAll(&models.Vendor{
			Name: vendorName,
		})
		if len(vendors) > 0 && err == nil {
			input.VendorId = vendors[0].Id
		}

	}

	if userExists && len(mail) > 0 {
		userObj, err := user.GetByMail(mail)
		if err == nil && userObj.Id != 0 {
			input.Owners = []models.User{*userObj}
		}
	}

	err := c.ShouldBind(&input)
	components, err := component.GetAll(&input)
	helper.AnswerGetAll(components, err, c)
}

// SearchComponents godoc
// @summary Search Component
// @description Search component by name.
// @tags Components
// @Security ApiKeyAuth
//@produce json
// @Param    q    query     string  true  "Search components by name."
// @response 200 {array} models.Component "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/search [get]
func SearchComponents(c *gin.Context) {
	searchQuery, searchExists := c.GetQuery("q")

	if searchExists {
		component, err := component.Search(searchQuery)
		helper.AnswerGetAll(component, err, c)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query not provided"})

	}
}

// GetAllComponentVulnerabilities godoc
// @summary Get component vulnerabilities by ID.
// @description Returns all listed vulnerabilities for a specific component.
// @tags Components
// @Security ApiKeyAuth
// @produce json
// @Param        id   path      int  true  "component ID"
// @response 200 {array} models.Vulnerability "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id}/vulnerabilities [get]
func GetAllComponentVulnerabilities(c *gin.Context) {
	var input models.Vulnerability
	err := c.ShouldBind(&input)

	vulns, err := vulnerability.GetAllForComponent(c.Param("id"), &input)
	helper.AnswerGetAll(vulns, err, c)

}

// GetComponentById godoc
// @summary Get component by ID
// @description Returns component for a specific ID.
// @tags Components
// @Security ApiKeyAuth
// @produce json
// @Param        id   path      int  true  "component ID"
// @response 200 {object} models.Component "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id} [get]
func GetComponentById(c *gin.Context) {

	component, err := component.GetById(c.Param("id"))
	helper.Answer(component, err, c)

}

// CreateComponent godoc
// @summary Create a new component
// @description Create a new component. Vendor must be created in the first place.
// @description Returns created component.
// @tags Components
// @Security ApiKeyAuth
// @produce json
// @accept json
// @Param   Component  body      models.CreateUpdateComponentInput  true  "Add Component."
// @response 200 {object} models.Component "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components [post]
func CreateComponent(c *gin.Context) {
	var input models.CreateUpdateComponentInput

	if err := helper.BindJSON(&input, c); err == nil {
		usr := helper.GetUserStringFromToken(c)
		component, err := component.Create(&input, usr)
		helper.Answer(component, err, c)

	}

}

// UpdateComponent godoc
// @summary Update a component
// @description Update an existing component.
// @description Will not succeed if component is in use by other users.
// @tags Components
// @Security ApiKeyAuth
// @produce json
// @accept json
// @Param        id   path      int  true  "component ID"
// @Param        Component  body      models.CreateUpdateComponentInput  true  "Update Component."
// @response 200 {object} models.Component "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id} [patch]
func UpdateComponent(c *gin.Context) {
	var input models.CreateUpdateComponentInput
	usr := helper.GetUserStringFromToken(c)

	if err := helper.BindJSON(&input, c); err == nil {
		component, err := component.Update(c.Param("id"), &input, usr)
		helper.Answer(component, err, c)

	}
}

// DeleteComponent godoc
// @summary Delete a component
// @description Delete a specific component.
// @description Will not succeed if component is in use by other users.
// @tags Components
// @Security ApiKeyAuth
// @Param        id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id} [delete]
func DeleteComponent(c *gin.Context) {
	usr := helper.GetUserStringFromToken(c)

	if err := component.Delete(c.Param("id"), usr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, "Deleted")
}

// SubscribeUserToComponent godoc
// @summary Subscribe a user to a component
// @description Subscribe a user via username (e-mail) to an specific entry.
// @tags Components
// @Security ApiKeyAuth
// @Param    user   query     string  true  "user to subscribe"
// @Param 	 id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id}/subscribe [post]
func SubscribeUserToComponent(c *gin.Context) {

	subscriber, userPresent := c.GetQuery("user")

	if userPresent {

		if err := component.UserAssociations(
			c.Param("id"),
			subscriber,
			true); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, "subscribed")

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User query not provides"})

	}
}

// UnsubscribeUserToComponent godoc
// @summary Unsubscribe a user form a component
// @description Unsubscribe a user via username (e-mail) from an specific entry.
// @tags Components
// @Security ApiKeyAuth
// @Param    user   query     string  true  "user to remove"
// @Param 	 id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} helper.ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id}/unsubscribe [post]
func UnsubscribeUserToComponent(c *gin.Context) {

	subscriber, userPresent := c.GetQuery("user")

	if userPresent {

		if err := component.UserAssociations(
			c.Param("id"),
			subscriber,
			false); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, "unsubscribed")

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User query not provided"})

	}
}
