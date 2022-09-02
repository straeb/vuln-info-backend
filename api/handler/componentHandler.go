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
// @param Authorization header string true "Authorization"
//@produce json
// @Param    search    query     string  false  "Search components by name."
// @Param    vendor    query     string  false  "Get components by vendor name."
// @Param    for    query     string  false  "Get components assigned to specific username (e-mail)."
// @response 200 {array} models.Component "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components [get]
func GetAllComponents(c *gin.Context) {

	var input models.Component

	searchQuery, searchExists := c.GetQuery("search")
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

	if searchExists {
		component, err := component.Search(&input, searchQuery)
		helper.AnswerGetAll(component, err, c)
		return
	}

	err := c.ShouldBind(&input)
	components, err := component.GetAll(&input)
	helper.AnswerGetAll(components, err, c)
}

// GetAllComponentVulnerabilities godoc
// @summary Get component vulnerabilities by ID.
// @description Returns all listed vulnerabilities for a specific component.
// @tags Components
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @Param        id   path      int  true  "component ID"
// @response 200 {array} models.Vulnerability "OK"
// @failure 400 {object} ApiError "Bad Request"
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
// @param Authorization header string true "Authorization"
// @produce json
// @Param        id   path      int  true  "component ID"
// @response 200 {object} models.Component "OK"
// @failure 400 {object} ApiError "Bad Request"
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
// @param Authorization header string true "Authorization"
// @produce json
// @accept json
// @Param   Component  body      models.CreateUpdateComponentInput  true  "Add Component."
// @response 200 {object} models.Component "OK"
// @failure 400 {object} ApiError "Bad Request"
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
// @param Authorization header string true "Authorization"
// @produce json
// @accept json
// @Param        id   path      int  true  "component ID"
// @Param        Component  body      models.CreateUpdateComponentInput  true  "Update Component."
// @response 200 {object} models.Component "OK"
// @failure 400 {object} ApiError "Bad Request"
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
// @param Authorization header string true "Authorization"
// @Param        id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} ApiError "Bad Request"
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

// OwnerComponentActions godoc
// @summary (Un-)Subscribe to a component
// @description (Un-)Subscribe an user via username (e-mail) to an specific entry.
// @description Only ONE parameter is accepted. If both are provided "subscribe" will be accepted.
// @tags Components
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @Param    subscribe   query     string  true  "Subscribe user"
// @Param    unsubscribe   query     string  true  "Subscribe user"
// @Param 	 id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /components/{id} [post]
func OwnerComponentActions(c *gin.Context) {

	subscriber, subscribe := c.GetQuery("subscribe")
	unsubscriber, unsubscribe := c.GetQuery("unsubscribe")

	if subscribe {

		if err2 := component.UserAssociations(
			c.Param("id"),
			subscriber,
			true); err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err2.Error()})
			return
		}
		c.JSON(http.StatusOK, "subscribed")

	} else if unsubscribe {
		if err2 := component.UserAssociations(
			c.Param("id"),
			unsubscriber,
			false,
		); err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err2.Error()})
			return
		}
		c.JSON(http.StatusOK, "subscribed")

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please specify correct query parameters"})

	}
}
