package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"vuln-info-backend/api/helper"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var vendor crud.VendorCRUD

// GetAllVendors godoc
// @summary Get All Vendors
// @description Returns a list of all vendors.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @response 200 {array} models.Vendor "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
// @Router /vendors [get]
func GetAllVendors(c *gin.Context) {
	var input models.Vendor

	err := c.ShouldBind(&input)
	vendor, err := vendor.GetAll(&input)
	helper.AnswerGetAll(vendor, err, c)

}

// SearchVendor godoc
// @summary Search vendor
// @description Search vendor by name.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @Param    q    query     string  true  "Search vendor by name."
// @response 200 {array} models.Vendor "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
// @Router /vendors/search [get]
func SearchVendor(c *gin.Context) {
	searchQuery, present := c.GetQuery("q")
	if present {
		vendor, err := vendor.Search(searchQuery)
		helper.AnswerGetAll(vendor, err, c)

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query not provided"})
	}
}

// GetVendorById godoc
// @summary Get vendor by ID
// @description Returns vedndor for a specific ID.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @Param    id   path      int  true  "vendor ID"
// @response 200 {object} models.Vendor "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /vendors/{id} [get]
func GetVendorById(c *gin.Context) {
	vendor, err := vendor.GetById(c.Param("id"))
	helper.Answer(vendor, err, c)
}

// CreateVendor godoc
// @summary Create a new vendor
// @description Create a new Vendor.
// @description Returns created vendor.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @accept json
// @Param    Vendor  body      models.CreateUpdateVendorInput  true  "Add Vendor."
// @response 200 {object} models.Vendor "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /vendors [post]
func CreateVendor(c *gin.Context) {
	var input models.CreateUpdateVendorInput

	if err := helper.BindJSON(&input, c); err == nil {
		usr := helper.GetUserStringFromToken(c)
		newVendor, err := vendor.Create(input.Name, usr)
		helper.Answer(newVendor, err, c)
	}
}

// UpdateVendor godoc
// @summary Update a vendor entry
// @description Update an existing vendor.
// @description Will not succeed if vendor is in use by a component.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @produce json
// @accept json
// @Param        id   path      int  true  "vendor ID"
// @Param        Vendor  body      models.CreateUpdateVendorInput  true  "Update Vendor."
// @response 200 {object} models.Vendor "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /vendors/{id} [patch]
func UpdateVendor(c *gin.Context) {
	var input models.CreateUpdateVendorInput

	if err := helper.BindJSON(&input, c); err == nil {
		usr := helper.GetUserStringFromToken(c)
		updatedVendor, err := vendor.Update(c.Param("id"), input.Name, usr)
		helper.Answer(updatedVendor, err, c)

	}
}

// DeleteVendor godoc
// @summary Delete a vendor
// @description Delete a specific component.
// @description Will not succeed if vendor is in use by a component.
// @tags Vendors
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @Param        id   path      int  true  "component ID"
// @response 200 {string} string "OK"
// @failure 400 {object} ApiError "Bad Request"
// @failure 401 {string} string "Unauthorized"
// @failure 404 {string} string "Not Found"
//@Router /vendors/{id} [delete]
func DeleteVendor(c *gin.Context) {
	usr := helper.GetUserStringFromToken(c)

	if err := vendor.Delete(c.Param("id"), usr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, "Deleted")

}
