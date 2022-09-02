package helper

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"net/http"
	"regexp"
)

// ApiError Only used for Swagger API documentaition
type ApiError struct {
	Error string `json:"error"`
}

/*
Answer Helper function used in api to answer requests.
Sends 404 or 200.
*/
func Answer[S any](s *S, err error, c *gin.Context) {
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, s)

}

/*
AnswerGetAll Helper function used in api to answer requests
with array return types. Sends 404 or 200.
*/
func AnswerGetAll[S any](s []S, err error, c *gin.Context) {
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, s)

}

/*
BindJSON Helper function used in api to bind requests.
//Sends 404.
*/
func BindJSON[S any](s *S, c *gin.Context) error {
	if err := c.ShouldBindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return err
	}
	return nil
}

/*
addCustomValidators Apply the validatos below
*/
func AddCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("cve", cve)
		v.RegisterValidation("cpe", cpe)
	}
}

/*
cve Validator for CVEs : CVE-YEAR-XXXX..N
*/
var cve validator.Func = func(fl validator.FieldLevel) bool {
	cve, ok := fl.Field().Interface().(string)
	if ok {
		//match CVE convention
		must := regexp.MustCompile(`CVE-\d\d\d\d-\d\d\d\d+\b`)
		if len(must.FindString(cve)) > 0 {
			return true
		}
		return false
	}
	return false
}

/*
cpe CPE 2.3 Validator, only used on Components, because cpes provided via vulnerabilities are from a valid api api
*/
var cpe validator.Func = func(fl validator.FieldLevel) bool {
	cpe, ok := fl.Field().Interface().(string)
	if ok {
		//Match CPE convention. See:https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
		must := regexp.MustCompile("cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|}~]))+(\\?*|\\*?))|[\\*\\-])){4}")
		if len(must.FindString(cpe)) > 0 {
			return true
		}
		return false
	}
	return false
}
