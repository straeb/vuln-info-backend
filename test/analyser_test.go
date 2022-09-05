package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"vuln-info-backend/models"
	"vuln-info-backend/service/core"
)
import db "vuln-info-backend/persistance/crud"

func TestMatchCPEs(t *testing.T) {

	SetUp()
	defer TearDown()

	var vendordb = db.VendorCRUD{}
	var componentdb = db.ComponentCRUD{}
	var vulnerabilitydb = db.VulnerabilityCRUD{}

	vendor, _ := vendordb.Create("Testvendor", "test@testing.de")
	component1, _ := componentdb.Create(&models.CreateUpdateComponentInput{
		Name:     "Testcomponent",
		Version:  "123981ukjnkjn",
		Cpe:      "cpe:2.3:a:freerdp:freerdp:1.0.0:beta2:*:*:*:*:*:*", //known to be vulnerable
		VendorId: vendor.Id,
	}, "test@testing.com")

	noComp, err := componentdb.Create(&models.CreateUpdateComponentInput{
		Name:     "Testcomponent2",
		Version:  "kjnfkjn",
		Cpe:      "cpe:2.3:a:freerdp:freerdp:1.0.0:beta2:*:*:*:*:*:*", //known to be vulnerable
		VendorId: vendor.Id,
	}, "test@testing.com")

	assert.NotNil(t, err, "Duplicate CPE not possible")
	assert.Nil(t, noComp)

	vuln1, _ := vulnerabilitydb.Create(models.CreateVulnerabilityInput{
		CVEId:       "CVE-2021-41159",
		Description: "",
		CWE:         "",
		CPEs:        nil,
	})

	core.MatchCPEs(0, -1)

	componentN, _ := componentdb.GetById(fmt.Sprint(component1.Id))

	assert.NotEqual(t, component1, componentN, "Component was modified")
	assert.Equal(t, componentN.Vulnerabilities[0].CVEId, vuln1.CVEId, "Vulnerability was added")
	vuln1N, _ := vulnerabilitydb.GetById("CVE-2021-41159")

	assert.NotEqual(t, vuln1N, vuln1, "Vulnerability was updated")

}
