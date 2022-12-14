package core

import (
	"log"
	"os"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var vulnerability crud.VulnerabilityCRUD
var component crud.ComponentCRUD
var matchLog = log.New(os.Stdout, "[ANALYSER] ", log.Ldate|log.Ltime)

func MatchCPEs(from int, to int) {

	//Get new Vulns from the last x days
	vulns, _ := vulnerability.GetAllCVEsFrom(from, to)
	matchLog.Printf("Checking Vulnerabilities form the last %v to %v days:\n", from, to)
	var matchCount = 0
	//For each vulnerability
	for _, vuln := range vulns {

		//Get object from cve.circl.lu API
		obj := callCircl(vuln.CVEId)
		if obj != nil {

			//Update description and cwe for each Vuln, if Data is already present
			var updatedDescr = vuln.Description != obj.Summary
			var updatedCWE = vuln.CWE != obj.Cwe

			if updatedDescr || updatedCWE {
				vulnerability.Update(vuln.CVEId, models.UpdateVulnerabilityInput{
					Description: obj.Summary,
					CWE:         obj.Cwe,
				})
			}

			var componentObj *models.Component

			/*
				Check each of the CPEs that are assigned to the CVE, if it matches a given entry
				in the components database.
			*/
			for _, cpe := range obj.VulnerableProduct {

				componentObj, _ = component.GetByCPE(cpe)

				/*
					If there is a match, assign the CPE to the vulnerability and the vulnerability
					to the Component

				*/
				if componentObj.Id != 0 {
					vulnerability.AppendCPE(&vuln, cpe)
					err := component.AppendVulnerability(componentObj, vuln)
					if err == nil {
						//Otherwise the component is already flagged
						matchCount++
						matchLog.Printf("Vulnerability %v assigned to %v:%v\n", vuln.CVEId, componentObj.Name, componentObj.Version)
					}
				} else {
				}
			}
		}

	}
	matchLog.Printf("Checked %v vulnerabilities. Found %v vulnerable componentes.\n", len(vulns), matchCount)

}
