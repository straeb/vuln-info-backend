package crud

import (
	"errors"
	"gorm.io/gorm"
	"log"
	"strconv"
	"strings"
	"time"
	"vuln-info-backend/models"
	db "vuln-info-backend/persistance/database"
)

type VulnerabilityCRUD struct{}

var thisVulnerability VulnerabilityCRUD

func (VulnerabilityCRUD) GetAllWithCpe(params *models.Vulnerability, cpe string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	//escape harmful character, limited due to the cpe convention
	cpe = strings.ReplaceAll(cpe, ";", "")

	if cpe != "" {
		//SELECT * FROM `vulnerabilities` WHERE <params> AND cve_id IN
		//(SELECT vulnerability_cve_id FROM `vulnerabilities_cpes` WHERE cpe_id = '<cpe>'));
		subQuery := db.DB.Table("vulnerabilities_cpes").
			Select("vulnerability_cve_id").
			Where("cpe_id = (?)", cpe)

		if err := db.DB.Preload("CPEs").
			Where(&params).
			Where("cve_id IN (?)", subQuery).
			Find(&vulns).Error; err != nil {

			return nil, db.Errs(err)
		}
		return vulns, nil

	}
	if err := db.DB.Preload("CPEs").
		Model(&vulns).
		Where(&params).
		Find(&vulns).Error; err != nil {
		return nil, db.Errs(err)
	}

	return vulns, nil
}

func (VulnerabilityCRUD) GetAll(parms *models.Vulnerability) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	if err := db.DB.Model(&vulns).
		Where(&parms).
		Find(&vulns).Error; err != nil {
		return nil, db.Errs(err)
	}

	return vulns, nil
}

func (VulnerabilityCRUD) GetAllCVEsFrom(from int, to int) ([]models.Vulnerability, error) {

	var vulns []models.Vulnerability

	var fromTime = time.Now().AddDate(0, 0, from)
	var toTime = time.Now().AddDate(0, 0, to)

	if err := db.DB.Select([]string{"cve_id", "description", "cwe", "created_at"}).
		Where("created_at BETWEEN ? AND ?", toTime, fromTime).
		Find(&vulns).Error; err != nil {
		return nil, db.Errs(err)
	}
	return vulns, nil

}

func (VulnerabilityCRUD) GetAllForComponent(compId string, params *models.Vulnerability) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability

	//escape harmful inputs
	compIdInt, err := strconv.Atoi(compId)
	if err != nil {
		return nil, db.InvIdErr
	}

	subQuery := db.DB.Table("component_vulnerabilities").
		Select("vulnerability_cve_id").
		Where("component_id = (?)", compIdInt)

	if err := db.DB.Where(&params).
		Where("cve_id IN (?)", subQuery).
		Find(&vulns).Error; err != nil {

		return nil, db.Errs(err)
	}
	return vulns, nil
}

func (VulnerabilityCRUD) GetById(id string) (*models.Vulnerability, error) {

	id = strings.ReplaceAll(id, "&%;/\\=", "")

	var vuln *models.Vulnerability
	if err := db.DB.Model(&vuln).
		First(&vuln, "cve_id = ?", id).Error; err != nil {
		return nil, db.Errs(err)
	}
	return vuln, nil

}

func (VulnerabilityCRUD) GetByIdWithCpe(id string) (*models.Vulnerability, error) {
	//escape harmful inputs
	id = strings.ReplaceAll(id, "&%;/\\=", "")

	var vuln *models.Vulnerability
	if err := db.DB.Preload("CPEs").
		Model(&vuln).
		First(&vuln, "cve_id = ?", id).
		Error; err != nil {
		return nil, db.Errs(err)
	}
	return vuln, nil

}

func (VulnerabilityCRUD) Create(input models.CreateVulnerabilityInput) (*models.Vulnerability, error) {

	vuln := input.TurnToVulnerability()

	if err := db.DB.Model(&models.Vulnerability{}).
		Create(&vuln).
		Preload("CPEs").
		Find(&vuln).Error; err != nil {
		return nil, db.Errs(err)
	}

	log.Printf("Created vulnerability recod %v\n", vuln.CVEId)
	return vuln, nil
}

func (VulnerabilityCRUD) UpdateOrCreate(input models.CreateVulnerabilityInput) (*models.Vulnerability, error) {

	_, err := thisVulnerability.GetById(input.CVEId)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		vuln, err := thisVulnerability.Create(input)
		if err != nil {
			return nil, err
		}
		return vuln, err
	}
	uodatedVuln, err := thisVulnerability.Update(input.CVEId, models.UpdateVulnerabilityInput{
		Description: input.Description,
		CWE:         input.CWE,
		CPEs:        input.CPEs,
	})
	if err != nil {
		return nil, err
	}
	return uodatedVuln, nil
}

func (VulnerabilityCRUD) Update(id string, input models.UpdateVulnerabilityInput) (*models.Vulnerability, error) {

	var vuln *models.Vulnerability

	vuln = &models.Vulnerability{
		CVEId:       id,
		Description: input.Description,
		CWE:         input.CWE,
		CPEs:        input.CPEs,
	}

	if err := db.DB.Session(&gorm.Session{
		FullSaveAssociations: true,
	}).Model(&models.Vulnerability{}).
		Where("cve_id = ?", id).
		Updates(&vuln).
		Preload("CPEs").Find(&vuln).Error; err != nil {
		return nil, db.Errs(err)
	}

	log.Println("Updated", vuln.CVEId)

	return vuln, nil

}

func (VulnerabilityCRUD) Delete(id string) error {
	//escape harmful inputs
	id = strings.ReplaceAll(id, "&%;/\\=", "")

	var vuln *models.Vulnerability

	if err := db.DB.Model(&vuln).
		Where("cve_id = ?", id).
		Delete(&vuln).Error; err != nil {
		return db.Errs(err)
	}
	return nil

}

func (VulnerabilityCRUD) AppendCPE(vuln *models.Vulnerability, cpe string) error {

	if err := db.DB.Model(&vuln).
		Where(&vuln).
		Association("CPEs").
		Append(&models.Cpe{
			Id: cpe,
		}); err != nil {
		return db.Errs(err)
	}

	return nil

}
