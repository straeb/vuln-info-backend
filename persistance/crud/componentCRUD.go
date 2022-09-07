package crud

import (
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"log"
	"os"
	"strconv"
	"strings"
	"vuln-info-backend/models"
	db "vuln-info-backend/persistance/database"
)

type ComponentCRUD struct{}

var thisComponent ComponentCRUD

var compLog = log.New(os.Stderr, "[COMPONENT] ", log.Ldate|log.Ltime)

func (ComponentCRUD) GetAll(params *models.Component) ([]models.Component, error) {
	var components []models.Component

	//Not elegant but normal way over params is not working for some reasons
	subQuery := db.DB.Table("components").Select("id")

	if len(params.Owners) != 0 {
		userId := params.Owners[0].Id
		subQuery = db.DB.Table("component_owners").
			Select("component_id").
			Where("user_id = ?", userId)
	}

	if err := db.DB.Preload("Vulnerabilities").
		Preload("Vendor").
		Preload("Owners").
		Model(&components).
		Where(&params).
		Where("id In (?)", subQuery).
		Find(&components).
		Error; err != nil {
		return nil, db.Errs(err)

	}

	return components, nil

}

func (ComponentCRUD) Search(searchQuery string) ([]models.Component, error) {
	//escape harmful characters
	searchQuery = strings.ReplaceAll(searchQuery, "?/\\=;", "")
	var components []models.Component

	if len(searchQuery) > 0 {
		if err := db.DB.Model(&components).
			Preload("Vulnerabilities").
			Preload("Vendor").
			Preload("Owners").
			Where("name LIKE ?", "%"+searchQuery+"%").
			Find(&components).Error; err != nil {
			return nil, db.Errs(err)
		}
		return components, nil
	}
	return components, nil
}

// GetById Preload Vulnerabilities without CPEs because theses are unnecessary information in this context
func (ComponentCRUD) GetById(id string) (*models.Component, error) {
	//escape harmful inputs
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, db.InvIdErr
	}

	var component *models.Component

	if err := db.DB.Preload("Vulnerabilities").
		Preload(clause.Associations).
		Model(&component).Where("id = ?", idInt).Find(&component).
		Error; err != nil {
		return nil, db.Errs(err)
	}
	return component, nil

}

func (ComponentCRUD) GetByCPE(cpe string) (*models.Component, error) {

	var component *models.Component
	if err := db.DB.Model(&component).
		Where("cpe = ?", cpe).
		Find(&component).Error; err != nil {
		return nil, db.Errs(err)
	}
	return component, nil
}

func (ComponentCRUD) GetByVendorID(venID int) ([]models.Component, error) {

	var components []models.Component
	if err := db.DB.Model(&components).
		Where("vendor_id = ?", venID).
		Find(&components).Error; err != nil {
		return nil, db.Errs(err)
	}
	return components, nil
}

func (ComponentCRUD) Create(input *models.CreateUpdateComponentInput, usr string) (*models.Component, error) {

	component := input.TurnToComponent()

	result, _ := thisComponent.GetByCPE(component.Cpe)
	if result.Id != 0 {
		return nil, errors.New("Record with this CPE already exists")
	}

	if err := db.DB.Model(component).
		Create(&component).
		Preload(clause.Associations).
		Find(&component).Error; err != nil {
		return nil, db.Errs(err)
	}

	compLog.Printf("%v created componetent recod %v: %v\n", usr, component.Name, component.Version)

	return component, nil

}

func (ComponentCRUD) Update(id string, input *models.CreateUpdateComponentInput, usr string) (*models.Component, error) {
	IdInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, db.InvIdErr
	}
	err2 := thisComponent.checkIfModifiable(id, usr)
	if err2 != nil {
		return nil, err2
	}

	component := input.TurnToComponent()

	if err := db.DB.Session(&gorm.Session{
		FullSaveAssociations: true,
	}).Model(&models.Component{}).
		Where("id = ?", IdInt).
		Updates(&component).
		Find(&component).Error; err != nil {
		return nil, db.Errs(err)
	}
	compLog.Printf("%v updated component Id: %v: %v\n", usr, component.Id, component.Name)
	//Return of the full updated object won't work with all the associations
	component, _ = thisComponent.GetById(id)
	return component, nil

}

func (ComponentCRUD) Delete(id string, usr string) error {
	IdInt, err := strconv.Atoi(id)
	if err != nil {
		return db.InvIdErr
	}
	err2 := thisComponent.checkIfModifiable(id, usr)
	if err2 != nil {
		return err2
	}

	var component *models.Component
	result := db.DB.Model(&component).
		Where("id = ?", IdInt).
		Delete(&component)

	if result.Error != nil {
		return db.Errs(err)
	}
	if result.RowsAffected == 0 {
		return errors.New("could not delete")
	}

	compLog.Printf("%v delted component id: %v\n ", usr, IdInt)
	return nil
}

func (ComponentCRUD) checkIfModifiable(id string, usr string) error {
	owners, err := thisUser.GetAllComponentOwners(id)
	if err != nil {
		return err
	}
	if len(owners) > 1 || (len(owners) == 1 && owners[0].EMail != usr) {
		return errors.New("could not delete or update - in use by an other user")
	}
	return nil
}

func (ComponentCRUD) AppendVulnerability(comp *models.Component, vuln models.Vulnerability) error {

	if err := db.DB.Model(&comp).
		Association("Vulnerabilities").
		Append(&vuln); err != nil {
		return db.Errs(err)
	}
	return nil
}

func (ComponentCRUD) UserAssociations(compId string, usrId string, append bool) error {

	var user models.User

	usrP, err := thisUser.GetByMail(usrId)
	if err != nil {
		return err
	}
	user = *usrP

	comp, err2 := thisComponent.GetById(compId)
	if err2 != nil {
		return err2
	}
	if append {
		if err := db.DB.Model(&comp).
			Association("Owners").
			Append(&user); err != nil {
			return db.Errs(err)
		}
		compLog.Printf("User %v subscribed to %v:%v", user.EMail, comp.Name, comp.Version)
	} else {
		if err := db.DB.Model(&comp).
			Association("Owners").
			Delete(&user); err != nil {
			return db.Errs(err)
		}
		compLog.Printf("User %v unsubscribed from to %v:%v", user.EMail, comp.Name, comp.Version)

	}

	return nil
}
