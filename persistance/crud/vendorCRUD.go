package crud

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"vuln-info-backend/models"
	db "vuln-info-backend/persistance/database"
)

type VendorCRUD struct{}

var thisVendor VendorCRUD

var vedorLog = log.New(os.Stderr, "[VENDOR] ", log.Ldate|log.Ltime)

func (VendorCRUD) GetAll(params *models.Vendor) ([]models.Vendor, error) {
	var vendors []models.Vendor

	if err := db.DB.Model(&vendors).
		Where(&params).
		Find(&vendors).
		Error; err != nil {
		return nil, db.Errs(err)
	}
	return vendors, nil

}

func (VendorCRUD) Search(searchQuery string) ([]models.Vendor, error) {
	//escape harmful characters
	searchQuery = strings.ReplaceAll(searchQuery, "?/\\=;", "")
	var vendors []models.Vendor

	if len(searchQuery) > 0 {
		if err := db.DB.Model(&vendors).
			Where("name LIKE ?", "%"+searchQuery+"%").
			Find(&vendors).Error; err != nil {
			return nil, db.Errs(err)
		}
		return vendors, nil
	}
	return vendors, nil
}

func (VendorCRUD) DoesExist(id string) bool {
	var vendor models.Vendor
	//escape harmful imputs
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return false
	}
	if err := db.DB.Model(&vendor).
		First(&vendor, idInt).
		Error; err != nil {
		return false
	}
	return true
}

func (VendorCRUD) GetById(id string) (*models.Vendor, error) {
	//escape harmful inputs
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, db.InvIdErr
	}

	var vendor *models.Vendor
	if err := db.DB.Model(&vendor).
		First(&vendor, idInt).
		Error; err != nil {
		return nil, db.Errs(err)
	}
	return vendor, nil

}

func (VendorCRUD) GetByName(n string) (*models.Vendor, error) {
	//escape harmful characters
	n = strings.ReplaceAll(n, "?/\\=;", "")
	var vendor *models.Vendor
	if err := db.DB.Model(&vendor).
		Where("name=?", n).
		First(&vendor).
		Error; err != nil {
		return nil, db.Errs(err)
	}
	return vendor, nil

}

func (VendorCRUD) Create(n string, usr string) (*models.Vendor, error) {
	//escape harmful characters
	n = strings.ReplaceAll(n, "?/\\=;", "")
	var vendor *models.Vendor

	vendor = &models.Vendor{Name: n}

	if err := db.DB.Model(&vendor).
		Create(&vendor).
		Find(&vendor).
		Error; err != nil {

		return nil, db.Errs(err)
	}

	vedorLog.Printf("%v created vendor: %v\n", usr, vendor.Name)

	return vendor, nil

}

func (VendorCRUD) Update(id string, n string, usr string) (*models.Vendor, error) {

	//escape harmful characters
	n = strings.ReplaceAll(n, "?/\\=;", "")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, db.InvIdErr
	}

	if thisVendor.isModifiable(idInt) {
		var vendor *models.Vendor
		if err := db.DB.Model(&vendor).
			First(&vendor, idInt).
			Updates(models.Vendor{Name: n}).
			Find(&vendor).
			Error; err != nil {
			return nil, db.Errs(err)
		}
		vedorLog.Printf("%v updated vendor Id: %:%v\n", usr, vendor.Id, vendor.Name)

		return vendor, nil
	} else {
		return nil, errors.New("vendor is in use by component entries")
	}
}

func (VendorCRUD) Delete(id string, usr string) error {

	//escape harmful inputs
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return err
	}

	var vendor *models.Vendor

	if thisVendor.isModifiable(idInt) {

		if err := db.DB.Where("id = ?", idInt).
			First(&vendor).
			Delete(&vendor).Error; err != nil {
			return db.Errs(err)
		}
		vedorLog.Printf("%v deleted vendor %v\n", usr, idInt)
		return nil
	} else {
		return errors.New("vendor is in use by component entries")
	}

}

func (VendorCRUD) isModifiable(id int) bool {

	var components []models.Component

	components, _ = thisComponent.GetByVendorID(id)

	if len(components) > 0 {
		return false
	}
	return true

}
