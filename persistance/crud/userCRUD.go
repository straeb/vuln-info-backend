package crud

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strconv"
	"vuln-info-backend/models"
	db "vuln-info-backend/persistance/database"
)

type UserCRUD struct{}

var thisUser UserCRUD

var userLog = log.New(os.Stderr, "[USER] ", log.Ldate|log.Ltime)

func (UserCRUD) GetAll() []models.User {
	var users []models.User
	db.DB.Find(&users)
	return users

}

func (UserCRUD) GetByMail(mail string) (*models.User, error) {
	//escape harmful inputs

	var user *models.User
	if err := db.DB.Model(&user).
		Where("e_mail = ?", mail).First(&user).Error; err != nil {
		return nil, db.Errs(err)
	}
	return user, nil
}

func (UserCRUD) Create(input models.CreateUpdateUserInput) (*models.User, error) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), 8)
	if err != nil {
		return nil, db.Errs(err)
	}

	var user = &models.User{
		EMail:    input.EMail,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return nil, errors.New("username already taken")

	}
	userLog.Printf("Created user %v\n", user.EMail)

	return &models.User{
		Id:    user.Id,
		EMail: user.EMail,
	}, nil
}

func (UserCRUD) Update(mail string, input models.CreateUpdateUserInput) (*models.User, error) {
	var user *models.User

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), 8)
	if err != nil {
		return nil, db.Errs(err)
	}
	if err := db.DB.Where("e_mail = ?", mail).
		First(&user).
		Updates(models.User{
			EMail:    input.EMail,
			Password: string(hashedPassword),
		}).Error; err != nil {
		return nil, db.Errs(err)
	}

	userLog.Printf("updated %v\n", user)

	return user, nil
}

func (UserCRUD) Delete(mail string) error {

	var user models.User

	if err := db.DB.Where("e_mail = ?", mail).
		First(&user).
		Delete(&user).
		Error; err != nil {
		return db.Errs(err)
	}
	return nil
}

func (UserCRUD) GetAllComponentOwners(compId string) ([]models.User, error) {
	var owners []models.User

	compIdInt, err := strconv.Atoi(compId)
	if err != nil {
		return nil, err
	}
	subQuery := db.DB.Table("component_owners").
		Select("user_id").
		Where("component_id = (?)", compIdInt)

	if err := db.DB.Where("id IN (?)", subQuery).
		Find(&owners).Error; err != nil {

		return nil, err
	}
	return owners, nil
}
