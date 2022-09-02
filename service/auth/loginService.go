package auth

import (
	"golang.org/x/crypto/bcrypt"
	"vuln-info-backend/persistance/crud"
)

var user crud.UserCRUD

type LoginService interface {
	LoginUser(email string, password string) bool
}

func LoginUser(email string, password string) bool {

	usr, err := user.GetByMail(email)
	if usr.Id == 0 || err != nil {
		return false
	}
	if err = bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(password)); err != nil {
		return false
	}

	return true
}
