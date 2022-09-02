package models

type User struct {
	Id       uint   `json:"id" gorm:"primary_key"`
	EMail    string `json:"e_mail" binding:"required" gorm:"unique"`
	Password string `json:"-"`
}

type UserMail struct {
	EMail string `json:"e_mail"`
}

type CreateUpdateUserInput struct {
	EMail    string `json:"e_mail" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginCredentials struct {
	Email    string `form:"e_mail"`
	Password string `form:"password"`
}
