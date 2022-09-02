package models

type Cpe struct {
	Id string `json:"cpe" gorm:"primary_key"` //form:"cpe"`
}

type CpeCollection struct {
	Cpes []Cpe `json:"cpes"`
}
