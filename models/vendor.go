package models

type Vendor struct {
	Id   uint   `json:"id" gorm:"primary_key" form:"id"`
	Name string `json:"name" form:"name" binding:"required"  gorm:"unique"`
}

type CreateUpdateVendorInput struct {
	Name string `json:"name" binding:"required"`
}
