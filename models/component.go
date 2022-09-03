package models

import "time"

type Component struct {
	Id              uint            `json:"id" gorm:"primary_key"`
	Name            string          `json:"name" form:"name"`
	Version         string          `json:"version" form:"version"`
	Cpe             string          `json:"cpe" form:"cpe" gorm:"unique"`
	VendorId        uint            `json:"-"`
	Vendor          Vendor          `json:"vendor" gorm:"ForeignKey:VendorId" form:"vendor"`
	Owners          []User          `json:"owners" gorm:"many2many:component_owners;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" gorm:"many2many:component_vulnerabilities;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	CreatedAt       time.Time       `json:"-"`
	UpdatedAt       time.Time       `json:"-"`
}

type CreateUpdateComponentInput struct {
	Name     string `json:"name" binding:"required"`
	Version  string `json:"version" binding:"required"`
	Cpe      string `json:"cpe" binding:"required,cpe"`
	VendorId uint   `json:"vendorId" binding:"required"`
}

func (c CreateUpdateComponentInput) TurnToComponent() *Component {
	return &Component{
		Name:     c.Name,
		Version:  c.Version,
		Cpe:      c.Cpe,
		VendorId: c.VendorId,
	}
}
