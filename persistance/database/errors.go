package database

import (
	"errors"
	"gorm.io/gorm"
)

// errs returns generic errors to keep the db state locked

func Errs(e error) error {

	if errors.Is(e, gorm.ErrRecordNotFound) {
		return e
	}
	if errors.Is(e, gorm.ErrEmptySlice) ||
		errors.Is(e, gorm.ErrMissingWhereClause) ||
		errors.Is(e, gorm.ErrInvalidField) ||
		errors.Is(e, gorm.ErrInvalidValueOfLength) {

		return errors.New("invalid values")

	} else {
		return errors.New("something went wrong")

	}

}

var InvIdErr = errors.New("invalid id")
