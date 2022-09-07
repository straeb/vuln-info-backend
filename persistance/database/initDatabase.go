package database

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vuln-info-backend/models"
)

var DB *gorm.DB

func ConnectDB(dsn string, debug bool) {

	var dbase *gorm.DB
	var err error

	if debug {
		dbase, err = gorm.Open(
			mysql.Open(dsn),
			&gorm.Config{
				Logger: logger.Default.LogMode(logger.Silent),
			})
		if err != nil {
			panic(err.Error())
		}

	} else {
		dbase, err = gorm.Open(
			mysql.Open(dsn),
			&gorm.Config{
				Logger: logger.Default.LogMode(logger.Silent),
			})
		if err != nil {
			panic(err.Error())
		}
	}

	err = dbase.AutoMigrate(
		&models.Vendor{},
		&models.User{},
	)
	//Stupid hack to force cpe forgeinKey as varchar, GORM won't do it
	//db.Exec("CREATE TABLE components (id BIGINT unsigned NOT NULL AUTO_INCREMENT, cpe_id varchar (191),  PRIMARY KEY ( id ));")
	err = dbase.AutoMigrate(
		&models.Component{},
		&models.Vulnerability{},
		&models.Cpe{},
		&models.Notification{},
	)

	if err != nil {
		panic(err.Error())
	}

	DB = dbase
}

func DropDB() {

	DB.Migrator().DropTable(
		&models.Vendor{},
		&models.User{},
		&models.Component{},
		&models.Vulnerability{},
		&models.Cpe{},
		&models.Notification{},
	)

	// m..n tables
	tables, _ := DB.Migrator().GetTables()

	for _, table := range tables {
		DB.Migrator().DropTable(table)

	}

}
