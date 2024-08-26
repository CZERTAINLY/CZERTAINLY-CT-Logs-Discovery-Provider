package db

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/config"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/logger"
	"errors"
	"fmt"
	"github.com/golang-migrate/migrate/v4"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var log = logger.Get()

func ConnectDB(config config.Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=%s search_path=%s %s", config.Database.Username, config.Database.Password, config.Database.Host, config.Database.Port, config.Database.Name, config.Database.SslMode, config.Database.Schema, config.Database.Props)
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   config.Database.Schema + ".",
			SingularTable: false,
		},
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	return
}

func MigrateDB(config config.Config) {
	log.Info("Migrating database")
	// search_path=public&x-migrations-table=hvault_migrations migration table name and schema, migration table must be in public schema if we want to create schema automatically
	connectionString := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?search_path=%s&x-migrations-table=%s_migrations&sslmode=%s", config.Database.Username, config.Database.Password, config.Database.Host, config.Database.Port, config.Database.Name, config.Database.Schema, config.Database.Schema, config.Database.SslMode)
	// log.Info("Connection string: " + connectionString)
	m, err := migrate.New(
		"file://migrations",
		connectionString,
	)
	if err != nil {
		log.Error(err.Error())
	}
	if err := m.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			{
				log.Error(err.Error())
			}
		}
	}
}
