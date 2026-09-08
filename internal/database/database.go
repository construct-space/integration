package database

import (
	"fmt"
	"log"
	"time"

	"construct/integration/internal/config"
	"construct/integration/internal/models"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is the process-wide handle. Set by Init at startup.
var DB *gorm.DB

func Init(cfg *config.Config) {
	var dialector gorm.Dialector
	switch cfg.DBDriver {
	case "postgres":
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPass, cfg.DBName)
		dialector = postgres.Open(dsn)
	default:
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			cfg.DBUser, cfg.DBPass, cfg.DBHost, cfg.DBPort, cfg.DBName)
		dialector = mysql.Open(dsn)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	DB = db
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(50)
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
	}
	if err := db.AutoMigrate(&models.Connection{}); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("integration DB ready: %s@%s:%s/%s", cfg.DBDriver, cfg.DBHost, cfg.DBPort, cfg.DBName)
}
