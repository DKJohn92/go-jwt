package initializers

import (
	"go-jwt/models"
	"log"
)

func SyncDatabase() {
	if DB == nil {
		log.Fatal("Database connection is not initialized")
	}
	DB.AutoMigrate(&models.User{})
}
