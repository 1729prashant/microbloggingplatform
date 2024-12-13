package auth

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword takes a plain text password and returns a hashed version
func HashPassword(password string) (string, error) {
	passwordByte := []byte(password)
	hashedPassword, err := bcrypt.GenerateFromPassword(passwordByte, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword[:]), nil
}

// CheckPasswordHash compares a plain text password with a hashed password
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
