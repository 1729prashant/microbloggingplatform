package auth

import (
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	passwordByte := []byte(password)
	hashedPassword, err := bcrypt.GenerateFromPassword(passwordByte, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return string(hashedPassword[:]), nil
}

func CheckPasswordHash(password, hash string) error {
	passwordByte := []byte(password)
	hashedPasswordByte := []byte(hash)

	err := bcrypt.CompareHashAndPassword(hashedPasswordByte, passwordByte)
	if err != nil {
		return err
	}

	return nil
}
