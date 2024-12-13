package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTCreationAndValidation(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"

	// Test valid token
	t.Run("Valid Token", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, time.Hour)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		gotUserID, err := ValidateJWT(token, secret)
		if err != nil {
			t.Errorf("Failed to validate token: %v", err)
		}

		if gotUserID != userID {
			t.Errorf("Got user ID %v, want %v", gotUserID, userID)
		}
	})

	// Test expired token
	t.Run("Expired Token", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, -time.Hour) // Expired 1 hour ago
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		_, err = ValidateJWT(token, secret)
		if err == nil {
			t.Error("Expected error for expired token, got nil")
		}
	})

	// Test invalid secret
	t.Run("Wrong Secret", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, time.Hour)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		_, err = ValidateJWT(token, "wrong-secret")
		if err == nil {
			t.Error("Expected error for wrong secret, got nil")
		}
	})
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		want        string
		expectError bool
	}{
		{
			name: "Valid Bearer Token",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:        "abc123",
			expectError: false,
		},
		{
			name:        "Missing Header",
			headers:     http.Header{},
			want:        "",
			expectError: true,
		},
		{
			name: "Invalid Format",
			headers: http.Header{
				"Authorization": []string{"NotBearer abc123"},
			},
			want:        "",
			expectError: true,
		},
		{
			name: "Missing Token",
			headers: http.Header{
				"Authorization": []string{"Bearer "},
			},
			want:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.expectError {
				t.Errorf("GetBearerToken() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if got != tt.want {
				t.Errorf("GetBearerToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	password := "mySecurePassword123"

	// Test password hashing
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword failed: %v", err)
	}
	if hash == password {
		t.Error("HashPassword didn't hash the password")
	}

	// Test password verification
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash failed for correct password: %v", err)
	}

	// Test wrong password
	err = CheckPasswordHash("wrongPassword", hash)
	if err == nil {
		t.Error("CheckPasswordHash passed for incorrect password")
	}
}
