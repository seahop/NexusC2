// internal/rest/auth/jwt_test.go
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()

	t.Run("hashes password successfully", func(t *testing.T) {
		t.Parallel()
		hash, err := HashPassword("testpassword123")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if hash == "" {
			t.Fatal("HashPassword returned empty hash")
		}
		if hash == "testpassword123" {
			t.Fatal("HashPassword returned plaintext password")
		}
	})

	t.Run("different passwords produce different hashes", func(t *testing.T) {
		t.Parallel()
		hash1, err := HashPassword("password1")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		hash2, err := HashPassword("password2")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("different passwords produced same hash")
		}
	})

	t.Run("same password produces different hashes due to salt", func(t *testing.T) {
		t.Parallel()
		hash1, err := HashPassword("samepassword")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		hash2, err := HashPassword("samepassword")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatal("bcrypt should produce different hashes for same password (different salts)")
		}
	})
}

func TestCheckPassword(t *testing.T) {
	t.Parallel()

	t.Run("correct password returns true", func(t *testing.T) {
		t.Parallel()
		hash, err := HashPassword("correctpassword")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if !CheckPassword("correctpassword", hash) {
			t.Fatal("CheckPassword returned false for correct password")
		}
	})

	t.Run("wrong password returns false", func(t *testing.T) {
		t.Parallel()
		hash, err := HashPassword("correctpassword")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if CheckPassword("wrongpassword", hash) {
			t.Fatal("CheckPassword returned true for wrong password")
		}
	})

	t.Run("empty password against valid hash returns false", func(t *testing.T) {
		t.Parallel()
		hash, err := HashPassword("somepassword")
		if err != nil {
			t.Fatalf("HashPassword returned error: %v", err)
		}
		if CheckPassword("", hash) {
			t.Fatal("CheckPassword returned true for empty password")
		}
	})

	t.Run("invalid hash returns false", func(t *testing.T) {
		t.Parallel()
		if CheckPassword("anypassword", "notavalidhash") {
			t.Fatal("CheckPassword returned true for invalid hash")
		}
	})
}

func TestValidateAccessToken(t *testing.T) {
	t.Parallel()

	secret := "test-secret-key-for-jwt-testing"
	manager := NewJWTManager(secret, 15*time.Minute, 24*time.Hour, nil)

	t.Run("valid token is accepted", func(t *testing.T) {
		t.Parallel()
		claims := Claims{
			UserID:   "user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "nexusc2-api",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		result, err := manager.ValidateAccessToken(tokenString)
		if err != nil {
			t.Fatalf("ValidateAccessToken returned error for valid token: %v", err)
		}
		if result.UserID != "user-123" {
			t.Errorf("expected UserID 'user-123', got '%s'", result.UserID)
		}
		if result.Username != "testuser" {
			t.Errorf("expected Username 'testuser', got '%s'", result.Username)
		}
	})

	t.Run("expired token returns ErrTokenExpired", func(t *testing.T) {
		t.Parallel()
		claims := Claims{
			UserID:   "user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				Issuer:    "nexusc2-api",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		_, err = manager.ValidateAccessToken(tokenString)
		if err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("wrong signing key returns ErrInvalidToken", func(t *testing.T) {
		t.Parallel()
		claims := Claims{
			UserID:   "user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "nexusc2-api",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("wrong-secret-key"))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		_, err = manager.ValidateAccessToken(tokenString)
		if err != ErrInvalidToken {
			t.Errorf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("malformed token returns ErrInvalidToken", func(t *testing.T) {
		t.Parallel()
		_, err := manager.ValidateAccessToken("not.a.valid.jwt.token")
		if err != ErrInvalidToken {
			t.Errorf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("empty token returns ErrInvalidToken", func(t *testing.T) {
		t.Parallel()
		_, err := manager.ValidateAccessToken("")
		if err != ErrInvalidToken {
			t.Errorf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("token signed with different algorithm is rejected", func(t *testing.T) {
		t.Parallel()
		// Attempt to use 'none' algorithm (algorithm confusion attack)
		claims := Claims{
			UserID:   "user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "nexusc2-api",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("failed to sign token with none: %v", err)
		}

		_, err = manager.ValidateAccessToken(tokenString)
		if err == nil {
			t.Fatal("ValidateAccessToken should reject tokens signed with 'none' algorithm")
		}
	})
}

func TestValidateAccessToken_TableDriven(t *testing.T) {
	t.Parallel()

	secret := "table-driven-test-secret"
	manager := NewJWTManager(secret, 15*time.Minute, 24*time.Hour, nil)

	makeToken := func(userID, username string, expiry time.Duration, signingKey string) string {
		claims := Claims{
			UserID:   userID,
			Username: username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "nexusc2-api",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte(signingKey))
		return tokenString
	}

	tests := []struct {
		name        string
		token       string
		wantErr     error
		wantUserID  string
	}{
		{
			name:       "valid token with correct key",
			token:      makeToken("uid-1", "alice", 10*time.Minute, secret),
			wantErr:    nil,
			wantUserID: "uid-1",
		},
		{
			name:    "expired token",
			token:   makeToken("uid-2", "bob", -5*time.Minute, secret),
			wantErr: ErrTokenExpired,
		},
		{
			name:    "wrong signing key",
			token:   makeToken("uid-3", "charlie", 10*time.Minute, "wrong-key"),
			wantErr: ErrInvalidToken,
		},
		{
			name:    "garbage token",
			token:   "garbage.data.here",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims, err := manager.ValidateAccessToken(tt.token)
			if err != tt.wantErr {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if tt.wantErr == nil && claims.UserID != tt.wantUserID {
				t.Errorf("expected UserID %q, got %q", tt.wantUserID, claims.UserID)
			}
		})
	}
}

func TestNewJWTManager(t *testing.T) {
	t.Parallel()

	t.Run("creates manager with correct settings", func(t *testing.T) {
		t.Parallel()
		m := NewJWTManager("secret", 30*time.Minute, 48*time.Hour, nil)
		if m == nil {
			t.Fatal("NewJWTManager returned nil")
		}
		if string(m.secretKey) != "secret" {
			t.Errorf("expected secret key 'secret', got '%s'", string(m.secretKey))
		}
		if m.accessExpiry != 30*time.Minute {
			t.Errorf("expected access expiry 30m, got %v", m.accessExpiry)
		}
		if m.refreshExpiry != 48*time.Hour {
			t.Errorf("expected refresh expiry 48h, got %v", m.refreshExpiry)
		}
	})
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	t.Run("produces consistent SHA256 hex output", func(t *testing.T) {
		t.Parallel()
		input := "test-refresh-token"
		result := hashToken(input)

		// Verify against manual SHA256
		expected := sha256.Sum256([]byte(input))
		expectedHex := hex.EncodeToString(expected[:])
		if result != expectedHex {
			t.Errorf("hashToken result mismatch: got %s, want %s", result, expectedHex)
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		t.Parallel()
		hash1 := hashToken("token-a")
		hash2 := hashToken("token-b")
		if hash1 == hash2 {
			t.Fatal("different inputs produced same hash")
		}
	})

	t.Run("output is 64 hex characters", func(t *testing.T) {
		t.Parallel()
		result := hashToken("some-token")
		if len(result) != 64 {
			t.Errorf("expected 64 hex chars (SHA256), got %d", len(result))
		}
	})
}

func TestClaimsStructure(t *testing.T) {
	t.Parallel()

	t.Run("claims embed registered claims correctly", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		claims := Claims{
			UserID:   "user-abc",
			Username: "admin",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
				Issuer:    "nexusc2-api",
			},
		}

		if claims.UserID != "user-abc" {
			t.Errorf("UserID mismatch")
		}
		if claims.Issuer != "nexusc2-api" {
			t.Errorf("Issuer mismatch")
		}
	})
}
