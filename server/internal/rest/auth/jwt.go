// internal/rest/auth/jwt.go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserInactive       = errors.New("user account is inactive")
)

type JWTManager struct {
	secretKey     []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	db            *sql.DB
}

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type User struct {
	ID           string
	Username     string
	PasswordHash string
	IsActive     bool
}

func NewJWTManager(secretKey string, accessExpiry, refreshExpiry time.Duration, db *sql.DB) *JWTManager {
	return &JWTManager{
		secretKey:     []byte(secretKey),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		db:            db,
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateTokenPair creates a new access and refresh token pair
func (m *JWTManager) GenerateTokenPair(user *User) (*TokenPair, error) {
	// Generate access token
	accessClaims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "nexusc2-api",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(m.secretKey)
	if err != nil {
		return nil, err
	}

	// Generate refresh token (random string)
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshTokenBytes)

	// Hash and store refresh token
	refreshTokenHash := hashToken(refreshToken)
	expiresAt := time.Now().Add(m.refreshExpiry)

	_, err = m.db.Exec(`
		INSERT INTO api_tokens (user_id, refresh_token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, refreshTokenHash, expiresAt)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(m.accessExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ValidateAccessToken validates an access token and returns the claims
func (m *JWTManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// RefreshResult contains the token pair and user info
type RefreshResult struct {
	TokenPair *TokenPair
	Username  string
}

// RefreshTokens validates a refresh token and generates a new token pair
func (m *JWTManager) RefreshTokens(refreshToken string) (*RefreshResult, error) {
	refreshTokenHash := hashToken(refreshToken)

	// Find the refresh token
	var userID string
	var expiresAt time.Time
	var tokenID string
	err := m.db.QueryRow(`
		SELECT id, user_id, expires_at
		FROM api_tokens
		WHERE refresh_token_hash = $1
	`, refreshTokenHash).Scan(&tokenID, &userID, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		// Delete expired token
		m.db.Exec("DELETE FROM api_tokens WHERE id = $1", tokenID)
		return nil, ErrTokenExpired
	}

	// Get user
	var user User
	err = m.db.QueryRow(`
		SELECT id, username, password_hash, is_active
		FROM api_users
		WHERE id = $1
	`, userID).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.IsActive)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Delete the old refresh token
	m.db.Exec("DELETE FROM api_tokens WHERE id = $1", tokenID)

	// Generate new token pair
	tokenPair, err := m.GenerateTokenPair(&user)
	if err != nil {
		return nil, err
	}

	return &RefreshResult{
		TokenPair: tokenPair,
		Username:  user.Username,
	}, nil
}

// InvalidateRefreshToken invalidates a refresh token (logout)
func (m *JWTManager) InvalidateRefreshToken(refreshToken string) error {
	refreshTokenHash := hashToken(refreshToken)
	_, err := m.db.Exec("DELETE FROM api_tokens WHERE refresh_token_hash = $1", refreshTokenHash)
	return err
}

// InvalidateAllUserTokens invalidates all refresh tokens for a user
func (m *JWTManager) InvalidateAllUserTokens(userID string) error {
	_, err := m.db.Exec("DELETE FROM api_tokens WHERE user_id = $1", userID)
	return err
}

// Authenticate validates user credentials and returns a token pair
func (m *JWTManager) Authenticate(username, password string) (*TokenPair, error) {
	var user User
	err := m.db.QueryRow(`
		SELECT id, username, password_hash, is_active
		FROM api_users
		WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.IsActive)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	if !CheckPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	// Update last login
	m.db.Exec("UPDATE api_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", user.ID)

	return m.GenerateTokenPair(&user)
}

// CreateUser creates a new API user
func (m *JWTManager) CreateUser(username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`
		INSERT INTO api_users (username, password_hash)
		VALUES ($1, $2)
	`, username, hash)

	return err
}

// AuthenticateByUsername authenticates a user by username only (cert-based auth)
// This auto-provisions the user if they don't exist
func (m *JWTManager) AuthenticateByUsername(username string) (*TokenPair, error) {
	var user User

	// Try to find existing user
	err := m.db.QueryRow(`
		SELECT id, username, password_hash, is_active
		FROM api_users
		WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.IsActive)

	if err == sql.ErrNoRows {
		// Auto-provision new user (no password needed for cert auth)
		var userID string
		err = m.db.QueryRow(`
			INSERT INTO api_users (username, password_hash, is_active)
			VALUES ($1, '', true)
			RETURNING id
		`, username).Scan(&userID)
		if err != nil {
			return nil, err
		}
		user = User{
			ID:       userID,
			Username: username,
			IsActive: true,
		}
	} else if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Update last login
	m.db.Exec("UPDATE api_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", user.ID)

	return m.GenerateTokenPair(&user)
}

// CleanupExpiredTokens removes expired refresh tokens
func (m *JWTManager) CleanupExpiredTokens() error {
	_, err := m.db.Exec("DELETE FROM api_tokens WHERE expires_at < CURRENT_TIMESTAMP")
	return err
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
