package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
)

// loginRequest is the expected JSON body for the login endpoint.
type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login authenticates a user with email + password and returns a signed JWT.
//
// POST /api/v1/auth/login
// Body: {"email":"...","password":"..."}
// Response: {"success":true,"data":{"token":"...","user":{...}}}
func Login(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	var user models.User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Return generic message to avoid user enumeration.
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid email or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid email or password"})
		return
	}

	token, err := generateJWT(user, getJWTSecret(c))
	if err != nil {
		log.Printf("[auth] failed to generate token for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not generate token"})
		return
	}

	writeAudit(c, db, &user.ID, nil, "auth.login", user.ID.String(), "user logged in")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"token": token,
			"user":  user,
		},
	})
}

// Me returns the currently authenticated user's profile.
//
// GET /api/v1/auth/me
// Requires: Authorization: Bearer <token>
func Me(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "not authenticated"})
		return
	}

	var user models.User
	if err := db.First(&user, "id = ?", userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "user not found"})
			return
		}
		log.Printf("[auth] me lookup error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": user})
}

// generateJWT creates a signed HS256 JWT for user, valid for 24 hours.
func generateJWT(user models.User, secret string) (string, error) {
	claims := middleware.Claims{
		UserID: user.ID.String(),
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
