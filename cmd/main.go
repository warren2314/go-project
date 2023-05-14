package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	jwtSecret       = os.Getenv("JWT_SECRET")
	sessionSecret   = os.Getenv("SESSION_SECRET")
	store           = sessions.NewCookieStore([]byte(sessionSecret))
	usernameRegexp  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	passwordRegexp  = regexp.MustCompile(`^[a-zA-Z0-9@#$%^&+=!]{8,}$`)
	uppercaseRegexp = regexp.MustCompile(`[A-Z]`)
	lowercaseRegexp = regexp.MustCompile(`[a-z]`)
	numberRegexp    = regexp.MustCompile(`[0-9]`)
	specialRegexp   = regexp.MustCompile(`[@#$%^&+=]`)
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	store.Options = &sessions.Options{
		MaxAge:   3600, //Session expiration time
		HttpOnly: true,
	}

	router := gin.Default()
	router.Static("/static", "./static")

	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/index", indexHandler)
	router.GET("/login", loginHandler)
	router.POST("/login", loginPostHandler)
	router.GET("/logout", logoutHandler)
	router.POST("/configure-firewall", configureFirewallHandler)
	router.POST("/configure-ssh", configureSSHHandler)
	//router.POST("/adduser", jwtAuthMiddleware(), addUserHandler)
	router.GET("/adduser", showAddUserForm)
	router.POST("/api/adduser", jwtAuthMiddleware(), addUserAPIHandler)

	router.Run(":8080")

}

func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	if !uppercaseRegexp.MatchString(password) {
		return false
	}
	if !lowercaseRegexp.MatchString(password) {
		return false
	}
	if !numberRegexp.MatchString(password) {
		return false
	}
	if !specialRegexp.MatchString(password) {
		return false
	}
	return true
}

func generateJWTToken(username string) (string, error) {
	// Set the expiration time for the token
	tokenExpiration := time.Now().Add(24 * time.Hour)

	// Create a new JWT Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      tokenExpiration.Unix(),
	})

	// Sign the token with a secret key
	signedToken, err := token.SignedString([]byte(jwtSecret))

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func loginHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func isMatch(pattern, value string) bool {
	match, _ := regexp.MatchString(pattern, value)
	return match
}

func loginPostHandler(c *gin.Context) {
	formData := struct {
		Username string `form:"username" binding:"required"`
		Password string `form:"password" binding:"required"`
	}{}

	if err := c.ShouldBind(&formData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	webUsername := os.Getenv("WEB_USERNAME")
	webPassword := os.Getenv("WEB_PASSWORD")

	if !usernameRegexp.MatchString(formData.Username) || !passwordRegexp.MatchString(formData.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username or password format"})
		return
	}

	if formData.Username != webUsername || formData.Password != webPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateJWTToken(formData.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate a token"})
		return
	}

	c.SetCookie("jwt", token, 3600, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/index")
}

func logoutHandler(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	session.Values["authenticated"] = false
	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")
}

func configureFirewallHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "configure_firewall.html", nil)
}

func configureSSHHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "configure_firewall.html", nil)
}

func showAddUserForm(c *gin.Context) {
	c.HTML(http.StatusOK, "add_user.html", nil)
}

func addUserAPIHandler(c *gin.Context) {
	formData := struct {
		Username string `form:"username" binding:"required"`
		Password string `form:"password" binding:"required"`
	}{}

	if err := c.ShouldBind(&formData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !usernameRegexp.MatchString(formData.Username) || !passwordRegexp.MatchString(formData.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username or password format"})
		return
	}

	// Execute the adduser command with sudo privileges
	cmd := exec.Command("sudo", "adduser", "--quiet", "--disabled-password", "--gecos", "", formData.Username)
	err := cmd.Run()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to add user")
		return
	}

	// Set the password using the chpasswd command
	cmd = exec.Command("echo", fmt.Sprintf("%s:%s", formData.Username, formData.Password))
	out, err := cmd.Output()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to set password")
		return
	}

	cmd = exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(string(out))
	err = cmd.Run()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to set password")
		return
	}

	c.String(http.StatusOK, "User added successfully")
}

func jwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to retrieve the token from the Authorization header
		tokenString := c.GetHeader("Authorization")

		// If it's not there, try to get it from a cookie
		if tokenString == "" {
			var err error
			tokenString, err = c.Cookie("jwt")
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header or cookie provided"})
				return
			}
		}

		// If it's in the form "Bearer <token>", remove "Bearer "
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Token"})
			return
		}
		c.Next()
	}
}
