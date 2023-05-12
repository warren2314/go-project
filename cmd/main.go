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
	"strings"
	"time"
)

var (
	jwtSecret     = os.Getenv("JWT_SECRET")
	sessionSecret = os.Getenv("SESSION_SECRET")
	store         = sessions.NewCookieStore([]byte(sessionSecret))
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	router := gin.Default()
	router.Static("/static", "./static")

	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/login", loginHandler)
	router.POST("/login", loginPostHandler)
	router.GET("/logout", logoutHandler)
	router.POST("/configure-firewall", configureFirewallHandler)
	router.POST("/configure-ssh", configureSSHHandler)
	router.POST("/adduser", jwtAuthMiddleware(), addUserHandler)
	router.GET("/adduser", showAddUserForm)
	router.POST("/api/adduser", addUserAPIHandler)

	router.Run(":8080")

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

func loginPostHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	webUsername := os.Getenv("WEB_USERNAME")
	webPassword := os.Getenv("WEB_PASSWORD")

	if username != webUsername || password != webPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateJWTToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate a token"})
		return
	}
	// Set Cookie usage
	c.SetCookie("jwt", token, 3600, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/adduser")
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
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Execute the adduser command with sudo privileges
	cmd := exec.Command("sudo", "adduser", "--quiet", "--disabled-password", "--gecos", "", username)
	err := cmd.Run()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to add user")
		return
	}

	// Set the password using the chpasswd command
	cmd = exec.Command("echo", fmt.Sprintf("%s:%s", username, password))
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

func addUserHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	cmd := exec.Command("sudo", "adduser", "--quiet", "--disabled-password", "--gecos", "", username)
	err := cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user"})
		return
	}

	cmd = exec.Command("echo", fmt.Sprintf("%s:%s", username, password))
	out, err := cmd.Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
		return
	}

	cmd = exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(string(out))
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User added successfully"})
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
