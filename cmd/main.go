package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
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

// generateCSRFToken generates a CSRF token.
func generateCSRFToken() string {
	// Generate a random byte slice
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		// Handle error
		return ""
	}

	// Encode the random bytes to base64 string
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token
}

// Check if a user is present in /etc/passwd
func validateUser(username string) (bool, error) {
	_, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

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

	router.GET("/api/adduser", jwtAuthMiddleware(), addUserAPIHandler)
	router.POST("/api/adduser", jwtAuthMiddleware(), addUserAPIHandler)

	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/adduser", showAddUserForm)
	router.GET("/login", loginHandler)
	router.POST("/login", loginPostHandler)
	router.GET("/logout", logoutAPIHandler)
	router.POST("/logout", logoutAPIHandler)
	router.GET("/configure_ssh", configureSSHHandler)
	router.POST("/api/addssh", jwtAuthMiddleware(), addSSHAPIHandler)
	router.POST("/api/configure_firewall", jwtAuthMiddleware(), configureFirewallAPIHandler)
	router.GET("/configure_firewall", configureFirewallHandler)

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

func generateJWTToken(username string, role string) (string, error) {
	// Set the expiration time for the token
	tokenExpiration := time.Now().Add(24 * time.Hour)

	// Create a new JWT Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
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
	c.HTML(http.StatusOK, "login.html", nil)
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

	// The role is hardcoded here as "admin" just for testing, I would usually expect this to come from a db or similar
	token, err := generateJWTToken(formData.Username, "admin")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate a token"})
		return
	}

	c.SetCookie("jwt", token, 3600, "/", "", false, true)
	c.HTML(http.StatusOK, "index.html", nil)
}

func logoutAPIHandler(c *gin.Context) {
	fmt.Println("Inside logoutAPIHandler")

	// Clear the JWT cookie
	c.SetCookie("jwt", "", -1, "/", "", false, true)
	fmt.Println("JWT cookie cleared")

	// Get the session
	session, err := store.Get(c.Request, "session")
	if err != nil {
		fmt.Println("Error getting session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
		return
	}

	// Clear the session
	session.Values["authenticated"] = false
	session.Options.MaxAge = -1
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		fmt.Println("Error saving session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear session"})
		return
	}
	fmt.Println("Session cleared")

	// Redirect to the login page
	c.Redirect(http.StatusTemporaryRedirect, "/login")
}

type FirewallRule struct {
	Protocol  string `json:"Protocol"`
	IpAddress string `json:"IpAddress"`
	Port      string `json:"Port"`
	Action    string `json:"Action"`
}

func ensureFirewallEnabled() error {
	cmd := exec.Command("sudo", "ufw", "status")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("could not check ufw status: %w", err)
	}

	if strings.Contains(string(output), "inactive") {
		cmd := exec.Command("sudo", "ufw", "enable")
		err = cmd.Run()

		if err != nil {
			return fmt.Errorf("could not enable ufw: %w", err)
		}
	}

	return nil
}

func configureFirewallAPIHandler(c *gin.Context) {
	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Missing CSRF token"})
		return
	}

	session, _ := store.Get(c.Request, "session")
	if session.Values["csrf"] != csrfToken {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid CSRF token"})
		return
	}
	var rule FirewallRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// IP check
	ip := net.ParseIP(rule.IpAddress)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	// Port check
	port, err := strconv.Atoi(rule.Port)
	if err != nil || port < 1 || port > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port number"})
		return
	}

	// Ensure that the firewall is enabled
	err = ensureFirewallEnabled()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to ensure firewall is enabled: %v", err)})
		return
	}

	// Run the ufw command to add the rule
	cmd := exec.Command("sudo", "ufw", rule.Action, "from", rule.IpAddress, "to", "any", "port", rule.Port)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Printf("stdout: %q\n", stdout.String())
		log.Printf("stderr: %q\n", stderr.String())
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to configure firewall: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Firewall configured successfully"})
}

func configureFirewallHandler(c *gin.Context) {
	// Generate CSRF token
	csrfToken := generateCSRFToken()

	// Get session
	session, _ := store.Get(c.Request, "session")

	// Store CSRF token in session
	session.Values["csrf"] = csrfToken
	err := session.Save(c.Request, c.Writer)
	if err != nil {
		// handle error
		log.Printf("Error saving session: %v", err)
		return
	}
	// Log the token so I can compare
	log.Printf("CSRF Token: %s", csrfToken)

	// Pass the CSRF token to the template
	c.HTML(http.StatusOK, "configure_firewall.html", gin.H{
		"csrfToken": csrfToken,
	})
}

func configureSSHHandler(c *gin.Context) {
	// Generate CSRF token
	csrfToken := generateCSRFToken()

	// Get session
	session, _ := store.Get(c.Request, "session")

	// Store CSRF token in session
	session.Values["csrf"] = csrfToken
	err := session.Save(c.Request, c.Writer)
	if err != nil {
		// handle error
		log.Printf("Error saving session: %v", err)
		return
	}
	// Log the token so I can compare
	log.Printf("CSRF Token: %s", csrfToken)

	// Pass the CSRF token to the template
	c.HTML(http.StatusOK, "configure_ssh.html", gin.H{
		"csrfToken": csrfToken,
	})
}

func addSSHAPIHandler(c *gin.Context) {
	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Missing CSRF token"})
		return
	}

	session, _ := store.Get(c.Request, "session")
	if session.Values["csrf"] != csrfToken {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid CSRF token"})
		return
	}
	username := c.PostForm("username")

	if _, err := user.Lookup(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "User does not exist"})
		return
	}

	privateKey, publicKey, err := generateSSHKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to generate SSH key pair"})
		return
	}

	sshDir := filepath.Join("/home", username, ".ssh")

	cmd := exec.Command("sudo", "mkdir", "-p", sshDir)
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to create .ssh directory: %v", err)})
		return
	}

	cmd = exec.Command("sudo", "chmod", "700", sshDir)
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to set permissions on .ssh directory: %v", err)})
		return
	}

	authorizedKeysFile := filepath.Join(sshDir, "authorized_keys")
	cmd = exec.Command("sudo", "sh", "-c", fmt.Sprintf("echo '%s' > %s", publicKey, authorizedKeysFile))
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to write public key to authorized_keys file"})
		return
	}

	cmd = exec.Command("sudo", "chmod", "600", authorizedKeysFile)
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to set permissions on authorized_keys file: %v", err)})
		return
	}

	cmd = exec.Command("sudo", "mkdir", "-p", "/root/.ssh")
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to create .ssh directory in root: %v", err)})
		return
	}

	cmd = exec.Command("sudo", "chmod", "700", "/root/.ssh")
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to set permissions on root's .ssh directory: %v", err)})
		return
	}

	privateKeyFile := filepath.Join("/root/.ssh", username+"_id_rsa")
	commandStr := fmt.Sprintf("echo -en '%s' > %s", privateKey, privateKeyFile)
	fmt.Println("Executing command:", commandStr) // Print the command
	cmd = exec.Command("sudo", "sh", "-c", commandStr)
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("Failed to write private key to file: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "SSH access added successfully"})
}

func generateSSHKeyPair() (privateKeyString string, publicKeyString string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	return string(privateKeyBytes), string(publicKeyBytes), nil
}

func showAddUserForm(c *gin.Context) {
	// Generate CSRF token
	csrfToken := generateCSRFToken()

	// Get session
	session, _ := store.Get(c.Request, "session")

	// Store CSRF token in session
	session.Values["csrf"] = csrfToken
	err := session.Save(c.Request, c.Writer)
	if err != nil {
		// handle error
		log.Printf("Error saving session: %v", err)
		return
	}
	// Log the token so I can compare
	log.Printf("CSRF Token: %s", csrfToken)

	// Pass the CSRF token to the template
	c.HTML(http.StatusOK, "add_user.html", gin.H{
		"csrfToken": csrfToken,
	})
}

func addUserAPIHandler(c *gin.Context) {
	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Missing CSRF token"})
		return
	}

	session, _ := store.Get(c.Request, "session")
	if session.Values["csrf"] != csrfToken {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid CSRF token"})
		return
	}

	formData := struct {
		Username string `form:"username" binding:"required"`
		Password string `form:"password" binding:"required"`
	}{}

	if err := c.ShouldBind(&formData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request format"})
		return
	}

	if !usernameRegexp.MatchString(formData.Username) || !passwordRegexp.MatchString(formData.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid username or password format"})
		return
	}

	// Execute the adduser command with sudo privileges
	cmd := exec.Command("sudo", "adduser", "--quiet", "--disabled-password", "--gecos", "", formData.Username)
	err := cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to add user"})
		return
	}

	// Set the password using the chpasswd command
	cmd = exec.Command("echo", fmt.Sprintf("%s:%s", formData.Username, formData.Password))
	out, err := cmd.Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to set password"})
		return
	}

	cmd = exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(string(out))
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to set password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "User added successfully"})
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

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["role"] != "admin" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Role"})
			return
		}

		c.Next()
	}
}
