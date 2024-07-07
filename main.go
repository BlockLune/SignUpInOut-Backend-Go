package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/dchest/captcha"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id",omitempty`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Credentials struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

var db *sql.DB

func DBInit() {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY, 
			email VARCHAR(255) NOT NULL, 
			password VARCHAR(255) NOT NULL
		)`)
	if err != nil {
		panic(err)
	}
}

func DBSignUp(user User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
	return err
}

func DBSignIn(credentials Credentials) (User, error) {
	var user User
	row := db.QueryRow("SELECT * FROM users WHERE email = ?", credentials.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	return user, err
}

func GenerateCaptchaHandler(c *gin.Context) {
	captchaId := captcha.New()
	c.JSON(http.StatusOK, gin.H{"captchaId": captchaId})
}

func CaptchaImageHandler(c *gin.Context) {
	captchaId := c.Param("captchaId")
	if captchaId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Captcha ID is required"})
		return
	}

	c.Header("Content-Type", "image/png")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	if err := captcha.WriteImage(c.Writer, captchaId, captcha.StdWidth, captcha.StdHeight); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate captcha image"})
	}
}

func SignUpHandler(c *gin.Context) {
	var request struct {
		User
		CaptchaId     string `json:"captchaId" binding:"required"`
		CaptchaAnswer string `json:"captchaAnswer" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !captcha.VerifyString(request.CaptchaId, request.CaptchaAnswer) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid captcha"})
		return
	}

	err := DBSignUp(request.User)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func SignInHandler(c *gin.Context) {
	var credentials Credentials
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, err := DBSignIn(credentials)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	DBInit()

	router := gin.Default()

	config := cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}
	router.Use(cors.New(config))
	router.GET("/api/captcha", GenerateCaptchaHandler)
	router.GET("/api/captcha/:captchaId", CaptchaImageHandler)
	router.POST("/api/users", SignUpHandler)
	router.POST("/api/users/signin", SignInHandler)
	router.Run("localhost:8080")
}
