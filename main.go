package main

import (
	"bufio"
	"log"
	"net/http"
	"os"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const minPasswordBits = 60

var verifier = emailverifier.NewVerifier()

func init() {
	verifier = verifier.EnableDomainSuggest()
	dispDomains := disposableDomains()
	verifier = verifier.AddDisposableDomains(dispDomains)
}

func main() {
	server := gin.Default()
	server.LoadHTMLGlob("templates/*/*/*.html")

	server.GET("/", getIndex)
	server.GET("/login", getLogin)
	server.POST("/login", postLogin)
	server.GET("/register", getRegister)
	server.POST("/register", postRegister)

	err := server.Run(":8081")
	if err != nil {
		panic(err)
	}
}

func disposableDomains() (dispDomains []string) {
	file, err := os.Open("blacklist-domains.txt")
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		dispDomains = append(dispDomains, scanner.Text())
	}

	return dispDomains
}

func getIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func getLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func postLogin(c *gin.Context) {
	var u User
	var err error

	user_shadow := c.PostForm("user-email-shadow")
	password_shadow := c.PostForm("password-shadow")

	err = u.userInDatabase(user_shadow)
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": "Unregistered user"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.HASH_PASS), []byte(password_shadow))
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": "Password doesn't match"})
		return
	}

	session, err := store.Get(c.Request, "session")
	if err != nil {
		return
	}

	session.Values["authenticated"] = true
	session.Values["userid"] = u.ID
	session.Save(c.Request, c.Writer)

	c.HTML(http.StatusOK, "succ-login.html", gin.H{"user": u.USERNAME})
}

func getRegister(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", nil)
}

func postRegister(c *gin.Context) {
	var u User
	var err error

	u.USERNAME = c.PostForm("user-shadow")
	u.EMAIL = c.PostForm("email-shadow")
	u.PASSWORD = c.PostForm("password-a-shadow")
	bPassword := c.PostForm("password-b-shadow")

	err = u.comprobationPassword(bPassword)
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": err})
		return
	}

	err = u.validateUsername()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": err})
		return
	}

	err = u.validatePassword()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": err})
		return
	}
}
