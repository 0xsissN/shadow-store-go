package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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
	server.Static("/public/store/images", "./templates/public/store/images")
	server.Static("/public/store/css", "./templates/public/store/css")
	server.Static("/private/store-user/css", "./templates/private/store-user/css")
	server.Static("/private/store-user/images", "./templates/private/store-user/images")

	server.GET("/", getIndex)
	server.GET("/games", gamesStore)
	server.GET("/about", aboutStore)

	server.GET("/login", getLogin)
	server.POST("/login", postLogin)
	server.GET("/register", getRegister)
	server.POST("/register", postRegister)
	server.GET("/emailverification/:username/:verpass", getEmail)
	server.GET("/passwordrecovery", getRecoveryPassword)
	server.POST("/passwordrecovery", postRecoveryPassword)
	server.GET("/accountrecovery/:username/:verpass", getEmailRecovery)
	server.POST("/accountchangepassword/:username/:verpass", postNewPassword)

	authUser := server.Group("/user", auth)
	authUser.GET("/profile", getProfile)
	authUser.GET("/logout", getLogOut)

	authUser.GET("/uindex", getUIndex)
	authUser.GET("/ustore", getUStore)
	authUser.GET("/unews", getUNews)
	authUser.GET("/uevents", getUEvents)
	authUser.GET("/uabout", getUAbout)

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
	session, err := store.Get(c.Request, "session")
	if err == nil {
		session.Options.MaxAge = -1
		session.Save(c.Request, c.Writer)
	}

	c.HTML(http.StatusOK, "index.html", nil)
}

func gamesStore(c *gin.Context) {
	c.HTML(http.StatusOK, "store.html", nil)
}

func aboutStore(c *gin.Context) {
	c.HTML(http.StatusOK, "about.html", nil)
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

	c.Redirect(http.StatusSeeOther, "/user/uindex")
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

	err = u.validateEmail()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": err})
		return
	}

	user_exist := u.comprobationUser()
	if user_exist {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": err})
		return
	}

	err = u.createNewUser()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"message": "Error to create new account, try again"})
		return
	}

	c.HTML(http.StatusOK, "succ-register.html", nil)
}

func getEmail(c *gin.Context) {
	var u User
	var err error

	username := c.Param("username")
	verPass := c.Param("verpass")

	err = u.userInDatabase(username)
	if err != nil {
		c.HTML(http.StatusBadRequest, "succ-register.html", gin.H{"message": err})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.VER_PASS), []byte(verPass))
	if err != nil {
		c.HTML(http.StatusBadRequest, "succ-register.html", gin.H{"message": err})
		return
	}

	err = u.makeActive()
	if err != nil {
		c.HTML(http.StatusBadRequest, "succ-register.html", gin.H{"message": err})
		return
	}

	c.HTML(http.StatusOK, "acc-user.html", nil)
}

func getProfile(c *gin.Context) {
	var err error
	session, err := store.Get(c.Request, "session")
	if err != nil {
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		c.HTML(http.StatusForbidden, "login.html", nil)
		return
	}

	var u User
	var ok bool

	u.ID, ok = session.Values["userid"].(string)
	if !ok {
		c.HTML(http.StatusForbidden, "login.html", nil)
		return
	}

	err = u.comprobationId()
	if err != nil {
		c.HTML(http.StatusForbidden, "login.html", nil)
		return
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{"user": u})
}

func getLogOut(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		return
	}

	delete(session.Values, "authenticated")
	delete(session.Values, "userid")
	session.Options.MaxAge = -1
	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusSeeOther, "/")
}

func getUIndex(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	c.HTML(http.StatusOK, "u-index.html", nil)
}

func getUStore(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	c.HTML(http.StatusOK, "u-store.html", nil)
}

func getUNews(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	c.HTML(http.StatusOK, "u-news.html", nil)
}

func getUEvents(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	c.HTML(http.StatusOK, "u-events.html", nil)
}

func getUAbout(c *gin.Context) {
	session, err := store.Get(c.Request, "session")
	if err != nil {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		c.Redirect(http.StatusForbidden, "/")
		return
	}

	c.HTML(http.StatusOK, "u-about.html", nil)
}

func getRecoveryPassword(c *gin.Context) {
	c.HTML(http.StatusOK, "recovery.html", nil)
}

func postRecoveryPassword(c *gin.Context) {
	var u User
	var err error

	user_shadow := c.PostForm("user-email")
	err = u.userInDatabase(user_shadow)
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Email dont exist, please create account"})
		return
	}

	var verificationPass string
	verificationPass, u.VER_PASS, err = u.newVerPass()
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	timeout := time.Now().Add(2 * time.Hour)

	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		return
	}

	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				fmt.Println(rollbackErr)
			}
			c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
			return
		}

		err = tx.Commit()
	}()

	var updateData *sql.Stmt
	updateData, err = tx.Prepare("UPDATE users SET ver_pass = ?, timeout_user = ? WHERE email = ?")
	if err != nil {
		return
	}

	var execData sql.Result
	execData, err = updateData.Exec(u.VER_PASS, timeout, user_shadow)
	if err != nil {
		return
	}

	rowAff, err := execData.RowsAffected()
	if rowAff == 0 {
		return
	}

	subject := "Account Recovery"
	htmlContent := fmt.Sprintf(`
		<h1>Account recovery</h1>
		<a href="http://localhost:8081/accountrecovery/%s/%s">Change Password</a>
	`, user_shadow, verificationPass)

	err = u.sendEmail(htmlContent, subject, user_shadow)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println(rollbackErr)
		}

		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	c.HTML(http.StatusOK, "check-recovery.html", nil)
}

func getEmailRecovery(c *gin.Context) {
	var u User
	var err error

	user_shadow := c.Param("username")
	linkVerPass := c.Param("verpass")

	err = u.userInDatabase(user_shadow)
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "User don't exist, please create an account"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.VER_PASS), []byte(linkVerPass))
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	currentTime := time.Now()
	var timeout time.Time

	timeout, err = time.Parse("2006-01-02 15:04:05.999999999", u.TIMEOUT)
	if err != nil {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	if currentTime.After(timeout) {
		c.HTML(http.StatusBadRequest, "recovery.html", gin.H{"message": "Was unable to send recovery email, try again"})
		return
	}

	c.HTML(http.StatusOK, "email-change.html", gin.H{
		"user":    u,
		"verpass": linkVerPass,
	})
}

func postNewPassword(c *gin.Context) {

}
