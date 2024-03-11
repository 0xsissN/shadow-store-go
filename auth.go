package main

import (
	"encoding/gob"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("confidelity"))

func init() {
	store.Options.HttpOnly = true
	store.Options.Secure = true
	gob.Register(&User{})
}

func auth(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	_, ok := session.Values["authenticated"]

	if !ok {
		c.HTML(http.StatusForbidden, "login.html", nil)
		c.Abort()
		return
	}

	c.Next()
}
