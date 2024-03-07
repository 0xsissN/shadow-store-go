package main

import (
	"encoding/gob"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("confidelity"))

func init() {
	store.Options.HttpOnly = true
	store.Options.Secure = true
	gob.Register(&User{})
}
