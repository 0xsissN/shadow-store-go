package main

import (
	"errors"
	"unicode"

	passwordValidator "github.com/wagslane/go-password-validator"
)

func (u *User) userInDatabase(user_shadow string) error {
	option := false
	for _, i := range user_shadow {
		if i == '@' {
			option = true
			break
		}
	}

	if option {
		query := "SELECT FROM * users WHERE email = ?"
		row := db.QueryRow(query, user_shadow)
		err := row.Scan(&u.ID, &u.USERNAME, &u.EMAIL, &u.HASH_PASS, &u.CREATED_AT, &u.ACTIVATE, &u.VER_PASS, &u.TIMEOUT)
		if err != nil {
			return err
		}

		return nil
	} else {
		query := "SELECT FROM * users WHERE username = ?"
		row := db.QueryRow(query, user_shadow)
		err := row.Scan(&u.ID, &u.USERNAME, &u.EMAIL, &u.HASH_PASS, &u.CREATED_AT, &u.ACTIVATE, &u.VER_PASS, &u.TIMEOUT)
		if err != nil {
			return err
		}

		return nil
	}

}

func (u *User) comprobationPassword(password_b string) error {
	if u.PASSWORD != password_b {
		return errors.New("passwords don't match")
	}

	return nil
}

func (u *User) validateUsername() error {
	for _, c := range u.USERNAME {
		if !unicode.IsLetter(c) {
			return errors.New("username must have only letters")
		}
	}

	lenUser := len(u.USERNAME)
	if lenUser < 4 || lenUser > 21 {
		return errors.New("the username size must be [4-21] characters")
	}

	return nil
}

func (u *User) validatePassword() error {
	err := passwordValidator.Validate(u.PASSWORD, minPasswordBits)

	return err
}
