package main

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"time"
	"unicode"

	passwordValidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
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

func (u *User) validateEmail() error {
	mail, err := verifier.Verify(u.EMAIL)
	if err != nil {
		return err
	}

	if !mail.Syntax.Valid {
		return errors.New("invalid email syntax")
	}

	if mail.Disposable {
		return errors.New("email disposable")
	}

	if !mail.HasMxRecords {
		return errors.New("error email")
	}

	return nil
}

func (u *User) comprobationUser() bool {
	exist := true
	query := "SELECT id FROM users WHERE username = ?"
	row := db.QueryRow(query, u.USERNAME)

	err := row.Scan(&u.ID)
	if err == sql.ErrNoRows {
		exist = false
	}

	return exist
}

func (u *User) createNewUser() error {
	var err error
	var hashPass []byte
	hashPass, err = bcrypt.GenerateFromPassword([]byte(u.PASSWORD), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	rand.NewSource(time.Now().UnixNano())

	var alphabeticRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	emailVerificationRune := make([]rune, 64)

	for i := 0; i < 64; i++ {
		emailVerificationRune[i] = alphabeticRunes[rand.Intn(len(alphabeticRunes)-1)]
	}

	generateVerHash := string(emailVerificationRune)

	var strVerHash []byte
	strVerHash, err = bcrypt.GenerateFromPassword([]byte(generateVerHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.VER_PASS = string(strVerHash)

	createdAt := time.Now().Local()
	timeout := time.Now().Local().AddDate(0, 0, 2)

	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				fmt.Println(rollbackErr)
			}

			return
		}

		err = tx.Commit()
	}()

	var prepareData *sql.Stmt
	prepareData, err = tx.Prepare("INSERT INTO users (username, email, hash_pass, created_at, activate, ver_pass, timeout_user) VALUES(?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	var execData sql.Result
	execData, err = prepareData.Exec(u.USERNAME, u.EMAIL, hashPass, createdAt, 0, u.VER_PASS, timeout)
	if err != nil {
		return err
	}

	rowAff, err := execData.RowsAffected()
	if err != nil {
		return err
	}

	if rowAff == 0 {
		return errors.New("changes don't save")
	}

	// Email send
	subject := "Verification account"
	htmlContect := fmt.Sprintf(`
		<h1>Activate account</h1>
		<a href="http://localhost:8081/emailverification/%s/%s">Click to verify email</a>			
	`, u.USERNAME, generateVerHash)

	err = u.sendEmail(htmlContect, subject, u.EMAIL)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println(rollbackErr)
		}

		return err
	}

	return nil
}

func (u *User) makeActive() error {
	var err error
	query, err := db.Prepare("UPDATE users SET active = true WHERE id = ?")
	if err != nil {
		return err
	}

	defer query.Close()
	_, err = query.Exec(u.ID)
	if err != nil {
		return err
	}

	return nil
}
