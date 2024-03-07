package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	var err error
	connection := MySqlUser + ":" + MySqlPass + "@tcp(" + MySqlAddress + ":" + MySqlPort + ")/" + MySqlDB

	db, err = sql.Open("mysql", connection)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
}
