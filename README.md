# Video Game Shadow Store

This project focuses on the design of a login and registration system for an online video game store, aiming to create a seamless and intuitive experience for users as they access the platform.

## Features

- **Homepage:** Display of main page.
- **Games:** Browse and view available games.
- **User Authentication:** Ability to log in, register.
- **Profile Management:** Users can manage their accounts, including view profile, change of password and account deletion.

## Technologies Used

- **HTML:** Page structure.
- **Go:** Backend development using Gin framework and various Go packages including `bcrypt`, `gomail`, `mysql`, `gorilla session`, `github.com/AfterShip/email-verifier`, and `github.com/wagslane/go-password-validator`.
- **CSS and Bootstrap:** Styling and layout enhancement, including cards and carousel.
- **SQL:** Database queries for backend operations.
- **JavaScript:** Functionality for game search feature.

## Backend Functionality

- **Login and Registration:** Passwords are hashed for security. Email verification is sent upon registration.
- **User Middleware:** Certain features (e.g., view profile, delete account, change password, log out) are accessible only when logged in.
- **Profile Management:** Includes account deletion and password change functionality.
- **Data Validation:** Functions for validating user inputs.
- **SQL Queries:** Database interactions for storing and retrieving data.
- **Blacklist:** Blocks certain domains (e.g., *@ioi*) during registration.

## Testing

- When you log in, a cookie is created and when you log out, the cookie is deleted.
- User authentication prevents duplicate emails or usernames during registration.
- If you try to enter a user page, it asks you to authenticate first.

## Installation

1. Ensure Go is installed.
2. Git clone the repository.
```
git clone https://github.com/0xsissN/shadow-store-go.git
```
3. Install required packages: Gin, MySQL, Gomail, Gorilla session, Email verifier, Password validator.
```
go get github.com/gin-gonic/gin
```
```
go get github.com/go-sql-driver/mysql
```
```
go get gopkg.in/gomail.v2
```
```
go get github.com/gorilla/sessions
```
```
go get -u github.com/AfterShip/email-verifier
```
```
go get -u github.com/wagslane/go-password-validator
```
4. If CSS or images fail to load, adjust the server's static file path.
5. Execute the SQL script in a database.
6. Configure the env.go file.
7. Run the project and enjoy!
```
go run . 
```

**Note:** Make sure to handle environment-specific configurations appropriately.
