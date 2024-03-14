# Video Game Shadow Store

This project aims to show the appearance of an online video game store and includes functionalities for the user.

## Features

- **Homepage:** Display of main page.
- **Games:** Browse and view available games.
- **News:** Read the latest news related to video games.
- **Events:** Information about upcoming gaming events.
- **About Us:** Description of the store and its mission.
- **User Authentication:** Ability to log in, register, view profile, and log out.
- **Profile Management:** Users can manage their accounts, including password change and account deletion.

## Technologies Used

- **HTML:** Page structure.
- **Go:** Backend development using Gin framework and various Go packages including `bcrypt`, `gomail`, `mysql`, `gorilla session`, `github.com/AfterShip/email-verifier`, and `github.com/wagslane/go-password-validator`.
- **CSS and Bootstrap:** Styling and layout enhancement, including cards and carousel.
- **SQL:** Database queries for backend operations.
- **JavaScript:** Functionality for game search feature.

## Backend Functionality

- **Login and Registration:** Passwords are hashed for security. Email verification is sent upon registration.
- **User Middleware:** Certain features (e.g., viewing events, news, profile, and log out) are accessible only when logged in.
- **Profile Management:** Includes account deletion and password change functionality.
- **Data Validation:** Functions for validating user inputs.
- **SQL Queries:** Database interactions for storing and retrieving data.
- **Blacklist:** Blocks certain domains (e.g., *@ioi*) during registration.

## Testing

- Upon logging in, a cookie is created. Logging out removes the cookie.
- User authentication prevents duplicate emails or usernames during registration.
- The server runs on `localhost:8081`.

## Installation

1. Ensure Go is installed.
2. Install required packages: Gin, MySQL, Gomail, Gorilla session, Email verifier, Password validator.
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
3. If CSS or images fail to load, adjust the server's static file path.
4. Execute the SQL script in a database.
5. Configure the env.go file
6. Run the project and enjoy!
```
go run . 
```

**Note:** Make sure to handle environment-specific configurations appropriately.
