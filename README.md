# SignUpInOut-Backend-Go

The backend part of the `SignUpInOut` project written with Go, which aims to create a simple registration and login system.

## Setup

1. Clone the repository
2. Create a `.env` file in the root directory and add the following environment variables:

   ```env
   DB_USER=yourusername
   DB_PASSWORD=yourpassword
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=yourdbname
   ```

3. Run the following commands:

   ```bash
   go get .
   go run .
   ```

## About storing passwords

Use bcrypt to hash passwords.
