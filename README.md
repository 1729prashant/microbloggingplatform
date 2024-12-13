# Microblogging Platform in Go

This is a microblogging platform designed with modern APIs, secure authentication, and extensibility. Users can post, delete, and manage "chirps" (short messages), as well as benefit from premium features such as "Chirpy Red" membership.

This project demonstrates a complete backend implementation using Go, PostgreSQL, and best practices for API development.

---

## Features

- **User Management**: Create, update, and authenticate users.
- **Microblogging**: Post, retrieve, and delete chirps.
- **Premium Membership**: Support for "Chirpy Red" with exclusive features.
- **Webhooks**: Integrate external services using secure API keys.
- **Readiness & Metrics**: Includes health checks and monitoring endpoints.

---

## Prerequisites

1. **Go**: Version 1.19 or higher.
2. **PostgreSQL**: Version 15. Ensure the database is running.
3. **Environment Configuration**:
   - Use `.env` to configure the application (see below for required values).

---

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/1729prashant/microbloggingplatform.git
cd microbloggingplatform
```

### 2. Set Up PostgreSQL

- Login to PostgreSQL and create a new PostgreSQL database.
`
CREATE DATABASE chirpy;
`
- Ensure the connection URL is available (e.g., `postgres://username:password@localhost:5432/chirpy`).

### 3. Configure the Environment

Create a `.env` file in the project root with the following variables:

```env
DB_URL=postgres://username:password@localhost:5432/chirpy
PLATFORM=dev
JWT_SECRET=<your_jwt_secret>
POLKA_KEY=<your_key_here>
```

### 4. Install Dependencies
```bash
go mod tidy
```

### 5. Run Database Migrations

Use a migration tool such as [migrate](https://github.com/golang-migrate/migrate) to initialize the database schema.

Example:
```bash
migrate -database $DB_URL -path migrations up
```

### 6. Run the Application
```bash
go run main.go
```

---

## API Endpoints

### User Endpoints

- **Create User**: `POST /api/users`
- **Update User**: `PUT /api/users`
- **Login**: `POST /api/login`
- **Refresh Token**: `POST /api/refresh`
- **Revoke Token**: `POST /api/revoke`

### Chirp Endpoints

- **Get All Chirps**: `GET /api/chirps?author_id=<uuid>&sort=<asc|desc>`
- **Create Chirp**: `POST /api/chirps`
- **Get Chirp by ID**: `GET /api/chirps/<chirpID>`
- **Delete Chirp**: `DELETE /api/chirps/<chirpID>`

### Admin Endpoints

- **Metrics**: `GET /admin/metrics`
- **Reset**: `POST /admin/reset` (Development mode only)

### Webhook Endpoints

- **Polka Webhook**: `POST /api/polka/webhooks`

---

## Development Notes

- **Clean Code Practices**: Follows Go conventions for error handling, middleware, and separation of concerns.
- **Security**:
  - Uses JWT for authentication.
  - Polka webhook requests require API key validation.
- **Extensibility**: Easily extendable for additional endpoints or business logic.

---

## Troubleshooting

1. **Cannot Connect to Database**:
   - Verify the `DB_URL` in the `.env` file.
   - Ensure PostgreSQL is running on the correct port.

2. **Missing API Key**:
   - Confirm `POLKA_KEY` is set correctly in the `.env` file.

3. **JWT Issues**:
   - Ensure `JWT_SECRET` is set in the `.env` file.

---


## TODO

Project likely to undergo significant changes. Chirps might become blogposts or something more generic. The end purpose is to have a code base that is multipurpose and can be customised for you.

---
