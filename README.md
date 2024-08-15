# Shop API

## Overview

The Shop API is a RESTful service built using NestJS and PostgreSQL. It provides a robust backend system for managing a shop's inventory, orders, customers, and more.

## Features

- User Authentication and Authorization
- Product Management (CRUD)
- Order Processing
- Customer Management
- Database integration with PostgreSQL

## Prerequisites

    Node.js v19
    PostgreSQL installed locally or accessible remotely

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/CodeVisionEvgen/shop-api-nestjs
cd shop-api-nestjs
```

### Install Dependencies

```bash
npm install
```

### Environment Variables

Create a .env file in the root directory of your project and fill in the required fields. Here are the available environment variables:

```env
# Server
PORT=3000

# Database
POSTGRESQL_HOST="localhost"
POSTGRESQL_PORT=5432
POSTGRESQL_USERNAME="admin"
POSTGRESQL_PASSWORD="testpwd"
POSTGRESQL_DATABASE="shopdb"

# JWT
JWT_SECRET="your_jwt_secret_key"
JWT_EXPIRATION_TIME="3600s"
```

## Running the API

To run the API in development mode, use the following command:

```bash
npm run start:dev
The server should now be running at http://localhost:3000.
```
