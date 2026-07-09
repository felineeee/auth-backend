# Production-ready Authentication Backend built with NestJS, Prisma 7, and PostgreSQL

## Preliminary

This project is an exploratory on my coding journey on authentication API design to demonstrate enterprise-grade security architecture, zero-trust data validation, and automated continuous integration. It handles complex credential workflows, including JWT rotation via HttpOnly cookies and Time-Based One-Time Passwords (TOTP) for Two-Factor Authentication (2FA).

## Architectural Goals

This project was engineered to master advanced backend concepts rather than relying on boilerplate solutions:

- **Strict Boundary Defense:** Utilizing NestJS `ValidationPipe` and DTOs to strip malicious payloads and prevent Mass Assignment vulnerabilities.
- **Stateless Session Security:** Implementing asymmetric JWT Access and Refresh token rotation strictly over `HttpOnly` cookies to neutralize XSS vectors.
- **Multi-Factor Authentication:** Orchestrating dynamic 2FA checkpoints using `otplib` and Passport.js.
- **Isolated E2E Testing:** Building an automated, containerized testing pipeline using Jest, Supertest, and Docker to ensure regressions never reach production.

## Tech Stack

| Technology            | Role in Project |
| :-------------------- | :-------------- |
| **NestJS**            | API Framework   |
| **Prisma**            | Database ORM    |
| **PostgreSQL**        | Database        |
| **Passport.js / JWT** | Auth Engine     |
| **Jest & Supertest**  | E2E Testing     |

## System Architecture & API Endpoints

**Data Flow:** `Client Request -> DTO Validation Pipe -> Throttler Guard -> Passport Strategy -> Controller -> Service -> Prisma -> PostgreSQL`

| Method | Endpoint                 | Protection    | Description                                                       |
| :----- | :----------------------- | :------------ | :---------------------------------------------------------------- |
| `POST` | `/auth/signup`           | Public        | Registers a new user and triggers verification state.             |
| `POST` | `/auth/verify-email`     | Public        | Consumes a token to activate a user account.                      |
| `POST` | `/auth/signin`           | Public        | Authenticates credentials; issues cookies or triggers 2FA prompt. |
| `POST` | `/auth/refresh`          | Public        | Rotates Access/Refresh tokens via HttpOnly cookie validation.     |
| `POST` | `/auth/logout`           | **JWT Guard** | Clears active server sessions and wipes client cookies.           |
| `POST` | `/auth/forgot-password`  | Public        | Generates a secure, time-limited password recovery token.         |
| `POST` | `/auth/reset-password`   | Public        | Consumes the recovery token to update the password hash.          |
| `POST` | `/auth/2fa/generate`     | **JWT Guard** | Generates a TOTP secret and returns a QR code URL.                |
| `POST` | `/auth/2fa/turn-on`      | **JWT Guard** | Validates the first 2FA code and locks it to the user account.    |
| `POST` | `/auth/2fa/authenticate` | Public        | Secondary login checkpoint for 2FA-enabled accounts.              |

## Local Setup & Installation

**Prerequisites:** You must have [Node.js](https://nodejs.org/) (v18+) and [Docker](https://www.docker.com/) installed on your machine.

## Local Setup & Installation

### 1. Clone and Install

```bash
git clone git@github.com:felineeee/auth-backend.git
cd auth-backend
npm install
```

### 2. Environment Configuration

Configure the `.env` file in the root directory, paste the connection string to the template as such:

```
# Database Configuration
## Fill the `TEST_DATABASE_URL` for now

DEV_DATABASE_URL="postgresql://user:password@localhost:5432/myapp?schema=public"
TEST_DATABASE_URL="postgresql://user:password@localhost:5433/myapp_test?schema=public"

# JWT Secrets
JWT_SECRET="replace_with_secure_jwt_secret"
REFRESH_SECRET="replace_with_secure_refresh_secret"
```

### 3. Boot the Database and Sync Schema

```
# Start the PostgreSQL containers
docker compose up -d

# Push the schema to the database
npx prisma db push
```

### 4. Start the Application

```
npm run start:dev
```

### 5. Automate Testing (E2E)

This project feature End-to-End test suite that simulates user lifecycles (Signup -> Verify -> Login -> Refresh -> Logout)

```
npm run test:e2e
```

## Roadmap & Planned Upgrades

- [ ] **Database Hardening & Replay Defenses**
      Expanding the Prisma PostgreSQL schema to track automated brute-force metrics (`failedAttempts`, `lockoutUntil`) and introducing a `tokenVersion` integer to establish a cryptographic baseline for refresh token replay defenses.
- [ ] **Pre-Auth JWT Checkpoints (BOLA Mitigation)**
      Refactoring the Two-Factor Authentication (2FA) workflow to issue short-lived (3-minute) Pre-Auth JWTs. This completely masks sequential database integer IDs from the frontend API network, neutralizing Broken Object Level Authorization (BOLA) vulnerabilities.
- [ ] **Active Threat Interception (Service Layer)**
      Wiring advanced business logic to automatically issue `423 Locked` HTTP exceptions upon excessive failed logins, and building active token-reuse detection to trigger global session revocations if cloned refresh tokens are detected in transit.
- [ ] **Server Environment Hardening**
      Locking down the Express.js network layer by integrating `Helmet.js` for strict HTTP header policies (preventing clickjacking and MIME-sniffing) alongside a heavily restricted CORS credential pipeline.
- [ ] **Continuous Integration (E2E) Expansion**
      Upgrading the `Supertest` automated testing matrix to handle encrypted Pre-Auth payloads and simulate advanced threat vectors (e.g., token replays and brute-force lockouts) against the dynamic Docker testing container.
