# Authentication & Authorization API

This repository contains a **secure authentication system** with support for **JWT, refresh tokens, Two-Factor Authentication (2FA), social logins (Google/Facebook), and password recovery**.

## 📌 Features

### 🔐 Core Authentication

- **Local Authentication**

  - Email/Password registration and login
  - Email verification
  - Password strength validation
  - Secure password reset flow

- **OAuth Integration**
  - Google OAuth2.0
  - Facebook OAuth
  - Provider conflict resolution
  - Automatic account linking

### 🛡️ Two-Factor Authentication (2FA)

- **TOTP-Based Authentication**

  - QR code setup
  - Time-based OTP verification
  - Compatible with Google Authenticator/Authy

- **Recovery Options**
  - Backup codes generation and management
  - Email-based recovery
  - SMS-based recovery (via Twilio)
  - Rate-limited recovery attempts

### 🔒 Security Features

- **Brute Force Protection**

  - Account lockout after 5 failed attempts
  - 15-minute lockout period
  - Failed attempt tracking

- **Rate Limiting**

  - API-wide rate limiting
  - Stricter limits for authentication endpoints
  - Per-user and per-IP rate limiting

- **Token Management**
  - JWT-based authentication
  - Refresh token rotation
  - Secure HTTP-only cookies

### 📧 Communication

- **Email Services**

  - Verification emails
  - Password reset notifications
  - 2FA recovery codes

- **SMS Integration**
  - 2FA verification codes
  - Recovery codes

## 🛠️ Technical Stack

- **Backend Framework**: Node.js + Express
- **Database**: MongoDB + Mongoose
- **Authentication**: Passport.js, JWT
- **Email Service**: Nodemailer
- **SMS Service**: Twilio
- **Security Packages**:
  - `express-rate-limit`
  - `helmet`
  - `express-mongo-sanitize`
  - `xss-clean`
  - `speakeasy` (for TOTP)
  - `qrcode` (for 2FA setup)

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository

```sh
git clone https://github.com/your-username/auth-api.git
cd auth-api
```

### 2️⃣ Install Dependencies

```sh
npm install
```

### 3️⃣ Setup Environment Variables

Create a `.env` file and configure it:

```env
PORT=
NODE_ENV=
BASE_URL=
DATABASE=
DATABASE_DOCKER=
DATABASE_USERNAME=
DATABASE_PASSWORD=
APP_NAME=


REDIS_HOST=
REDIS_PORT=
REDIS_PASSWORD=

JWT_SECRET=
JWT_EXPIRES_IN=
JWT_COOKIE_EXPIRES_IN=
JWT_REFRESH_EXPIRES_IN=

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=

FACEBOOK_APP_ID=
FACEBOOK_APP_SECRET=
FACEBOOK_CALLBACK_URL=

SESSION_SECRET=

EMAIL_HOST=
EMAIL_PORT=

EMAIL_FROM=
EMAIL_USER=
EMAIL_PASSWORD=

TWILIO_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=
```

### 4️⃣ Start the Server

```sh
npm start
```

## 🛠️ API Endpoints

### 🔑 Authentication

| Endpoint                                 | Method   | Description                   |
| ---------------------------------------- | -------- | ----------------------------- |
| `/api/v1/auth/signup`                    | **POST** | Register a new user           |
| `/api/v1/auth/login`                     | **POST** | Authenticate and receive JWT  |
| `/api/v1/auth/logout`                    | **POST** | Logout user and clear session |
| `/api/v1/auth/refresh-token`             | **POST** | Refresh access token          |
| `/api/v1/auth/google`                    | **POST** | Register & Login use Google   |
| `/api/v1/auth/facebook`                  | **POST** | Register & Login use Facebook |
| `/api/v1/auth/verify-email`              | **GET**  | Verify user email             |
| `/api/v1/auth/resend-verification-email` | **POST** | Resend verification email     |

### 🔐 Two-Factor Authentication (2FA)

| Endpoint                                | Method     | Description                        |
| --------------------------------------- | ---------- | ---------------------------------- |
| `/api/v1/auth/2fa/setup`                | **POST**   | Setup 2FA (Generate QR Code)       |
| `/api/v1/auth/2fa/verify`               | **POST**   | Verify 2FA OTP                     |
| `/api/v1/auth/2fa/reset`                | **DELETE** | Disable 2FA                        |
| `/api/v1/auth/backup-codes`             | **POST**   | Generate backup codes              |
| `/api/v1/auth/backup-codes/verify`      | **POST**   | Verify backup code                 |
| `/api/v1/auth/2fa/recovery-code`        | **POST**   | Request 2FA recovery OTP via email |
| `/api/v1/auth/2fa/recovery-code/verify` | **POST**   | Verify 2FA recovery OTP            |
| `/api/v1/auth/2fa/recovery/request-sms` | **POST**   | Request 2FA recovery OTP via SMS   |
| `/api/v1/auth/2fa/recovery/verify-sms`  | **POST**   | Verify 2FA recovery OTP via SMS    |

### 🔄 Password Recovery

| Endpoint                         | Method   | Description                |
| -------------------------------- | -------- | -------------------------- |
| `/api/v1/auth/forgot-password`   | **POST** | Request password reset OTP |
| `/api/v1/auth/verify-reset-code` | **POST** | Verify reset OTP           |
| `/api/v1/auth/reset-password`    | **POST** | Reset password             |

## 🔍 Authentication & 2FA Flowchart

The following diagram illustrates the **user authentication process**, including **2FA verification and recovery options**:

```mermaid
%% User Authentication, OAuth, 2FA & Password Recovery Flow
flowchart TD
    Start(["User Request"]) --> RateCheck{"Rate Limit Check"}
    RateCheck -- Exceeded --> Block["429 Too Many Requests"]
    RateCheck -- OK --> AuthType{"Authentication Type"}
    AuthType -- OAuth --> ChooseProvider{"Select Provider"}
    ChooseProvider -- Google --> GoogleAuth["Google OAuth"]
    ChooseProvider -- Facebook --> FacebookAuth["Facebook OAuth"]
    GoogleAuth --> OAuthCallback["OAuth Callback"]
    FacebookAuth --> OAuthCallback
    OAuthCallback --> ValidateOAuth{"Validate OAuth"}
    ValidateOAuth -- Email Exists --> CheckProvider{"Check Provider"}
    CheckProvider -- Different Provider --> ConflictError["409 Provider Conflict"]
    CheckProvider -- Same Provider --> UpdateUser["Update OAuth Info"]
    ValidateOAuth -- New User --> CreateOAuthUser["Create OAuth User"]
    UpdateUser --> GenerateTokens["Generate JWT & Refresh Token"]
    CreateOAuthUser --> GenerateTokens
    AuthType -- Signup --> ValidateInput["Validate Signup Data"]
    ValidateInput -- Invalid --> Error1["400 Bad Request"]
    ValidateInput -- Valid --> CreateUser["Create User Account"]
    CreateUser --> SendVerification["Send Verification Email"]
    SendVerification --> WaitVerify["Await Verification"]
    WaitVerify -- Click Link --> VerifyEmail["Verify Email"]
    VerifyEmail --> LoginRequired["Redirect to Login"]
    AuthType -- Login --> BruteCheck{"Check Account Lock"}
    BruteCheck -- Locked --> WaitUnlock["Wait 15min Lockout"]
    BruteCheck -- Unlocked --> ValidateCreds["Validate Credentials"]
    ValidateCreds -- Invalid --> IncAttempts["Increment Failed Attempts"]
    IncAttempts -- &gt; 5 Attempts --> LockAccount["Lock Account 15min"]
    ValidateCreds -- Valid --> CheckVerified{"Email Verified?"}
    CheckVerified -- No --> RequireVerification["Email Verification Required"]
    CheckVerified -- Yes --> Check2FA{"2FA Enabled?"}
    Check2FA -- Yes --> Choose2FA{"Choose 2FA Method"}
    Choose2FA -- TOTP --> EnterTOTP["Enter TOTP Code"]
    Choose2FA -- Backup --> EnterBackup["Enter Backup Code"]
    Choose2FA -- Email Recovery --> RequestEmail["Request Email OTP"]
    Choose2FA -- SMS Recovery --> RequestSMS["Request SMS OTP"]
    RequestEmail --> RateLimit2{"Rate Limit Check"}
    RequestSMS --> RateLimit2
    RateLimit2 -- Exceeded --> Block2["Wait 1 Minute"]
    RateLimit2 -- OK --> SendOTP["Send OTP"]
    SendOTP --> VerifyOTP["Verify OTP"]
    EnterTOTP --> Verify2FA{"Verify 2FA"}
    EnterBackup --> Verify2FA
    VerifyOTP --> Verify2FA
    Verify2FA -- Invalid --> Error2["401 Unauthorized"]
    Verify2FA -- Valid --> GenerateTokens
    Check2FA -- No --> GenerateTokens
    GenerateTokens --> SetCookies["Set HTTP-Only Cookies"]
    SetCookies --> Success["200 Login Success"]
    Success --> Setup2FA{"Setup 2FA?"}
    Setup2FA -- Yes --> GenSecret["Generate Secret"]
    GenSecret --> ShowQR["Display QR Code"]
    ShowQR --> VerifySetup["Verify Setup Code"]
    VerifySetup -- Valid --> GenBackup["Generate Backup Codes"]
    VerifySetup -- Invalid --> SetupFail["Setup Failed"]
    GenBackup --> Enable2FA["Enable 2FA"]
    AuthType -- Reset Password --> CheckEmail["Verify Email Exists"]
    CheckEmail -- Not Found --> Error3["404 Not Found"]
    CheckEmail -- Found --> CheckLocalUser{"Is Local User?"}
    CheckLocalUser -- No --> OAuthReset["Use OAuth Provider Reset"]
    CheckLocalUser -- Yes --> SendReset["Send Reset OTP"]
    SendReset --> VerifyReset["Verify Reset Code"]
    VerifyReset -- Valid --> NewPassword["Set New Password"]
    VerifyReset -- Invalid --> ResetFail["Reset Failed"]
    NewPassword --> LoginRequired

     RateCheck:::check
     Block:::error
     GoogleAuth:::oauth
     FacebookAuth:::oauth
     OAuthCallback:::oauth
     CheckProvider:::check
     ConflictError:::error
     UpdateUser:::oauth
     CreateOAuthUser:::oauth
     GenerateTokens:::process
     ValidateInput:::process
     Error1:::error
     CreateUser:::process
     BruteCheck:::check
     CheckVerified:::check
     Check2FA:::check
     Choose2FA:::check
     Verify2FA:::check
     Error2:::error
     Success:::success
     GenSecret:::process
     SetupFail:::error
     Enable2FA:::success
     Error3:::error
     CheckLocalUser:::check
     OAuthReset:::oauth
     ResetFail:::error
    classDef error fill:#ff6b6b
    classDef success fill:#51cf66
    classDef process fill:#339af0
    classDef check fill:#ffd43b
    classDef oauth fill:#20c997

```

## 📝 License

This project is licensed under the **MIT License**.
