
# Authentication Package for Express and Next.js

Fixed the issues with version 2.2.

This package offers a flexible authentication system suitable for applications built with Express and Next.js, providing serverless function exports for user registration, login, email verification, password reset, and user management through React Context.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Settings](#settings)
- [Authentication Process](#authentication-process)
- [Serverless Functions](#serverless-functions)
- [Usage](#usage)
  - [Next.js App Router](#nextjs-app-router)
  - [Next.js Pages Router](#nextjs-pages-router)
  - [ExpressJS](#expressjs)
  - [User Context](#user-context)
- [Types](#types)
- [Contributing](#contributing)
- [Versions](#versions)

## Features

- **Next.js and ExpressJS Support**: Flexible implementation for both Next.js and Express.
- **Serverless Functions**: Offers direct, serverless function exports for endpoints.
- **User Registration & Login**: Supports secure user authentication.
- **Email Verification & Password Reset**: Helps users verify their email and reset passwords.
- **User Context Management**: Provides user state handling via React Context.
- **Configurable Routes**: Route protection managed through JSON files.
- **Easy-to-Configure**: Use JSON to customize routes and authentication requirements.

## Installation

Install the package:

```bash
npm install @tomkoooo/t-auth@latest
```

## Environment Variables

Add the following to your `.env` file:

```env
JWT_SECRET=your_secret_key
MONGO_URI=your_mongo_database_uri
MONGO_DB_NAME=your_database_name
SMTP_HOST=your_email_service
SMTP_USER=your_email_username
SMTP_PASS=your_email_password
SMTP_PORT=your_smtp_port
SMTP_SECURE=secure_setting_for_smtp
```

### Email Service Environment Variables

Below are the required environment variables to configure the `nodemailer` email service transporter:

```javascript
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
```

---

## Settings Files for the Package

There are three optional settings files:

1. [***auth.options.json***](#general-settings-authoptionsjson)
2. [***auth.schema.json***](#schema-settings-authschemajson)
3. [***auth.routes.json***](#router-settings-authroutesjson)

These files provide default settings but are not mandatory. If you choose to use them, create them at the root level of your project with these exact names.

---

### General Settings (`auth.options.json`)

Example configuration:

```json
{
  "verificationRequired": true,
  "authMethod": "Email",
  "emailTemplate": {
    "html": "<h1>Welcome!</h1><p>Please verify your email. {{code}}</p>",
    "subject": "Email Verification"
  }
}
```

- **verificationRequired**: `true | false`  
  Enables email verification, which is checked on every route change and login. Defaults to `false`. Note: Every user will have a `verificationCode` in the database with `verified: false` initially.

- **authMethod**: `Email | Username | both`  
  Sets the base for user authentication.

- **emailTemplate**:  
  Defines the content for email verification/password reset emails. `{{code}}` is a placeholder for the verification code.

---

### Schema Settings (`auth.schema.json`)

The default schema used in the `users` collection is as follows:

```javascript
const defaultUserSchema = {
  name: '',
  email: '',
  password: '',
  role: 'user',
  verified: false,
  codes: {
    reset: null,
    token: null,
    verification: null
  }
};
```

To expand this schema, add additional JSON fields in `auth.schema.json`, which will be combined with the default schema for the collection.

```javascript
const optionsPath = path.resolve(process.cwd(), 'auth.schema.json');
const options = fs.readFileSync(optionsPath, 'utf-8');
const userSchemaOptions = {...defaultUserSchema, ...JSON.parse(options).userSchema}
```

---

### Router Settings (`auth.routes.json`)

You can create public and private routes in JSON by following this structure:

```json
{
  "routes": {
    "[route]": {
      "type": "[publicity]",
      "credentials": "[arithmetic condition as string]",
      "redirectTo": "[redirect route if credentials return false]"
    }
  }
}
```

By default, if no `auth.routes.json` file provided every route will be public

- **Public vs Private Routes**:  
  - For public routes (`type: 'public'`), any user can access without authentication.
  - For private routes (`type: 'private'`), access requires authentication or specific conditions.

- **Setting Access Credentials**:  
  - Define access for private routes using `credentials`. For instance, setting `credentials: "user"` only allows authenticated users.
  - For more specific access, such as an `/admin` route, use `credentials: "user.role === 'admin'"`.

- **Redirect Behavior**:  
  - If a user fails to meet access criteria for a private route, they will be redirected to a default route or a `redirectTo` route, if specified. This ensures secure access control across the application.

--- 

This setup allows flexible control over route access, enabling you to enforce different access levels for users based on roles and authentication status.


## Authentication Process

JWTs are paired with IP addresses for secure user authentication. This approach limits token use to a single device and prevents token theft across IPs.

### Serverless Functions

This package exports the following asynchronous serverless functions:
(Marked as 'use server')

#### Database Connection
- **connectToDatabase()** - Establishes a connection to MongoDB.

#### Utility Functions
- **generateToken(userId, clientIp)** - Creates a JWT based on user ID and client IP.
- **validateToken(token, clientIp?)** - Validates a JWT with IP that are either provided or not. The functions call a `getClientIp()` function to get the ip for the pairing

#### Email Options
- **emailOptions()** - Returns email HTML template and subject from `auth.options.json`.
- **authOptions()** - Returns general auth configuration from `auth.options.json`.
- **userSchemaOptions()** - Returns user schema from `auth.schema.json`.
- **routesOptions()** - Returns route configuration from `auth.routes.json`.

#### Verification Code
- **generateVerificationCode(userId, verificationMethod)** - Generates a verification code for a specified method. (verification, reset) Returns the token for the databse, hashed client ip and the hashed user id.

#### Email Service
- **sendMail(to, subject, html?, text?)** - Sends an email.
- **sendVerificationEmail(to, code)** - Sends an email with a verification code.

#### Authentication Functions
- **registerUser(email, password)** - Registers a user. Returns `{success, user, token, message}` the token is needed for the `getUser()` function and it needs to be sotred in the cookies.
- **loginUser(identifier, password)** - Authenticates a user. Returns `{success, user, token, message}` the token is needed for the `getUser()` function and it needs to be sotred in the cookies.
- **getUser(token, ip?)** - Fetches user details with the [authentication](#authentication-process) process.

#### Verification Functions
- **verifyEmail(token, verificationCode)** - Verifies an email using a token and code.
- **resetPassword(email, resetCode, newPassword)** - Resets the user password.
- **requestPasswordReset(email)** - Initiates a password reset.
- **resendVerificationEmail(email)** - Resends the verification email.

## Usage

***By default the [authentication method](#serverless-functions) is **NOT** storing the token in the cookies [but gives it back as token](#authentication-functions). For the middlewere to work you **NEED** to sore the token in the cookies!***

### Next.js App Router

In Next.js App Router (v13+), create `_middleware.ts` to use the middleware.

#### Setup Middleware

```javascript
// /app/_middleware.ts
import { appRouterMiddleware } from '@tomkoooo/t-auth';
import { NextResponse } from 'next/server';

export async function middleware(req) {
  return appRouterMiddleware(req, NextResponse.next());
}
```

#### Pre-Built API Endpoints

You may define custom API endpoints for each serverless function. For example:

```javascript
// /app/api/auth/forgot-password/route.ts
import { requestPasswordReset } from '@tomkoooo/t-auth';

export async function POST(req) {
  return requestPasswordReset(req);
}
```

### Next.js Pages Router

Similarly, set up the middleware in the Pages Router:

```javascript
// /pages/_middleware.ts
import { pagesRouterMiddleware } from '@tomkoooo/t-auth';
import { NextApiRequest, NextApiResponse } from 'next';

export async function middleware(req: NextApiRequest, res: NextApiResponse) {
  await pagesRouterMiddleware(req, res);
}
```

Define endpoints in `/pages/api/`. Example:

```javascript
// /pages/api/auth/forgot-password.js
import { requestPasswordReset } from '@tomkoooo/t-auth';

export default async function POST(req, res) {
  return requestPasswordReset(req, res);
}
```

### ExpressJS

To use the package in Express, add the middleware:

```javascript
// Express Server Setup
import express from 'express';
import { expressMiddlewere } from '@tomkoooo/t-auth';

const app = express();

expressMiddlewere(app);

//or app.use(expressMiddlewere)

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

Or use the pre-configured server with routes:

```javascript
import { createServer } from '@tomkoooo/t-auth';

const app = createServer();

app.listen(3000, () => {
  console.log('Authentication server running on port 3000');
});
```

It provides pre-configured API routes (at `api/auth/[login, register, forgot-password, etc..]`) and the middlewere implamentation. 
For more information the routes listed in `./src/express/apiRoutes.ts`

### User Context

Wrap your Next.js or React app with `UserProvider` to manage user state.

***By default the [authentication method](#serverless-functions) is **NOT** storing the token in the cookies [but gives it back as token](#authentication-functions). For the middlewere to work you **NEED** to sore the token in the cookies!***

#### Example in Next.js App Router

```javascript
// /app/layout.tsx
import { UserProvider, getUser } from '@tomkoooo/t-auth';
import { cookies } from 'next/headers';

export default async function Layout({ children }) {
  const token = cookies().get('token')?.value;
  const user = token ? await getUser(token) : null;

  return (
    <UserProvider user={user}>
      {children}
    </UserProvider>
  );
}
```

#### Example in React

```javascript
// src/App.js
import React, { useEffect, useCallback } from 'react';
import { UserProvider, useUser } from '@tomkoooo/t-auth';

const getCookie = (name) => {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
};

const AppContent = () => {
  const { user, setUser, setLoading, loading } = useUser();

  // Cookie-ból kivonjuk a `token` értékét
  const token = getCookie('token');

  // Felhasználói adatokat lekérdező fetchUser függvény
  const fetchUser = useCallback(async () => {
    if (!token) return;

    try {
        setLoading(true)
      const response = await fetch('/api/user', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      if (!response.ok) throw new Error('Failed to fetch user');
      setLoading(false)
      const userData = await response.json();
      setUser(userData);
    } catch (error) {
      console.error('Error fetching user:', error);
      setLoading(false)
      setUser(null); // Hiba esetén null
    }
  }, [token, setUser]);

  // fetchUser meghívása betöltéskor
  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  return (
    <div>
      {loading && <div>Loading....</div>}
      <h1>Hello {!loading && user ? user.username : 'Guest'}</h1>
    </div>
  );
};

function App() {
  return (
    <UserProvider>
      <AppContent />
    </UserProvider>
  );
}

export default App;
```

Wrap your app:

```javascript
<UserProvider>
  <AppContent />
</UserProvider>
```

## Types

You can access the user's type wich will match your additional schema settings with the default one.

```javascript
import {User} from '@tomkoooo/t-auth'
```

## Contributing

Please submit issues or feature requests for improvements.
[githib.com/Tomkoooo/tauth](#https://github.com/Tomkoooo/tauth)
