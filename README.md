# Authentication Package for Express and Next.js

This package provides a robust authentication system for applications built with Express and Next.js. It supports user registration, login, email verification, password resets, and user state management through React Context.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Settings](#settings)
- [Authentication Process](#authentication-process)
- [Functions](#provided-server-side-async-functions)
- [Usage](#usage)
  - [NextJs App Router](#nextjs-app-router)
  - [NextJs Pages Router](#nextjs-pages-router)
  - [ExpresJs](#expressjs)
  - [Context Usage](#user-context)
- [Retrive client-side token](#provided-server-side-async-functions)
- [Types](#types)
- [Contributing](#contributing)

## Features

- **Universal Usage**: Supports NextJs (App and Pages router) and ExpressJs
- **Universal Middleware**: Works with both Express and Next.js for user authentication.
- **User Registration**: Securely register users with email verification.
- **Login and Logout**: Authenticate users and manage sessions.
- **Password Reset**: Allow users to reset their passwords via email.
- **User Context**: Provides a way to manage user state in React applications.
- **Built in route manager**: Provides route protection based on end user setup.
- **Flexible Configuration**: Configure routes and authentication requirements using JSON files.

## Installation

To install the package, run:

```bash
npm install @tomkoooo/t-auth@latest
```

## Environment Variables
This package requires certain environment variables to function correctly. Create a .env file in your project root and add the following variables:

```env
JWT_SECRET=your_secret_key
MONGO_URI=your_mongo_database_uri
SMTP_HOST=your_email_service
SMTP_USER=your_email_username
SMTP_PASS=your_email_password
SMTP_PORT=your_smtp_port

```
Email service env variables is for:
``` javascript 
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false, // true, if using port 465, false, if 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
```

## Settings

There is 3 settings file for the package:
- [auth.options.json](#general-options)
- [auth.schema.json](#schema-options)
- [auth.routes.json](#router-options)

Neither of them is necessary there is provided default settings.
***If you using them you need to create them on the root level of your project with the given name.***

### General options

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
- ***VerificationRequired:*** 
    - true | false for email verifaction, this will be checked on every route change, login. By default it is false, but every user will get a verificationCode in the db, and will have a verifcation false.
- ***AuthMethod:*** 
    - Email | Username | both for the user authentication base
- ***EmailTemplate:*** 
    - Email content for email verifcation/password reset as html, {{code}} is where the verification code will be placed

### Schema configuration in auth.schema.json

Default schema used in 'users' collection:
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

- In the file you can expand this schema by adding additional jsons, the two file combined will add the schema for the collection

### Route settings in auth.routes.json
You can create public/private routes in a json file by implamenting this structure:

```json
 {
    "routes": {
        "[route]": {
            "type": "[publicity]",
            "credentials": "[arethemtics as string]",
            "redirectTo": "[redirect route if credentials returns as false]"
        }
    }
}
```

You can define specific routes in the routes configuration object, specifying which routes are public and which require authentication. Each route has a type and an optional credentials condition.

- **Public vs Private Routes:**

    - If a route is set to public (e.g., type: 'public'), the middleware allows any user to access it without authentication.
    - If a route is set to private (e.g., type: 'private'), only users who meet certain criteria can access it.
- **Setting Access Credentials:**

    - For private routes, use credentials to define the condition for access. The middleware checks this condition before allowing access.
    - For example, on the route /settings, you may want only logged-in users to have access. Set credentials to user, so the middleware only allows users who are authenticated.
    - For more specific access, such as an /admin route only accessible to admin users, you can set credentials to a condition like user.role === 'admin'. Only users who satisfy this condition will be allowed through.
- **Redirect Behavior:**

    - If a user tries to access a private route but doesn’t meet the credentials, they’ll be redirected to a default route, or if specified, a redirectTo route for that particular route.
This setup provides flexible control over route access based on user status and roles, making it easier to enforce security and access levels across your app.

# Authentication Process:
This package uses ***JWT (JSON Web Tokens)*** to authenticate users. When a user logs in, the JWT is generated and paired with their IP address to create a unique hash. This process provides an added layer of security by linking the token to both the user and their device.

- **How it works:**

    - ***On login***, the (loginUser) function generates a JWT that includes the user’s ID (user._id) and is signed with the JWT_SECRET. However, the JWT itself ***does not*** include the user’s IP.
    - The token is stored in the database along with a hash of the token and the user's ***IP address.***
    - ***When the user makes a request*** with the JWT, both the ***middleware*** and the getUser() function will:
        - Extract the user’s current IP address.
        - Hash the IP address together with the JWT.
        - Compare this hashed combination with the stored hash in the database.
    - This ensures that only the user’s original device (with the correct IP) can access the account, preventing client-side attacks such as token theft.

- **Security Benefits:**

    - Even if the JWT is stolen (e.g., through a man-in-the-middle attack), the attacker will not be able to use it because the middleware will check the ***IP hash*** stored in the database and compare it with the IP of the device making the request.
    - This effectively prevents unauthorized access from different devices or IP addresses, making the application more secure.

- **Limitation:**

    - ***Single-device login:*** Since the token is tied to a specific IP, the user cannot log in from multiple devices at the same time. If they try to log in from another device, it will fail because the IP hash will not match.
In summary, this authentication approach ensures high security by preventing token theft attacks and pairing each token with the user’s IP. However, it also restricts the ability to log in from multiple devices simultaneously.


## Provided Server-Side Async Functions
The package includes pre-written, server-side async functions for various authentication tasks:

##### - getUser(token)
 - **Parameter:** token - client-side stored JWT (valid for 24 hours).
 - **Returns:** The user object.

##### - loginUser(identifier, password)

 + **Parameters:**
    + ***identifier*** - either email or username.
    + ***password*** - unhashed password.
 - **Returns:** The user object and the  ***token*** needed for further authentication.
 (Store in cookies, localStorage etc.)

##### - registerUser(email, password)

 - **Parameters:**
    - ***email*** - user’s email.
    - ***password*** - unhashed password.
 - **Returns:** { newUser: <user object> | null, success: true | false, message: <status message> }
 - **Message Options:**
    - "Registration successful. Please verify your email if required.
    - Registration successful" if no email verification is needed.

##### - logout(email)
- **Paramater:** email - the user's email.
- **Returns:** { success: true | false, message: 'The user logged out.' }

##### - requestPasswordReset(email)
- **Parameter:** email - the user’s email.
- **Returns:** { success: true | false, message: 'An email with a reset code (stored in the database) is sent to the user.' }


##### - verifyEmail(email, verificationCode)

- **Parameters:**
    - ***email*** - user’s email.
    - ***verificationCode*** - code provided to the user via email.
- **Returns:** { success: true | false, message: '' }


##### - resetPassword(email, resetCode, newPassword)

- **Parameters:**
    - ***email*** - user’s email.
    - ***resetCode*** - code provided to the user via email.
    - ***newPassword*** - unhashed password.
- **Returns:** { success: true | false, message: '' }

##### - sendVerificationEmail(email, verificationCode)

- **Parameters:**
    - ***email*** - user’s email.
    - ***verificationCode*** - user’s verification code as stored in the database (user.codes.verification).
- **Returns:** { success: true | false, message: '' }

#####  Error Handling
 - All functions can throw errors that include an error message.

###### Note: The provided API endpoints are configured to run the corresponding pre-written functions automatically, and waits the paramaters in the request body. (App router req.json, Pages router/ExpressJs req.body). The API functions will have the function name + [router type] + Route (example: requestPasswordResetAppRoute, requestPasswordResetPagesRoute)


# Usage

#### NextJs App Router
To use the authentication features in Next.js, some manual setup is required.
First we need to setup our middlewere that will run the pre-written middlewere

- In the app directory create the _middlewere.ts file with this conetnt:
```javascript
// /app/_middleware.ts
import { universalAuthMiddleware } from '@tomkoooo/t-auth';  // Import from the package
import { NextResponse } from 'next/server';

export async function middleware(req: Request) {
  // Call the universal auth middleware
  const res = NextResponse.next();
  await universalAuthMiddleware(req, res);
  return res;
}

```

##### pre-built API
To use these pre-written API endpoint functions we need to create the corresponding API endpoint in our API folder then import the function.

On the request you need to provide the [function](#provided-server-side-async-functions) paramater. Read the [note](#note-the-provided-api-endpoints-are-configured-to-run-the-corresponding-pre-written-functions-automatically-and-waits-the-paramaters-in-the-request-body-app-router-reqjson-pages-routerexpressjs-reqbody-the-api-functions-will-have-the-function-name--router-type--route-example-requestpasswordresetapproute-requestpasswordresetpagesroute) for the functions as API usage.


for example here is the request password reset endpoint:

```javascript
// app/api/auth/forgot-password/route.ts
import { requestResetPasswordAppRoute } from '@tomkoooo/t-auth';

export async function POST(req) {
  return requestPasswordResetAppRoute(req);
}

```

#### NextJs Pages Router
To use the authentication features in Next.js, some manual setup is required.
First we need to setup our middlewere that will run the pre-written middlewere

- In the pages directory create the _middlewere.ts file with this content:
```javascript
// /pages/_middleware.ts
import { universalAuthMiddleware } from '@tomkoooo/t-auth';  // Import from node_modules
import { NextApiRequest, NextApiResponse } from 'next';

export async function middleware(req: NextApiRequest, res: NextApiResponse) {
  // Call the universal auth middleware
  await universalAuthMiddleware(req, res, () => {
    // After authentication, the request proceeds here
    res.status(200).send('Protected content');
  });
}

```
##### pre-built API
To use these pre-written API endpoint functions we need to create the corresponding API endpoint in our API folder then import the function.

On the request you need to provide the [function](#provided-server-side-async-functions) paramater. Read the [note](#note-the-provided-api-endpoints-are-configured-to-run-the-corresponding-pre-written-functions-automatically-and-waits-the-paramaters-in-the-request-body-app-router-reqjson-pages-routerexpressjs-reqbody-the-api-functions-will-have-the-function-name--router-type--route-example-requestpasswordresetapproute-requestpasswordresetpagesroute) for the functions as API usage.

For example here is the request password reset endpoint:

```javascript
// pages/api/auth/forgot-password.ts (or .js)
import { requestResetPasswordPagesRoute } from '@tomkoooo/t-auth'; // Importing the handler

export default async function POST(req, res) {
  return requestResetPasswordPagesRoute(req, res); // Call the handler
}

```

## ExpressJS

For expressJs there is a provided server with the middlewere and with all the routes that are listed in the NextJs setup.
All you need to do is to use the pre-written server in your express server
```javascript
import { createServer } from '@tomkoooo/t-auth';

const app = createServer();

// Optionally, the user can mount custom routes (if needed)
app.listen(3000, () => {
  console.log('User app running with authentication server on port 3000');
});
```

If you dont want to use the pre-build server you can also import the universalAuthMiddlewere to any express server 
``` javascript 
// Apply the universal auth middleware globally to all routes by default
  app.use(universalAuthMiddleware); // This will apply the auth logic for every incoming request
```
and also you can use the routes without the pre-build server by importing them as 'apiRoutes' wich you can mounth under any additional routes.
```javascript 
 // Mount your API routes under '/api/auth'
  app.use('/api/auth', apiRoutes);
```

On the pre-build server they are nested under '/api/auth'.

The apiRoutes structure like this:
``` javascript 
const router = express.Router();

// POST login route
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const { token, user } = await loginUser(email, password);
    res.json({ token, user });
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

export default router;
```

### User Context

By default the context does not include any data for the user, but it gives the ability to set the user object. By this approach is easier to implament into any rendering, and framework.

#### App router
In NextJs >13 app router projects get the user object on the root layout.tsx file and wrap your application with the provider.

```javascript
// app/layout.tsx
import { UserProvider, getUser } from '@tomkoooo/t-auth';
import { cookies } from 'next/headers';
import { ReactNode } from 'react';

export default async function Layout({ children }: { children: ReactNode }) {
  // Fetch token from cookies (server-side safe)
  const token = cookies().get('token')?.value;
  let user = null;

  if (token) {
    // Fetch user using the token
    user = await getUser(token);
  }

  return (
    <UserProvider user={user}>
      {children}
    </UserProvider>
  );
}

```

#### Pages Router
In pages router you can use getInitialProps or getServerSideProps in your files. 
Here is an example on the root _app.tsx file:
```javascript
// pages/_app.tsx
import { UserProvider, getUser } from '@tomkoooo/t-auth';
import App from 'next/app';
import { cookies } from 'next/headers';

function MyApp({ Component, pageProps, user }) {
  return (
    <UserProvider user={user}>
      <Component {...pageProps} />
    </UserProvider>
  );
}

// Use getInitialProps to fetch user data on the server side
MyApp.getInitialProps = async (appContext) => {
  const appProps = await App.getInitialProps(appContext);

  // Get token from cookies (SSR-safe)
  const cookieHeader = appContext.ctx.req?.headers.cookie;
  let user = null;

  if (cookieHeader) {
    const token = cookies().get('token')?.value;
    if (token) {
      user = await getUser(token);
    }
  }

  return { ...appProps, user };
};

export default MyApp;
```

#### Client side fetching
You can fetch the user object by calling an API and then setting the context's user's value to the response.

This makes possible to be able to use it plain React as well and this is why this provided code is in vanilla js and ts.

If youe're using [ExpressJs](#expressjs) with the pre-build server you don't need to setup any API routes but on NextJs you have to create manually the API endpoints structure and write your own mechanism or use the [pre-built](#pre-built-api) API-s or the [server-side](#user-context) functions

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
#### Using User Context
You can access user data anywhere in your components:

```javascript
import { useUser } from '@tomkoooo/t-auth';

const MyComponent = () => {
  const { user, loading } = useUser();

  if (loading) return <p>Loading...</p>;

  return <div>{user ? `Welcome, ${user.name}` : 'Please log in.'}</div>;
};
```

# Types
You can access the user's type wich will match your additional schema settings with the default one.
``` javascript
import {User} from '@tomkoooo/t-auth'
```

# Contributing
Contributions are welcome! Please open an issue or a pull request.
[Github/Tomkoooo](https://github.com/Tomkoooo/tauth)