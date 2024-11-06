# Authentication Package for Express and Next.js

This package provides a robust authentication system for applications built with Express and Next.js. It supports user registration, login, email verification, password resets, and user state management through React Context.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Settings](#settings)
- [Token](#token)
- [Usage](#usage)
  - [NextJs App Router](#nextjs-app-router)
  - [NextJs Pages Router](#nextjs-pages-router)
  - [ExpresJs](#expressjs)
  - [Client Side (React Context)](#client-side-react-context)
- [Functions](#usage)
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
npm install @tomkoooo/t-auth
```

## Environment Variables
This package requires certain environment variables to function correctly. Create a .env file in your project root and add the following variables:

```env
MONGO_URI=your_mongo_database_uri
SMTP_HOST=your_email_service
SMTP_USERyour_email_username
SMTP_PASS=your_email_password
SMTP_PORT=your_smtp_port

```
Email service env variables is for:
``` javascript 
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false, // true, ha 465-öt használsz, false, ha 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
```

## Settings

### General configuration in the auth.options.json file on the root of the project

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
- VerificationRequired: true | false for email verifaction, this will be checked on every route change, login. By default it is false, but every user will get a verificationCode in the db, and will have a verifcation false.
- AuthMethod: Email | Username | both for the user authentication base
- EmailTemplate: Email content for email verifcation/password reset as html, {{code}} is where the verification code will be placed

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

- You can declare a route in the routes object for example the route '/', then you can make it private or public as its type if it is public then the middlewere will allow every traffic through it
but if it is false it will read te credentials as arethemtics for example for the route '/settings' we only want users that are logged in we can check it as setting the credentials to 'user'
or the '/admin' route we want only admin users so we can set the credentails to 'user.role === 'admin'' and the middlewere were check on it. Based on the returned value (true | false) we will be 
redirected to the route | redirectTo route 

# Token

For authentication the package uses JWT with the end users IP to hash the corresponding token that are paired with the user in the database.
This prevents the client side attacks because even if the JWT gets stolen the middlewere and the getUser will pair it with an IP and get a match.
Only on the loginUser function will return the token that is hashed with the JWT_SECRET and the user._id but its not containing the IP, but on
the database the token will be registered with the JWT and the IP hash on login. 
On every call where the user sends the token both the middlewere and getUser() will get the users IP and hash it with the token to check for matching in the database.

By this approach the product will be safe from the cleint side attacks and will be very secure but will not allow to be able to login from 2 device at once.

# Usage

### NextJs
In nextJs we need to make some instalations manually.

The package provides pre-written SERVER SIDE async functions for:
- getUser(token) -> token: client side stored jwt (avaible for 24h) -> return the user object
- loginUser(idintifier, password) -> idintifier: email | username, password: password unhashed -> return the user object and the token
- registerUser(email, password) -> password: password unhashed -> return { newUser: user object | null if email verifaction needed, success: true | false, message: 'Registration successful. Please verify your email if required.' | 'Registration successful' }
- requestPasswordReset(email) -> email sent to the user wiht the code thats in the db and returns {success: true | false, message: ''}
- verifyEmail(email, verificationCode) -> verficationCode: The code that the user gived based on the given code to the users email -> return {success: true | false, message: ''}
- resetPassword(email resetCode, newPassword) -> resetCode: The code that the user gived based on the given code to the users email, newPassword: password unhashed -> return {success: true | false, message: ''}
- sendVerifactionEmail(email, verificationCode) -> verificationCode: users verification code in the db, user.codes.verification

email: users email
All functions can throw errors with an error message in them

NOTE: all pre-written API endpoints will run the corresponding pre-written functions

#### NextJs App Router
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
The package provides pre-written API endpoints for:
- userAppRoute -> req.headers.get('authorization')?.split(' ')[1] || ''; (GET)
- loginAppRoute -> const { email, password } = await req.json(); (POST)
- registerAppRoute -> const { email, password } = await req.json(); (POST)
- forgotPasswordAppRoute -> const { email } = await req.json(); (POST)
- requestResetPasswordAppRoute -> const { email, code, newPassword } = await req.json(); (POST)
- logoutAppRoute -> const {email} = await req.json(); (POST)

To use these pre-written API endpoint functions we need to create the corresponding API endpoint in our API folder then import the function
for example here is the request password reset endpoint:

```javascript
// app/api/auth/forgot-password/route.ts
import { requestResetPasswordAppRoute } from '@tomkoooo/t-auth';

export async function POST(req) {
  return requestPasswordResetAppRoute(req);
}

```

#### NextJs Pages Router
First we need to setup our middlewere that will run the pre-written middlewere

- In the pages directory create the _middlewere.ts file with this conetnt:
```javascript
// /pages/_middleware.ts
import { universalAuthMiddleware } from 'your-package-name/src/middleware/universalAuthMiddleware';  // Import from node_modules
import { NextApiRequest, NextApiResponse } from 'next';

export async function middleware(req: NextApiRequest, res: NextApiResponse) {
  // Call the universal auth middleware
  await universalAuthMiddleware(req, res, () => {
    // After authentication, the request proceeds here
    res.status(200).send('Protected content');
  });
}

```

The package provides pre-written API endpoints for:
- userPagesRoute -> req.headers('authorization')?.split(' ')[1] || ''; (GET)
- loginPagesRoute -> const { email, password } = await req.body(); (POST)
- registerPagesRoute -> const { email, password } = await req.body(); (POST)
- forgotPasswordPagesRoute -> const { email } = await req.body(); (POST)
- requestResetPasswordPagesRoute -> const { email, code, newPassword } = await req.body(); (POST)
- logoutPagesRoute -> const {email} = await req.body(); (POST)

To use these pre-written API endpoint functions we need to create the corresponding API endpoint in our API folder then import the function
for example here is the request password reset endpoint:

```javascript
// pages/api/auth/forgot-password.ts (or .js)
import { requestResetPasswordPagesRoute } from '@tomkoooo/t-auth'; // Importing the handler

export default async function POST(req, res) {
  return requestResetPasswordPagesRoute(req, res); // Call the handler
}

```

### ExpressJS

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
```

### Client Side (React Context)

By default the context will run a call at '/api/user' endpoint as GET and waits an object that will be set for the user and tries to get the token from the localStorage.
So if you not provide the endpoint (in expressJs this is provided) then the user will always be null, but you can set it manually.
In the context you can access:
- loading -> loader for user
- user -> retrived user object
- setUser -> If u want to set it manually

- To manage user state in your React application, use the provided context.

```javascript
useEffect(() => {
    const fetchUser = async () => {
      const token = localStorage.getItem('token');
      try {
        const response = await fetch('/api/user', {
          method: 'GET',
          headers: {authorization: `Bearer ${token}`},
          credentials: 'include', // Ensure cookies are sent if needed
        });
        if (response.ok) {
          const fetchedUser = await response.json();
          setUser(fetchedUser);
        } else {
          setUser(null);
        }
      } catch (error) {
        console.error("Error fetching user:", error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  ```

Setting Up User Context
Wrap your application with the UserProvider to manage user authentication state:

```javascript
import { UserProvider } from '@tomkoooo/t-auth';

function MyApp({ Component, pageProps }) {
  return (
    <UserProvider>
      <Component {...pageProps} />
    </UserProvider>
  );
}
```
- Using User Context
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
You can access the user's type wich will match your additional schema settings with the default one like this:
``` javascript
import {User} from '@tomkoooo/t-auth'
```

# Contributing
Contributions are welcome! Please open an issue or a pull request.
[Github](https://github.com/Tomkoooo/tauth)