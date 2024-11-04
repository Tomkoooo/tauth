# Authentication Package for Express and Next.js

This package provides a robust authentication system for applications built with Express and Next.js. It supports user registration, login, email verification, password resets, and user state management through React Context.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
  - [Server Side (Express/Next.js)](#server-side-expressnextjs)
  - [Client Side (React Context)](#client-side-react-context)
- [API Reference](#api-reference)
  - [Middleware](#middleware)
  - [Authentication Functions](#authentication-functions)
  - [User Context](#user-context)
- [Example Configuration](#example-configuration)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Universal Middleware**: Works with both Express and Next.js for user authentication.
- **User Registration**: Securely register users with email verification.
- **Login and Logout**: Authenticate users and manage sessions.
- **Password Reset**: Allow users to reset their passwords via email.
- **User Context**: Provides a way to manage user state in React applications.
- **Flexible Configuration**: Configure routes and authentication requirements using JSON files.

## Installation

To install the package, run:

```bash
npm install your-package-name
```

## Environment Variables
This package requires certain environment variables to function correctly. Create a .env file in your project root and add the following variables:

```env
MONGO_URI=your_mongo_database_uri
EMAIL_SERVICE=your_email_service
EMAIL_USER=your_email_username
EMAIL_PASS=your_email_password
```

Email Configuration in auth.options.json
Create an auth.options.json file in your project root to configure email options:

```json
{
  "verificationRequired": true,
  "emailTemplate": {
    "html": "<h1>Welcome!</h1><p>Please verify your email.</p>",
    "subject": "Email Verification"
  }
}
```
# Usage

### Server Side (Express/Next.js)
Setting Up Middleware
To use the authentication middleware, import and use it in your server application (Express or Next.js):

```javascript
// In your Express app
import express from 'express';
import { universalAuthMiddleware } from 'your-package-name';

const app = express();
app.use(express.json());
app.use(universalAuthMiddleware);

// Define your routes
app.post('/login', loginUser);
app.post('/register', registerUser);
app.post('/reset-password', resetPassword);
```
- In Next.js, you can use the middleware in your API routes:

```javascript
// In your Next.js API route
import { universalAuthMiddleware } from 'your-package-name';

export default async function handler(req, res) {
  await universalAuthMiddleware(req, res, () => {
    // Your logic here
    res.status(200).json({ message: 'Authenticated!' });
  });
}
```
### Client Side (React Context)
To manage user state in your React application, use the provided context.

Setting Up User Context
Wrap your application with the UserProvider to manage user authentication state:

```javascript
import { UserProvider } from 'your-package-name';

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
import { useUser } from 'your-package-name';

const MyComponent = () => {
  const { user, loading } = useUser();

  if (loading) return <p>Loading...</p>;

  return <div>{user ? `Welcome, ${user.name}` : 'Please log in.'}</div>;
};
```
# API Reference
### Middleware
- universalAuthMiddleware
Handles user authentication for routes. Attaches the user object to the request if authenticated.

#### Usage: Call as middleware in your server (Express/Next.js).
#### Authentication Functions
- registerUser
Registers a new user in the database.

##### Parameters:
- userData: An object containing user information (name, email, password).
- Returns: User object on success; error on failure.
#### loginUser
- Authenticates a user and returns user information if successful.

##### Parameters:
- email: User's email.
- password: User's password.
- Returns: User object on success; error on failure.

#### resetPassword
- Sends a password reset email to the user.

##### Parameters:
- email: User's email.
- Returns: Success message or error.

#### - User Context

API Endpoint for Fetching User
To allow the client-side application to fetch the authenticated user's information, you need to create an API endpoint that utilizes the authentication middleware. This endpoint will check if the user is authenticated and return the user's data if they are.

- Creating the API Endpoint
- Set Up the API Route

In your Express or Next.js application, create a new API route that uses the universalAuthMiddleware. This route will respond with the authenticated user's information.

```javascript
// For an Express application
import express from 'express';
import { universalAuthMiddleware } from 'your-package-name';

const app = express();

// Middleware to check authentication
app.use(universalAuthMiddleware);

// Define the user route
app.get('/api/user', (req, res) => {
  if (req.user) {
    // If authenticated, send user data
    res.status(200).json(req.user);
  } else {
    // If not authenticated, send null
    res.status(401).json(null);
  }
});
```
```javascript

// For a Next.js application
import { universalAuthMiddleware } from 'your-package-name';

export default async function handler(req, res) {
  await universalAuthMiddleware(req, res, () => {
    if (req.user) {
      // If authenticated, send user data
      res.status(200).json(req.user);
    } else {
      // If not authenticated, send null
      res.status(401).json(null);
    }
  });
}
```
##### Client-Side Fetching

With the API endpoint set up in the package, you can now fetch the authenticated user information from the client side using the fetchUser function you provided in the useEffect:

```javascript
useEffect(() => {
  const fetchUser = async () => {
    try {
      const response = await fetch('/api/user', {
        method: 'GET',
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
#### Important Notes
- Authentication: The API endpoint uses the universalAuthMiddleware to authenticate the user. Make sure the middleware is correctly implemented to verify the user's token and set the req.user object.
- CORS: If your client-side application is hosted on a different origin than your server, ensure that CORS is properly configured to allow requests from your client.
- Error Handling: The client-side code includes error handling for both the network request and the case where the user is not authenticated.

#### - UserProvider
- Wraps your application to provide user state context.

- Props: children - React components.
#### useUser
Hook to access user data in your components.

#####Returns:
- user: The authenticated user object or null.
- loading: Boolean indicating if the user data is still being loaded.

# Contributing
Contributions are welcome! Please open an issue or a pull request.