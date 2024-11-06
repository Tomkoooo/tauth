// index.js

// Exporting middleware
export { universalAuthMiddleware } from './src/middlewere/universalAuthMiddlewere';

// Exporting user authentication functions
export { getUser } from './src/auth';
export { registerUser } from './src/auth';
export { loginUser } from './src/auth'; // Assuming you have a loginUser function
export { sendVerificationEmail } from './src/emailService/emailService'; // Assuming you have this function
export { resetPassword } from './src/auth'; // Assuming you have this function
export { logout } from './src/auth'; // Assuming you have this function

// Exporting MongoDB connection
export { connectToDatabase } from './src/db/mongodb';

// Exporting context and provider for React
export { UserProvider, useUser } from './src/hooks/useUser';

// Exporting types if you have any
export { User } from './src/types/userSchema'; // Assuming you have a types file for TypeScript types

// Exporting Next.js API Routes for both App Router and Pages Router

// For App Router
export { POST as forgotPasswordAppRoute } from './src/api/next/auth/forgot-password/route';
export { POST as requestResetPasswordAppRoute } from './src/api/next/auth/reset-password/route';
export { POST as loginAppRoute } from './src/api/next/auth/login/route';
export { POST as registerAppRoute } from './src/api/next/auth/register/route';
export { GET as userAppRoute } from './src/api/next/auth/user/route';
export { POST as logoutAppRoute } from './src/api/next/auth/logout/route';

// For Pages Router
export { default as forgotPasswordPagesRoute } from './src/api/next/auth/forgot-password';
export { default as requestResetPasswordPagesRoute } from './src/api/next/auth/reset-password';
export { default as loginPagesRoute } from './src/api/next/auth/login';
export { default as registerPagesRoute } from './src/api/next/auth/register';
export { default as userPagesRoute } from './src/api/next/auth/user';
export { default as logoutPagesRoute } from './src/api/next/auth/logout';

// Export ExpressJs createServer
export { createServer } from './src/api/express/server';
export { default as apiRoutes } from './src/api/express/apiRoutes';
