// src/index.js

// Exporting middleware
export { universalAuthMiddleware } from './middleware/universalAuthMiddleware';

// Exporting user authentication functions
export { getUser } from './auth/getUser';
export { registerUser } from './auth/registerUser';
export { loginUser } from './auth/loginUser'; // Assuming you have a loginUser function
export { sendEmailVerification } from './auth/sendEmailVerification'; // Assuming you have this function
export { resetPassword } from './auth/resetPassword'; // Assuming you have this function

// Exporting MongoDB connection
export { connectToDatabase } from './db/mongodb';

// Exporting context and provider for React
export { UserProvider, useUser } from './context/UserContext';

// Exporting types if you have any
export * from './types'; // Assuming you have a types file for TypeScript types
