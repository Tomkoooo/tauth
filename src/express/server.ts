// src/server.ts
import express from 'express';
import apiRoutes from './apiRoutes';
import { expressMiddlewere } from '../middlewere/expressMiddlewere'; // Import universal auth middleware

// Create an Express server instance and mount the API routes
export function createServer() {
  const app = express();

  // Apply the universal auth middleware globally to all routes by default
  app.use(expressMiddlewere); // This will apply the auth logic for every incoming request

  app.use(express.json());  // Middleware for parsing JSON request bodies

  // Mount your API routes under '/api/auth'
  app.use('/api/auth', apiRoutes);

  return app;
}

// Optionally, export a function to run the server (useful for internal tests)
if (require.main === module) {
  const app = createServer();
  app.listen(3000, () => {
    console.log('Server is running on port 3000');
  });
}