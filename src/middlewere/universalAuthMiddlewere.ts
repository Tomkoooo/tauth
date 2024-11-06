// src/middleware/universalAuthMiddleware.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { Request, Response, NextFunction } from 'express';
import { getUser } from '../auth';  // Assuming this is the correct path
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

interface RouteConfig {
  type: 'private' | 'public';
  credentials?: string;
  redirectTo?: string;
}

interface RoutesConfig {
  routes: { [key: string]: RouteConfig };
}

// Load user-defined routes configuration
const loadUserRoutesConfig = (): RoutesConfig => {
  const userConfigPath = path.resolve(process.cwd(), 'auth.routes.json');

  if (fs.existsSync(userConfigPath)) {
    const configData = fs.readFileSync(userConfigPath, 'utf8');
    return JSON.parse(configData) as RoutesConfig;
  } else {
    console.warn('routes.json not found in project root. Using empty configuration.');
    return { routes: {} };
  }
};

export const universalAuthMiddleware = (
  req: Request | NextApiRequest,
  res: Response | NextApiResponse,
  next: NextFunction
): void => {
  const config = loadUserRoutesConfig();
  const routeConfig = config.routes[req.url || '/'];

  // If no configuration is found for this route, or it's a public route, skip the middleware
  if (!routeConfig || routeConfig.type === 'public') {
    return next(); // Proceed to the next middleware or route handler
  }

  const authenticate = async () => {
    try {
      // Extract the token from the Authorization header (Bearer token)
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({ message: 'Token is required' });
      }

      // Extract the client IP from the headers
      const clientIp =
        (req as any).ip ||
        (req as NextApiRequest).headers['x-forwarded-for'] ||
        (req as any).connection.remoteAddress;
      if (!clientIp) {
        return res.status(400).json({ message: 'Client IP could not be determined' });
      }

      // Verify the token and decode it
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; ip: string };

      // Check if the client IP matches the IP stored in the token
      if (decoded.ip !== clientIp) {
        return res.status(401).json({ message: 'IP address mismatch' });
      }

      // Retrieve the user from the database using the token and client IP
      const user = await getUser(token, clientIp as string);
      if (!user) {
        return res.status(401).json({ message: 'User not found or unauthorized' });
      }

      // Evaluate credentials if they are defined in the route config
      if (user && eval(routeConfig.credentials || 'true')) {
        (req as any).user = user; // Attach the user to the request object
        return next(); // Proceed to the next middleware or route handler
      } else {
        // Redirect or deny access based on route config
        if (routeConfig.redirectTo) {
          return res.status(302).setHeader('Location', routeConfig.redirectTo).end();
        } else {
          return res.status(403).json({ message: 'Access denied' });
        }
      }
    } catch (error) {
      console.error(error);

      // Handle error: either redirect or send an unauthorized response
      if (routeConfig.redirectTo) {
        return res.status(302).setHeader('Location', routeConfig.redirectTo).end();
      } else {
        return res.status(401).json({ message: 'Unauthorized' });
      }
    }
  };

  // Call the authenticate function asynchronously
  authenticate().catch(next);
};
