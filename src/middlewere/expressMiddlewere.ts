import { Request, Response, NextFunction, Express } from 'express';
import { getUser } from '../auth/getUser';
import { routesOptions } from '../utils/options';

const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const routes = routesOptions();
  const { originalUrl: pathname } = req; // Use original URL path
  const cookieToken = req.cookies?.token || ''; // Get JWT token from cookies
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] || req.socket.remoteAddress; // Get client IP

  const routeConfig = routes?.routes?.[pathname];

  // Allow access if route is undefined in config (e.g., unlisted public route)
  if (!routeConfig) return next();

  // Public route logic - allow access without further checks
  if (routeConfig.type === 'public') return next();

  // For private routes, check token validity
  if (routeConfig.type === 'private') {
    if (!cookieToken) {
      return res.redirect(routeConfig.redirectTo || '/login');
    }

    try {
      // Retrieve session/user information
      const session = await getUser(cookieToken, ip);

      // Check user credentials if specified
      if (routeConfig.credentials && session.success) {
        const user = session.user;
        const condition = new Function('user', `return ${routeConfig.credentials}`);
        if (!condition(user)) {
          return res.redirect(routeConfig.redirectTo || '/login');
        }
      }

      return next(); // Pass through if authenticated and conditions are met
    } catch (error) {
      console.error('Token verification error:', error);
      return res.redirect(routeConfig.redirectTo || '/login');
    }
  }

  // Default to allowing access if no specific route configuration matches
  return next();
};

// Apply middleware to specific routes dynamically based on config
export const expressMiddlewere = (app: Express) => {
  const routes = routesOptions();
  const protectedPaths = Object.keys(routes!.routes);

  protectedPaths.forEach((path) => {
    app.use(path, authMiddleware); // Apply middleware to each defined route
  });
};
