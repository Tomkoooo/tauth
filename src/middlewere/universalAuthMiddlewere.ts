// src/middleware/universalAuthMiddleware.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { Request, Response, NextFunction } from 'express';
import { getUser } from '../auth'; // Az auth függvényed
import fs from 'fs';
import path from 'path';

interface RouteConfig {
  type: 'private' | 'public';
  credentials?: string;
  redirectTo?: string;
}

interface RoutesConfig {
  routes: { [key: string]: RouteConfig };
}

// routes.json konfiguráció betöltése a felhasználó projektjének gyökérmappájából
const loadUserRoutesConfig = (): RoutesConfig => {
  const userConfigPath = path.resolve(process.cwd(), 'routes.json'); // Gyökérmappa

  if (fs.existsSync(userConfigPath)) {
    const configData = fs.readFileSync(userConfigPath, 'utf8');
    return JSON.parse(configData) as RoutesConfig;
  } else {
    console.warn('routes.json not found in project root. Using empty configuration.');
    return { routes: {} }; // Üres konfiguráció, ha a fájl nem létezik
  }
};

// Middleware függvény
export const universalAuthMiddleware = async (
  req: Request | NextApiRequest,
  res: Response | NextApiResponse,
  next: NextFunction | (() => void)
) => {
  const config = loadUserRoutesConfig();
  const routeConfig = config.routes[req.url || '/'];

  // Ha nincs konfiguráció az útvonalhoz, engedjük át
  if (!routeConfig) {
    if (typeof next === 'function') next();
    return;
  }

  // Publikus útvonal átengedése
  if (routeConfig.type === 'public') {
    if (typeof next === 'function') next();
    return;
  }

  // Privát útvonal ellenőrzése
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const clientIp = (req as any).ip || (req as NextApiRequest).headers['x-forwarded-for'] || (req as any).connection.remoteAddress;
    let user = null
    if(token){
      user = await getUser(token, clientIp as string);
    }

    if (user && eval(routeConfig.credentials || 'true')) {
      (req as any).user = user;
      if (typeof next === 'function') next();
    } else {
      // Átirányítás vagy hibaüzenet
      if (routeConfig.redirectTo) {
        res.status(302).setHeader('Location', routeConfig.redirectTo).end();
      } else {
        res.status(403).json({ message: 'Access denied' });
      }
    }
  } catch {
    if (routeConfig.redirectTo) {
      res.status(302).setHeader('Location', routeConfig.redirectTo).end();
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  }
};
