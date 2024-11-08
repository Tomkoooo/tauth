import { NextResponse, NextRequest } from 'next/server';
import { getUser } from '../auth/getUser';
import { routesOptions } from '../utils/options';
import { cookies } from 'next/headers';

export async function appRouterMiddleware(req: NextRequest) {
const ip = req.headers.get('x-real-ip') || req.headers.get('x-forwarded-for');
const { pathname } = req.nextUrl; // Get the current route path
const cookieToken = (await cookies()).get('token')?.value?.toString() || '';
const session = await getUser(cookieToken, ip);
const routes = routesOptions();
let routeConfig;

if (routes) {
    routeConfig = routes.routes[pathname];
}

  if (routeConfig) {
    // Public route - no authentication required
    if (routeConfig.type === 'public') {
      return NextResponse.next();
    }

    // Private route - check credentials
    if (routeConfig.type === 'private' && routeConfig.credentials && routeConfig.redirectTo) {
      if (session.success) {
        // Evaluate the credentials condition
        const user = session.user; // Assuming session has user object
        const condition = new Function('user', `return ${routeConfig.credentials}`);
        if (condition(user)) {
          return NextResponse.next();
        } else {
          return NextResponse.redirect(new URL(routeConfig.redirectTo, req.url));
        }
      } else {
        // No session, redirect to login
        return NextResponse.redirect(new URL(routeConfig.redirectTo, req.url));
      }
    }
  }

  // If route not found in the config, continue as normal
  return NextResponse.next();
}

// Define matcher for Pages Router by adding specific paths based on routesOptions config
export const config = {
    matcher: Object.keys(routesOptions()!.routes).map((path) => path.startsWith('/') ? path : `/${path}`),
  };
