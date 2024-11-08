import { NextResponse, NextRequest } from 'next/server';
import { getUser } from '../auth/getUser';
import { routesOptions } from '../utils/options';

// Secret for JWT verification (customize as needed)
const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secret-key'); 

export async function pagesRouterMiddlewere(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  // Retrieve IP information
  const forwarded = req.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0] : req.headers.get('x-real-ip') || req.nextUrl.hostname;
  
  // Retrieve token from cookies
  const cookieToken = req.cookies.get('token')?.value || ''; 
  const routes = routesOptions();
  const session = await getUser(cookieToken, ip);
  
  // Get route configuration for the current path
  const routeConfig = routes?.routes?.[pathname];
  
  // Allow access if route is undefined in config (e.g., unlisted public route)
  if (!routeConfig) return NextResponse.next();

  // Public route logic
  if (routeConfig.type === 'public') return NextResponse.next();

  // Private route logic
  if (routeConfig.type === 'private') {
    if (!cookieToken) {
      // Redirect to login if not authenticated
      return NextResponse.redirect(new URL(routeConfig.redirectTo || '/login', req.url));
    }

    try {
      // Verify and check user credentials if provided
      if (routeConfig.credentials) {
        const condition = new Function('user', `return ${routeConfig.credentials}`);
        if (!session.success || !condition(session.user)) {
          return NextResponse.redirect(new URL(routeConfig.redirectTo || '/login', req.url));
        }
      }
      
      // If session is valid and conditions are met, proceed
      return NextResponse.next();
    } catch (error) {
      // Redirect to login if session verification fails
      return NextResponse.redirect(new URL(routeConfig.redirectTo || '/login', req.url));
    }
  }

  // Allow access if no specific config is set for route type
  return NextResponse.next();
}

// Define matcher for Pages Router by adding specific paths based on routesOptions config
export const config = {
  matcher: Object.keys(routesOptions()!.routes).map((path) => path.startsWith('/') ? path : `/${path}`),
};
