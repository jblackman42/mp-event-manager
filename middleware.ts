import { NextRequest, NextResponse } from 'next/server';
import { PROTECTED_ROUTES } from '@/app/lib/constants';
import { checkSession } from '@/app/lib/oauth';

export async function middleware(request: NextRequest) {
  try {
    const url = request.nextUrl;
    const isProtectedRoute = PROTECTED_ROUTES.some(route => url.pathname.startsWith(route.path));

    const sessionCookie = request.cookies.get('session')?.value;
    
    if (!sessionCookie && isProtectedRoute) {
      return NextResponse.redirect(new URL('/', request.url));
    }
    
    if (sessionCookie && isProtectedRoute) {
      const isSessionValid = await checkSession(sessionCookie, request);
      
      if (!isSessionValid) {
        return NextResponse.redirect(new URL('/', request.url));
      }
    }
    
    return NextResponse.next();
  } catch (error) {
    console.error('Middleware error:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      path: request.nextUrl.pathname,
      stack: error instanceof Error ? error.stack : undefined
    });
    
    // On error, redirect to home page for protected routes
    const url = request.nextUrl;
    const isProtectedRoute = PROTECTED_ROUTES.some(route => url.pathname.startsWith(route.path));
    
    if (isProtectedRoute) {
      return NextResponse.redirect(new URL('/', request.url));
    }
    
    return NextResponse.next();
  }
}
  
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|.*\\.png$).*)'
  ],
};