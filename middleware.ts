import { NextRequest, NextResponse } from 'next/server';
import { PROTECTED_ROUTES } from '@/app/lib/constants';
import { checkSession } from '@/app/lib/oauth';

export async function middleware(request: NextRequest) {
  const url = request.nextUrl;
  const isProtectedRoute = PROTECTED_ROUTES.some(route => url.pathname.startsWith(route.path));

  const sessionCookie = request.cookies.get('session')?.value;
  const isSessionValid = !!sessionCookie && await checkSession(sessionCookie, request);
  
  if (!isSessionValid && isProtectedRoute) {
    return NextResponse.redirect(new URL('/', request.url));
  } else {
    return NextResponse.next();
  }
}
  
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|.*\\.png$).*)'
  ],
};