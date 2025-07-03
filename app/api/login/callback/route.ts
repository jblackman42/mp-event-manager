import { getToken, getUser, getUserRoles, UserRoles } from '@/app/lib/oauth';
import { redirect } from 'next/navigation';
import { NextRequest, NextResponse } from 'next/server';
import { serialize } from 'cookie';
import { encrypt } from '@/app/lib/encryption';
import { User } from '@/app/lib/oauth';
import { handleError, ValidationError, OAuthError } from '@/app/lib/errors';

export async function GET(request: NextRequest) {
    try {
        const code = request.nextUrl.searchParams.get('code');
        const state = request.nextUrl.searchParams.get('state');

        if (!code) {
            throw new ValidationError('Authorization code is required');
        }

        // Extract returnTo from state parameter
        let returnTo = '/';
        if (state) {
            try {
                const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
                returnTo = stateData.returnTo || '/';
            } catch (error) {
                console.warn('Failed to parse state parameter, using default returnTo');
                returnTo = '/';
            }
        }

        const redirectUri = request.nextUrl.origin + '/api/login/callback';
        
        const tokenData = await getToken(code, redirectUri);

        const { token_type, access_token, refresh_token, expires_in } = tokenData;

        if (!access_token) {
            throw new OAuthError('Failed to obtain access token');
        }

        const user: User = await getUser(token_type, access_token);
        const roles: UserRoles = await getUserRoles(user);

        const sessionData = JSON.stringify({
            ...user,
            access_token,
            refresh_token,
            expires_in,
            expiry_date: new Date(new Date().getTime() + expires_in * 1000).toISOString(),
            user_roles: roles.user_roles ?? '',
            user_groups: roles.user_groups ?? ''
        });

        const encryptedSessionData = await encrypt(sessionData);

        const cookie = serialize('session', encryptedSessionData, {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24 * 7,
            path: '/'
        });

        const response = NextResponse.redirect(new URL(returnTo, request.url));
        response.headers.set('Set-Cookie', cookie);
        return response;
    } catch (error) {
        const appError = handleError(error);
        
        // Log the error for debugging
        console.error('Login callback error:', {
            message: appError.message,
            statusCode: appError.statusCode,
            stack: appError.stack,
            url: request.url
        });

        // Redirect to error page with appropriate message
        const errorMessage = appError instanceof ValidationError 
            ? 'Invalid authorization request'
            : appError instanceof OAuthError
            ? 'Authentication service error'
            : 'Login failed';
            
        return redirect(`/error?msg=${encodeURIComponent(errorMessage)}`);
    }
}