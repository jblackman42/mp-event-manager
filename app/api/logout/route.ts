import { NextRequest, NextResponse } from "next/server";
import { decrypt } from '@/app/lib/encryption';
import { SessionData } from "@/app/lib/oauth";
import { encodeUrlForm } from "@/app/lib/util"; 
import { handleError, createErrorResponse, AuthenticationError } from "@/app/lib/errors";
import axios from "axios";

export async function GET(req: NextRequest) {
  try {
    const sessionCookie = req.cookies.get("session")?.value;

    if (!sessionCookie) {
      const redirectUrl = new URL('/', req.nextUrl.origin);
      const response = NextResponse.redirect(redirectUrl);
      response.headers.set("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
      return response;
    }

    const sessionData = await decrypt(sessionCookie);
    const { access_token }: SessionData = JSON.parse(sessionData);

    // Validate that we have the required environment variables
    const clientId = process.env.NEXT_PUBLIC_CLIENT_ID || process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    
    if (!clientId || !clientSecret) {
      throw new AuthenticationError('OAuth client credentials not configured');
    }

    // Create Basic Auth header from environment variables
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    await axios({
      method: "POST",
      url: `https://my.pureheart.org/ministryplatformapi/oauth/connect/revocation`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": `Basic ${basicAuth}`
      },
      data: encodeUrlForm({
        token: access_token,
        token_type_hint: "access_token"
      })
    });

    const redirectUrl = new URL('/', req.nextUrl.origin);
    
    const response = NextResponse.redirect(redirectUrl);
    response.headers.set("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    return response;
  } catch (error) {
    const appError = handleError(error);
    
    // Log the error for debugging
    console.error('Logout error:', {
      message: appError.message,
      statusCode: appError.statusCode,
      stack: appError.stack
    });

    // Return appropriate error response
    if (appError.statusCode >= 400 && appError.statusCode < 500) {
      return NextResponse.json(
        createErrorResponse(appError, req.nextUrl.pathname),
        { status: appError.statusCode }
      );
    }

    // For server errors, redirect to error page
    const errorUrl = new URL('/error?msg=Error in logout', req.nextUrl.origin);
    return NextResponse.redirect(errorUrl);
  }
}