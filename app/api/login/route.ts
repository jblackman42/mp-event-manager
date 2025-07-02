import { getOAuthConfig } from '@/app/lib/oauth';
import { encodeUrlForm } from '@/app/lib/util';
import { redirect } from 'next/navigation';
import { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
    const { authorization_endpoint } = await getOAuthConfig()
    
    // Get the returnTo parameter from the query string
    const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
    
    // Create a state parameter that includes the returnTo URL
    // This will be passed back to us in the callback
    const state = Buffer.from(JSON.stringify({ returnTo })).toString('base64');
    
    const redirectUri = `${request.nextUrl.origin}/api/login/callback`;
    
    const loginConfig = encodeUrlForm({
      client_id: process.env.NEXT_PUBLIC_CLIENT_ID || process.env.CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'http://www.thinkministry.com/dataplatform/scopes/all openid offline_access',
      state: state
    })

  return redirect(`${authorization_endpoint}?${loginConfig}`);
}