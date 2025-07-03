import { encodeUrlForm } from './util';
import { PROTECTED_ROUTES } from './constants';
import { decrypt, encrypt, verifyJWT } from './encryption';
import { serialize } from 'cookie';  
import { NextRequest } from 'next/server';

export interface User {
  amr: string;
  auth_hash: string;
  auth_time: string;
  display_name: string;
  email: string;
  email_verified: string;
  ext_Address_Line_1: string;
  ext_Address_Line_2: string;
  ext_City: string;
  ext_Congregation_Name: string;
  ext_Contact_GUID: string;
  ext_Contact_ID: string;
  ext_Contact_Status: string;
  ext_Display_Name: string;
  ext_Domain_GUID: string;
  ext_Email_Address: string;
  ext_Engagement_Level: string;
  ext_First_Name: string;
  ext_Home_Phone: string;
  ext_Household_ID: string;
  ext_Last_Name: string;
  ext_Latitude: string;
  ext_Longitude: string;
  ext_Member_Status: string;
  ext_Mobile_Phone: string;
  ext_Nickname: string;
  ext_Participant_Type: string;
  ext_Postal_Code: string;
  ext_Red_Flag_Notes: string;
  'ext_State/Region': string;
  ext_User_GUID: string;
  family_name: string;
  given_name: string;
  idp: string;
  locale: string;
  middle_name: string;
  name: string;
  nickname: string;
  roles: Array<string>;
  user_type: string;
  sub: string;
  userid: string;
  zoneinfo: string;
}

export interface SessionData extends User {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expiry_date: string;
  user_groups: string;
  user_roles: string;
}

export interface UserRole {
  Role_ID: number;
  Role_Name: string;
}

export interface UserGroup {
  User_Group_ID: number;
  User_Group_Name: string;
}
export interface UserRoles {
  user_roles: UserRole[];
  user_groups: UserGroup[];
}

interface OAuthConfig {
    issuer: string;
    jwks_uri: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    end_session_endpoint: string;
    check_session_iframe: string;
    revocation_endpoint: string;
    introspection_endpoint: string;
    frontchannel_logout_supported: boolean;
    frontchannel_logout_session_supported: boolean;
    scopes_supported: Array<string>;
    claims_supported: Array<string>;
    response_types_supported: Array<string>;
    response_modes_supported: Array<string>;
    grant_types_supported: Array<string>;
    subject_types_supported: Array<string>;
    id_token_signing_alg_values_supported: Array<string>;
    code_challenge_methods_supported: Array<string>;
    token_endpoint_auth_methods_supported: Array<string>;
}

export interface TokenData {
  id_token: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

let currOAuthConfig: OAuthConfig;

export async function getOAuthConfig(): Promise<OAuthConfig> {
  if (!currOAuthConfig) {
    const discoverUrl = process.env.NEXT_PUBLIC_DISCOVER_URL;
    if (!discoverUrl) {
      throw new Error('NEXT_PUBLIC_DISCOVER_URL environment variable is not set');
    }
    
    try {
      const response = await fetch(discoverUrl);
      if (!response.ok) {
        throw new Error(`Failed to fetch OAuth config: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json() as OAuthConfig;
      
      // Validate required fields
      if (!data.authorization_endpoint || !data.token_endpoint || !data.userinfo_endpoint) {
        throw new Error('Invalid OAuth configuration: missing required endpoints');
      }
      
      currOAuthConfig = data;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Failed to fetch OAuth configuration');
    }
  }
  return currOAuthConfig;
}

export async function getJWKSUri(): Promise<string | null> {
  try {
    const config = await getOAuthConfig();
    return config.jwks_uri || null;
  } catch (error) {
    console.error('Failed to get JWKS URI:', error);
    return null;
  }
}

export async function getToken(code: string, redirectUri: string) {
    const { token_endpoint } = await getOAuthConfig();
    
    const clientId = process.env.NEXT_PUBLIC_CLIENT_ID || process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    
    if (!clientId || !clientSecret) {
      throw new Error('OAuth client credentials not configured');
    }
    
    const formData = {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: code
    };

    try {
      const response = await fetch(token_endpoint, {
        method: "POST",
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: encodeUrlForm(formData)
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Token exchange failed:', response.status, errorText);
        throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
      }
      
      const tokenData = await response.json();
      
      // Validate required token fields
      if (!tokenData.access_token || !tokenData.token_type) {
        throw new Error('Invalid token response: missing required fields');
      }
      
      return tokenData as TokenData;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Failed to exchange authorization code for token');
    }
}

export async function getUser(token_type: string, access_token: string): Promise<User> {
  const { userinfo_endpoint } = await getOAuthConfig();

  try {
    const response = await fetch(userinfo_endpoint, {
      method: 'POST',
      headers: {
        "Content-Type": "application/json",
        "Authorization": `${token_type} ${access_token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.status} ${response.statusText}`);
    }

    const userData = await response.json();
    
    // Validate required user fields
    if (!userData.sub || !userData.email) {
      throw new Error('Invalid user data: missing required fields');
    }
    
    return userData as User;
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Failed to retrieve user information');
  }
}

export async function getUserRoles(user: User): Promise<UserRoles> {
  const { ext_User_GUID } = user;

  if (!ext_User_GUID) {
    throw new Error('User GUID is required to fetch roles');
  }

  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL;
  if (!baseUrl) {
    throw new Error('NEXT_PUBLIC_BASE_URL environment variable is not set');
  }

  try {
    const response = await fetch(`${baseUrl}/api/oauth/roles`, {
      method: 'POST',
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ guid: ext_User_GUID })
    });

    if (!response.ok) {
      throw new Error(`Failed to get user roles: ${response.status} ${response.statusText}`);
    }

    const responseData = await response.json();
    
    if (!Array.isArray(responseData) || responseData.length === 0) {
      throw new Error('Invalid user roles response format');
    }
    
    const [userRoles] = responseData;
    
    // Validate the structure
    if (!userRoles || typeof userRoles !== 'object') {
      throw new Error('Invalid user roles data structure');
    }
    
    return userRoles as UserRoles;
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Failed to retrieve user roles');
  }
}


async function refreshAccessToken(refresh_token: string): Promise<TokenData> {
  // using fetch here because axios can't run in the Edge Runtime
  const authResponse = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL}/api/client/auth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      grant_type: "refresh_token",
      refresh_token: refresh_token
    })
  });
  if (!authResponse.ok) {
    throw new Error('Failed to fetch auth status');
  }

  const auth: TokenData = await authResponse.json();

  const token_expire_date = new Date();
  token_expire_date.setSeconds(token_expire_date.getSeconds() + auth.expires_in);
  
  const response: TokenData = auth;

  return response;
}

export async function checkSession(sessionValue: string, request: NextRequest): Promise<boolean> {
  const url = request.nextUrl;
  const isProtectedRoute = PROTECTED_ROUTES.some(route => url.pathname.startsWith(route.path));

  if (!isProtectedRoute) {
    return true;
  }

  try {
    const sessionData = await decrypt(sessionValue);
    const parsedSessionData = JSON.parse(sessionData) as SessionData;
    const { access_token, expiry_date, refresh_token, user_roles, user_groups } = parsedSessionData;
    
    if (!access_token) {
      console.warn('Session missing access token');
      return false;
    }
    
    let currentToken = access_token;

    // if refresh token exists & access token is expired
    if (refresh_token && new Date() > new Date(expiry_date)) {
      try {
        const newAuth: TokenData = await refreshAccessToken(refresh_token);
        currentToken = newAuth.access_token;
        
        // Preserve all existing session data and only update token-related fields
        const updatedSessionData: SessionData = {
          ...parsedSessionData,
          access_token: newAuth.access_token,
          refresh_token: newAuth.refresh_token,
          expires_in: newAuth.expires_in,
          expiry_date: new Date(new Date().getTime() + newAuth.expires_in * 1000).toISOString(),
        };
        
        const encryptedSessionData = await encrypt(JSON.stringify(updatedSessionData));
        const cookie = serialize('session', encryptedSessionData, {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === 'production',
          maxAge: 60 * 60 * 24 * 7, // One week
          path: '/',
        });
        request.headers.set('Set-Cookie', cookie);
      } catch (refreshError) {
        console.error('Failed to refresh token:', refreshError);
        return false;
      }
    }

    const isTokenValid = await verifyJWT(currentToken);
    if (!isTokenValid) {
      console.warn('Invalid JWT token');
      return false;
    }
    
    const route = PROTECTED_ROUTES.find(route => url.pathname.startsWith(route.path));
    if (!route) {
      console.warn('No matching route found for path:', url.pathname);
      return false;
    }

    // Handle empty user roles/groups gracefully
    const userRoles = user_roles ? user_roles.split(',').filter(Boolean).map(Number) : [];
    const userGroups = user_groups ? user_groups.split(',').filter(Boolean).map(Number) : [];

    const isUserInRequiredRole = route.requiredRoleID.length === 0 || 
      userRoles.some((role: number) => route.requiredRoleID.includes(role));
    const isUserInRequiredGroup = route.requiredGroupID.length === 0 || 
      userGroups.some((group: number) => route.requiredGroupID.includes(group));

    if (isUserInRequiredRole || isUserInRequiredGroup) {
      return true;
    }
    
    console.warn('User does not have required permissions for route:', url.pathname);
    return false;
  } catch (error) {
    console.error('Failed to check session:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      path: url.pathname
    });
    return false;
  }
}