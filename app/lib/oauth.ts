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
    
    const response = await fetch(discoverUrl);
    if (!response.ok) {
      throw new Error('Failed to fetch OAuth config');
    }
    
    const data = await response.json() as OAuthConfig;
    currOAuthConfig = data;
    return currOAuthConfig;
  }
  return currOAuthConfig;
}

export async function getToken(code: string, redirectUri: string) {
    const { token_endpoint } = await getOAuthConfig();
    
    const clientId = process.env.NEXT_PUBLIC_CLIENT_ID || process.env.CLIENT_ID;
    
    const formData = {
      client_id: clientId,
      client_secret: process.env.CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: code
    };

    const response = await fetch(token_endpoint, {
      method: "POST",
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: encodeUrlForm(formData)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      // console.error('Token exchange failed:', response.status, errorText);
      throw new Error(`Failed to get token: ${response.status} ${errorText}`);
    }
    
    return await response.json() as unknown as TokenData;
}

export async function getUser(token_type: string, access_token: string): Promise<User> {
  const { userinfo_endpoint } = await getOAuthConfig();

  const response = await fetch(userinfo_endpoint, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "Authorization": `${token_type} ${access_token}`
    }
  });

  if (!response.ok) {
    throw new Error('Failed to get user info');
  }

  const userData = await response.json();
  return userData as unknown as User;
}

export async function getUserRoles(user: User): Promise<UserRoles> {
  const { ext_User_GUID } = user;

  const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL}/api/oauth/roles`, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ userGuid: ext_User_GUID })
  });

  if (!response.ok) {
    throw new Error('Failed to get user roles');
  }

  const [userRoles] = await response.json();
  return userRoles as unknown as UserRoles;
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
    let currentToken = access_token;

    // if refresh token exists & access token is expired
    if (refresh_token && new Date() > new Date(expiry_date)) {
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
    }

    const isTokenValid = await verifyJWT(currentToken);
    if (!isTokenValid) {
      return false;
    }
    
    const route = PROTECTED_ROUTES.find(route => url.pathname.startsWith(route.path));

    const userRoles = user_roles.split(',').map(Number);
    const userGroups = user_groups.split(',').map(Number);

    const isUserInRequiredRole = userRoles.some((role: number) => route?.requiredRoleID.includes(role));
    const isUserInRequiredGroup = userGroups.some((group: number) => route?.requiredGroupID.includes(group));

    if (isUserInRequiredRole || isUserInRequiredGroup) {
      return true;
    }
    
    return false;
  } catch (error) {
    // console.error('Failed to check session:', error);
    return false;
  }
}