const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const ivLength = 12; // AES-GCM recommends 12 bytes IV

// Cache for JWKS to avoid fetching on every verification
let jwksCache: { keys: any[]; expiresAt: number } | null = null;
const JWKS_CACHE_DURATION = 60 * 60 * 1000; // 1 hour

export interface tokenPayload {
  iss: string;
  aud: string;
  exp: number;
  nbf: number;
  client_id: string;
  scope: string[];
  sub: string;
  auth_time: number;
  idp: string;
  auth_hash: string;
  name: string;
  amr: string[];
}

export function parseJWT(token: string): tokenPayload {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    // Decode the payload (second part)
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8')
    );

    return payload as tokenPayload;
  } catch (error) {
    throw new Error('Failed to parse JWT');
  }
}

export async function verifyJWT(token: string): Promise<boolean> {
  try {
    // Decode without verification first to get header
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false; // Invalid JWT format
    }

    // Decode the header to get the key ID (kid)
    const header = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8')
    );

    // Decode the payload (second part)
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8')
    );

    // Check if token has expired
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return false; // Token has expired
    }

    // Check if token is not yet valid
    if (payload.nbf && payload.nbf > now) {
      return false; // Token not yet valid
    }

    // Verify issuer if configured
    const expectedIssuer = process.env.NEXT_PUBLIC_JWT_ISSUER;
    if (expectedIssuer && payload.iss !== expectedIssuer) {
      console.warn(`JWT issuer mismatch: expected ${expectedIssuer}, got ${payload.iss}`);
      return false;
    }

    // Verify audience if configured
    const expectedAudience = process.env.NEXT_PUBLIC_JWT_AUDIENCE;
    if (expectedAudience && payload.aud !== expectedAudience) {
      console.warn(`JWT audience mismatch: expected ${expectedAudience}, got ${payload.aud}`);
      return false;
    }

    // Verify signature if we have the public keys
    const isValidSignature = await verifyJWTSignature(token, header);
    if (!isValidSignature) {
      return false; // Invalid signature
    }

    return true;
  } catch (error) {
    console.error('JWT verification error:', error);
    return false; // Invalid token format or parsing error
  }
}

async function verifyJWTSignature(token: string, header: any): Promise<boolean> {
  try {
    // Try to get JWKS URI from OAuth config first, then fallback to environment variable
    let jwksUri = process.env.NEXT_PUBLIC_JWKS_URI;
    
    if (!jwksUri) {
      try {
        const { getJWKSUri } = await import('./oauth');
        const oauthJwksUri = await getJWKSUri();
        if (oauthJwksUri) {
          jwksUri = oauthJwksUri;
        }
      } catch (error) {
        console.warn('Failed to get JWKS URI from OAuth config:', error);
      }
    }
    
    if (!jwksUri) {
      console.warn('JWKS URI not configured, skipping signature verification');
      return true; // Skip verification if JWKS not configured
    }

    const keyId = header.kid;
    if (!keyId) {
      console.warn('JWT header missing key ID (kid)');
      return false;
    }

    // Get the public key for this key ID
    const publicKey = await getPublicKey(jwksUri, keyId);
    if (!publicKey) {
      console.warn(`Public key not found for key ID: ${keyId}`);
      return false;
    }

    // Verify the signature
    const signature = token.split('.')[2];
    const data = token.split('.').slice(0, 2).join('.');
    
    const isValid = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      publicKey,
      Buffer.from(signature, 'base64url'),
      new TextEncoder().encode(data)
    );

    return isValid;
  } catch (error) {
    console.error('JWT signature verification error:', error);
    return false;
  }
}

async function getPublicKey(jwksUri: string, keyId: string): Promise<CryptoKey | null> {
  try {
    // Check cache first
    if (jwksCache && Date.now() < jwksCache.expiresAt) {
      const key = jwksCache.keys.find((k: any) => k.kid === keyId);
      if (key) {
        return await importJWK(key);
      }
    }

    // Fetch JWKS if not cached or expired
    const response = await fetch(jwksUri);
    if (!response.ok) {
      throw new Error(`Failed to fetch JWKS: ${response.status}`);
    }

    const jwks = await response.json();
    
    // Cache the JWKS
    jwksCache = {
      keys: jwks.keys || [],
      expiresAt: Date.now() + JWKS_CACHE_DURATION
    };
    
    // Find the key with matching key ID
    const key = jwksCache.keys.find((k: any) => k.kid === keyId);
    if (!key) {
      return null;
    }

    return await importJWK(key);
  } catch (error) {
    console.error('Error fetching public key:', error);
    return null;
  }
}

async function importJWK(key: any): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

async function getKey(): Promise<CryptoKey> {
  const password = process.env.ENCRYPTION_SECRET;
  if (!password) {
    throw new Error('ENCRYPTION_SECRET environment variable is required');
  }
  
  const salt = textEncoder.encode('salt');
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(text: string): Promise<string> {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(ivLength));
  const encodedText = textEncoder.encode(text);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encodedText
  );
  const buffer = new Uint8Array(encrypted);
  const ivString = btoa(String.fromCharCode(...Array.from(iv)));
  const encryptedString = btoa(String.fromCharCode(...Array.from(buffer)));
  return `${ivString}:${encryptedString}`;
}

export async function decrypt(text: string): Promise<string> {
  const [ivString, encryptedString] = text.split(':');
  if (!ivString || !encryptedString) {
    throw new Error('Invalid input for decryption');
  }
  const iv = new Uint8Array(atob(ivString).split('').map(char => char.charCodeAt(0)));
  const encrypted = new Uint8Array(atob(encryptedString).split('').map(char => char.charCodeAt(0)));
  const key = await getKey();
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encrypted
  );
  return textDecoder.decode(decrypted);
}