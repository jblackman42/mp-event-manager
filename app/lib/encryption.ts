const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const ivLength = 12; // AES-GCM recommends 12 bytes IV

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
    // Decode without verification
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false; // Invalid JWT format
    }

    // Decode the payload (second part)
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64').toString('utf8')
    );

    // Check if token has expired
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return false; // Token has expired
    }

    return true;
  } catch (error) {
    return false; // Invalid token format or parsing error
  }
};

async function getKey(): Promise<CryptoKey> {
  const password = process.env.ENCRYPTION_SECRET || 'default_secret';
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