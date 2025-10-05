import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { getOrCreateKeyPair } from '../keys';

export async function GET() {
  const keyPair = await getOrCreateKeyPair();
  let publicKeyBase64 = '';

  const match = (keyPair?.publicKey ?? '').match(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/);
  if (match && match[1]) {
    publicKeyBase64 = match[1].replace(/\s/g, '');
  }

  return NextResponse.json({ publicKey: publicKeyBase64 });
}

// Function to decrypt on server
export async function decryptAesKey(encryptedAesKey: string): Promise<Buffer> {
  const keyPair = await getOrCreateKeyPair();
  
  const encryptedBuffer = Buffer.from(encryptedAesKey, 'base64');
  
  return crypto.privateDecrypt(
    {
      key: keyPair?.privateKey ?? '',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedBuffer
  );
}