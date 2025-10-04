import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // Recommended 96 bits for GCM
const TAG_LENGTH = 16; // 128 bits auth tag

// Get encryption key from environment variable
const getEncryptionKey = (): Buffer => {
  const key = process.env.SPOTIFY_ENCRYPTION_KEY;
  if (!key) {
    throw new Error('SPOTIFY_ENCRYPTION_KEY environment variable is required');
  }
  // Ensure key is 32 bytes
  const keyBuffer = Buffer.from(key, 'hex');
  if (keyBuffer.length !== KEY_LENGTH) {
    throw new Error('SPOTIFY_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return keyBuffer;
};

export interface EncryptedData {
  encrypted: string;
  iv: string;
  tag: string;
}

/**
 * Encrypts data using AES-256-GCM
 */
export const encrypt = (data: string): EncryptedData => {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
};

/**
 * Decrypts data using AES-256-GCM
 */
export const decrypt = (encryptedData: EncryptedData): string => {
  const key = getEncryptionKey();
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const tag = Buffer.from(encryptedData.tag, 'hex');

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

/**
 * Generates a new encryption key (for setup purposes)
 */
export const generateEncryptionKey = (): string => {
  return randomBytes(KEY_LENGTH).toString('hex');
};