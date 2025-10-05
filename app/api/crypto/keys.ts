import crypto from 'crypto';

let keyPair: { publicKey: string; privateKey: string } | null = null;

export async function getOrCreateKeyPair() {
  if (!keyPair) {
    keyPair = await new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'rsa',
        {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        },
        (err, publicKey, privateKey) => {
          if (err) reject(err);
          else resolve({ publicKey, privateKey });
        }
      );
    });
  }
  return keyPair;
}
