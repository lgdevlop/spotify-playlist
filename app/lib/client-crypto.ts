export class ClientCrypto {
  private static async getEncryptionKey(): Promise<CryptoKey> {
    const response = await fetch('/api/crypto/public-key');
    const { publicKey } = await response.json();

    // Convert base64 (PEM body) to ArrayBuffer
    const der = this.base64ToArrayBuffer(publicKey);

    return crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt', 'wrapKey']
    );
  }

  static async encryptCredentials(credentials: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }): Promise<string> {
    // 1. Generate AES key
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    // 2. Encrypt data with AES
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(credentials));
    const encryptedCredentialsBytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);

    // 3. Encrypt AES key with RSA public key (wrap)
    const publicKey = await this.getEncryptionKey();
    const wrappedAesKey = await crypto.subtle.wrapKey('raw', aesKey, publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaOaepParams);

    // 4. Build payload
    const payload = {
      encryptedCredentials: this.arrayBufferToBase64(encryptedCredentialsBytes),
      encryptedAesKey: this.arrayBufferToBase64(wrappedAesKey),
      iv: this.arrayBufferToBase64(iv.buffer),
    };

    return this.arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(payload)).buffer);
  }

  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes?.[i] ?? 0);
    return btoa(binary);
  }
}
