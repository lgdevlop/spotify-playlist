import { getSessionData } from './session-manager';

export class SessionValidator {
  static async validateSession(): Promise<boolean> {
    const session = await getSessionData();
    
    // Validate that session exists and has valid credentials
    return !!(session && session.spotifyConfig && session.spotifyConfig.clientId);
  }
  
  static async validateCredentialAccess(): Promise<boolean> {
    const isValidSession = await this.validateSession();
    if (!isValidSession) {
      throw new Error('Invalid session for credential access');
    }
    
    // Additional validation logic (e.g., check timestamps, IP consistency if needed)
    return true;
  }
}