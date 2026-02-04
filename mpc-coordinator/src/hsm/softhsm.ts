import * as graphene from 'graphene-pk11';
import { createLogger } from '../utils/logger';

const logger = createLogger('SoftHSM');

export interface HSMConfig {
  modulePath: string;
  tokenLabel: string;
  userPin: string;
}

export class SoftHSM {
  private mod: graphene.Module;
  private session: graphene.Session | null = null;
  private slot: graphene.Slot | null = null;

  constructor(private config: HSMConfig) {
    this.mod = graphene.Module.load(config.modulePath, 'SoftHSM');
  }

  /**
   * Initialize HSM and open session
   */
  async initialize(): Promise<void> {
    try {
      this.mod.initialize();
      logger.info('SoftHSM initialized');

      // Find the specified token
      const slots = this.mod.getSlots(true);
      for (let i = 0; i < slots.length; i++) {
        const slot = slots.items(i);
        const token = slot.getToken();
        
        if (token.label.trim() === this.config.tokenLabel) {
          this.slot = slot;
          logger.info(`Found token: ${token.label}`);
          break;
        }
      }

      if (!this.slot) {
        throw new Error(`Token not found: ${this.config.tokenLabel}`);
      }

      // Open session and login
      this.session = this.slot.open(
        graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION
      );
      this.session.login(this.config.userPin, graphene.UserType.USER);
      logger.info('HSM session opened and logged in');
    } catch (error) {
      logger.error('Failed to initialize HSM:', error);
      throw error;
    }
  }

  /**
   * Store key to HSM
   */
  async storeKey(keyId: string, keyData: Buffer, keyType: 'private' | 'secret' = 'secret'): Promise<string> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      if (keyType === 'secret') {
        // Store symmetric key (for encrypting MPC share data)
        const key = this.session.create({
          class: graphene.ObjectClass.SECRET_KEY,
          keyType: graphene.KeyType.AES,
          label: keyId,
          token: true,
          private: true,
          sensitive: true,
          extractable: false,
          encrypt: true,
          decrypt: true,
          value: keyData,
        }).toType<graphene.SecretKey>();

        const handle = key.handle.toString('hex');
        logger.info(`Stored secret key in HSM: ${keyId}, handle: ${handle}`);
        return handle;
      } else {
        // Store private key (for ECDSA/EdDSA)
        const key = this.session.create({
          class: graphene.ObjectClass.PRIVATE_KEY,
          keyType: graphene.KeyType.EC,
          label: keyId,
          token: true,
          private: true,
          sensitive: true,
          extractable: false,
          sign: true,
          value: keyData,
        }).toType<graphene.PrivateKey>();

        const handle = key.handle.toString('hex');
        logger.info(`Stored private key in HSM: ${keyId}, handle: ${handle}`);
        return handle;
      }
    } catch (error) {
      logger.error(`Failed to store key ${keyId}:`, error);
      throw error;
    }
  }

  /**
   * Read key from HSM
   */
  async getKey(handle: string): Promise<graphene.Key> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const handleBuffer = Buffer.from(handle, 'hex');
      const key = this.session.getObject(handleBuffer);
      if (!key) throw new Error(`Key with handle ${handle} not found`);
      return key.toType<graphene.Key>();
    } catch (error) {
      logger.error(`Failed to get key with handle ${handle}:`, error);
      throw error;
    }
  }

  /**
   * Encrypt data using HSM
   */
  async encrypt(handle: string, data: Buffer): Promise<Buffer> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const key = await this.getKey(handle);
      const cipher = this.session.createCipher(
        { name: 'AES_CBC_PAD', params: Buffer.alloc(16) },
        key
      );
      
      const encrypted = cipher.update(data);
      cipher.final();
      
      return Buffer.from(encrypted);
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw error;
    }
  }

  /**
   * Decrypt data using HSM
   */
  async decrypt(handle: string, encryptedData: Buffer): Promise<Buffer> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const key = await this.getKey(handle);
      const decipher = this.session.createDecipher(
        { name: 'AES_CBC_PAD', params: Buffer.alloc(16) },
        key
      );
      
      const decrypted = decipher.update(encryptedData);
      decipher.final();
      
      return Buffer.from(decrypted);
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw error;
    }
  }

  /**
   * Generate random numbers
   */
  async generateRandom(length: number): Promise<Buffer> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const random = this.session.generateRandom(length);
      return Buffer.from(random);
    } catch (error) {
      logger.error('Random generation failed:', error);
      throw error;
    }
  }

  /**
   * List all stored keys
   */
  async listKeys(): Promise<Array<{ label: string; handle: string; type: string }>> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const keys: Array<{ label: string; handle: string; type: string }> = [];
      
      for (const obj of this.session.find()) {
        const key = obj.toType<graphene.Key>();
        keys.push({
          label: key.label,
          handle: key.handle.toString('hex'),
          type: key.class === graphene.ObjectClass.SECRET_KEY ? 'secret' : 'private',
        });
      }
      
      return keys;
    } catch (error) {
      logger.error('Failed to list keys:', error);
      throw error;
    }
  }

  /**
   * Delete key
   */
  async deleteKey(handle: string): Promise<void> {
    if (!this.session) {
      throw new Error('HSM session not initialized');
    }

    try {
      const key = await this.getKey(handle);
      this.session.destroy(key);
      logger.info(`Deleted key with handle: ${handle}`);
    } catch (error) {
      logger.error(`Failed to delete key ${handle}:`, error);
      throw error;
    }
  }

  /**
   * Close session and clean up resources
   */
  async close(): Promise<void> {
    if (this.session) {
      try {
        this.session.logout();
        this.session.close();
        this.session = null;
        logger.info('HSM session closed');
      } catch (error) {
        logger.error('Failed to close HSM session:', error);
      }
    }

    if (this.mod) {
      try {
        this.mod.finalize();
        logger.info('HSM finalized');
      } catch (error) {
        logger.error('Failed to finalize HSM:', error);
      }
    }
  }
}

// Singleton instance
let hsmInstance: SoftHSM | null = null;

export function getHSM(): SoftHSM {
  if (!hsmInstance) {
    const config: HSMConfig = {
      modulePath: process.env.PKCS11_MODULE_PATH || '/usr/lib/softhsm/libsofthsm2.so',
      tokenLabel: process.env.HSM_TOKEN_LABEL || 'MPC-Token',
      userPin: process.env.HSM_USER_PIN || '1234',
    };
    hsmInstance = new SoftHSM(config);
  }
  return hsmInstance;
}

export async function initializeHSM(): Promise<void> {
  const hsm = getHSM();
  await hsm.initialize();
}

export async function closeHSM(): Promise<void> {
  if (hsmInstance) {
    await hsmInstance.close();
    hsmInstance = null;
  }
}
