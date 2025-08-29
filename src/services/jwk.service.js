import { safeLogger } from '../config/logger.js';
import { generalCache } from '../cache/general.cache.js';
import { publishEvent } from '../events/index.js';
import { v4 as uuidv4 } from 'uuid';
import * as jose from 'jose';
import { env } from '../config/env.js';

class JWKService {
  static KEY_ROTATION_INTERVAL;
  static MAX_KEYS;
  static CACHE_TTL;
  static RSA_KEY_SIZE;
  static JWT_ALGORITHM;

  static {
    const config = env.services.jwk;
    const jwtConfig = env.jwt;
    JWKService.KEY_ROTATION_INTERVAL = config.keyRotationInterval;
    JWKService.MAX_KEYS = config.maxKeys;
    JWKService.CACHE_TTL = config.cacheTTL;
    JWKService.RSA_KEY_SIZE = config.rsaKeySize;
    JWKService.JWT_ALGORITHM = jwtConfig.accessAlgorithm;

    safeLogger.info('JWKService initialized with config', {
      config,
      jwtConfig,
    });
  }

  constructor() {
    this.keyRotationInterval = JWKService.KEY_ROTATION_INTERVAL;
    this.maxKeys = JWKService.MAX_KEYS;
    this.cacheTTL = JWKService.CACHE_TTL;
    this._activeKeys = [];
    this.keyRotationTimer = null;
  }

  async initialize() {
    try {
      const keys = await this.getActiveKeys();
      if (keys.length === 0) {
        await this.generateKeyPair();
        safeLogger.info('Initial JWK key generated');
      } else {
        await this.validateAndRotateKeys();
        safeLogger.info('JWK service initialized with existing keys', {
          keyCount: keys.length,
        });
      }
      this.startRotationTimer();
    } catch (error) {
      safeLogger.error('Failed to initialize JWK service', {
        error: error.message,
      });
      throw error;
    }
  }

  async generateKeyPair() {
    try {
      const keyId = this.generateKeyId();

      const pemPair = await jose.generateKeyPair(JWKService.JWT_ALGORITHM, {
        modulusLength: JWKService.RSA_KEY_SIZE,
      });

      const keyPair = await this.pemToJwk(pemPair, keyId);

      await this.storeKeyPair(keyPair);

      safeLogger.info('Key pair generated', {
        kid: keyId,
        algorithm: JWKService.JWT_ALGORITHM,
      });
      return keyPair;
    } catch (error) {
      safeLogger.error('Failed to generate key pair', {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  }

  async pemToJwk(pemPair, keyId) {
    try {
      const { publicKey, privateKey } = pemPair;
      const publicKeyJwk = await jose.exportJWK(publicKey);

      const jwk = {
        ...publicKeyJwk,
        kid: keyId,
        alg: JWKService.JWT_ALGORITHM,
      };

      const keyPair = {
        kid: keyId,
        publicKey,
        privateKey,
        jwk,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + this.keyRotationInterval),
      };

      return keyPair;
    } catch (error) {
      safeLogger.error('Failed to convert PEM to JWK', {
        error: error.message,
      });
      throw error;
    }
  }

  async getJWKSet() {
    try {
      const cached = await generalCache.get('jwk', 'set');

      if (cached) {
        return cached;
      }

      const keys = await this.getActiveKeys();

      if (keys.length === 0) {
        safeLogger.warn('No keys available for JWK set');
        return { keys: [] };
      }

      const jwkSet = {
        keys: keys.map(key => key.jwk),
      };

      try {
        await generalCache.set('jwk', 'set', jwkSet, {
          ttl: this.cacheTTL,
          compress: true,
        });
      } catch (cacheError) {
        safeLogger.warn('Failed to cache JWK set, but continuing', {
          error: cacheError.message,
        });
      }
      return jwkSet;
    } catch (error) {
      safeLogger.error('Failed to get JWK Set', {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  }

  async getJWKByKid(kid) {
    try {
      const key = await this.getKeyByKid(kid);

      return key?.jwk || null;
    } catch (error) {
      safeLogger.error('Failed to get JWK by KID', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }

  async rotateKeys() {
    try {
      const newKey = await this.generateKeyPair();
      const keys = await this.getAllKeys();

      if (keys.length > this.maxKeys) {
        const keysToRemove = keys
          .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
          .slice(0, keys.length - this.maxKeys);
        for (const key of keysToRemove) {
          this.removeKey(key.kid);
        }
      }

      const finalKeys = await this.getActiveKeys();

      await generalCache.delete('jwk', 'set');

      await publishEvent('jwk.keys_rotated', {
        newKid: newKey.kid,
        totalKeys: finalKeys.length,
        timestamp: new Date(),
      });

      safeLogger.info('Key rotation completed', {
        newKid: newKey.kid,
        totalKeys: finalKeys.length,
      });

      return {
        newKid: newKey.kid,
        totalKeys: finalKeys.length,
        rotatedAt: new Date(),
      };
    } catch (error) {
      safeLogger.error('Failed to rotate keys', {
        error: error.message,
      });
      throw error;
    }
  }

  async getPrivateKey(kid) {
    try {
      const key = await this.getKeyByKid(kid);
      if (!key) {
        throw new Error('Key not found');
      }
      return key.privateKey;
    } catch (error) {
      safeLogger.error('Failed to get private key', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }

  async getCurrentSigningKey() {
    try {
      const keys = await this.getActiveKeys();
      if (keys.length === 0) {
        const newKey = await this.generateKeyPair();
        return newKey;
      }
      const sortedKeys = keys.sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
      );
      return sortedKeys[0];
    } catch (error) {
      safeLogger.error('Failed to get current signing key', {
        error: error.message,
      });
      throw error;
    }
  }

  async validateAndRotateKeys() {
    try {
      const keys = await this.getActiveKeys();
      const now = new Date();

      const expiringKeys = keys.filter(key => {
        const expiresAt = new Date(key.expiresAt);
        const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);
        return expiresAt <= oneHourFromNow;
      });

      if (expiringKeys.length > 0) {
        await this.rotateKeys();
        return true;
      }
      return false;
    } catch (error) {
      safeLogger.error('Failed to validate and rotate keys', {
        error: error.message,
      });
      throw error;
    }
  }

  async storeKeyPair(keyPair) {
    try {
      if (!this._activeKeys) {
        this._activeKeys = [];
      }

      this._activeKeys = this._activeKeys.filter(
        key => key.kid !== keyPair.kid
      );

      this._activeKeys.push(keyPair);
    } catch (error) {
      safeLogger.error('Failed to store key pair', {
        error: error.message,
        kid: keyPair?.kid,
      });
      throw error;
    }
  }

  async getKeyByKid(kid) {
    try {
      const keys = await this.getActiveKeys();
      const foundKey = keys.find(key => key.kid === kid);

      return foundKey || null;
    } catch (error) {
      safeLogger.error('Failed to get key by KID', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }

  async getActiveKeys() {
    try {
      if (!this._activeKeys || this._activeKeys.length === 0) {
        return [];
      }

      const now = new Date();
      const activeKeys = this._activeKeys.filter(
        key => new Date(key.expiresAt) > now
      );

      if (activeKeys.length === 0) {
        return [];
      }

      return activeKeys;
    } catch (error) {
      safeLogger.error('Failed to get active keys', {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  }

  async getAllKeys() {
    return this._activeKeys || [];
  }

  removeKey(kid) {
    try {
      if (this._activeKeys) {
        this._activeKeys = this._activeKeys.filter(key => key.kid !== kid);
      }
    } catch (error) {
      safeLogger.error('Failed to remove key', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }

  generateKeyId() {
    return `jwk-${uuidv4()}`;
  }

  startRotationTimer() {
    this.rotationTimer = setInterval(
      async () => {
        try {
          const wasRotated = await this.validateAndRotateKeys();
          if (wasRotated) {
            safeLogger.info('Keys automatically rotated via scheduler');
          }
        } catch (error) {
          safeLogger.error('Scheduled key rotation failed', {
            error: error.message,
            stack: error.stack,
          });
        }
      },
      2 * 60 * 1000
    );

    safeLogger.info('Key rotation timer started - validating every 2 minutes');
  }

  stopRotationTimer() {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
      safeLogger.info('Key rotation timer stopped');
    }
  }

  async shutdown() {
    this.stopRotationTimer();
    safeLogger.info('JWK service shutdown');
  }

  async getKeyStats() {
    const keys = await this.getAllKeys();
    const activeKeys = await this.getActiveKeys();
    return {
      totalKeys: keys.length,
      activeKeys: activeKeys.length,
      expiredKeys: keys.length - activeKeys.length,
      nextRotation:
        activeKeys.length > 0
          ? Math.min(...activeKeys.map(k => new Date(k.expiresAt)))
          : null,
      lastRotation:
        activeKeys.length > 0
          ? Math.max(...activeKeys.map(k => new Date(k.createdAt)))
          : null,
      lastCheck: new Date(),
    };
  }

  async getHealthStatus() {
    try {
      const keys = await this.getAllKeys();
      const activeKeys = await this.getActiveKeys();
      const now = new Date();

      const nextRotation =
        keys.length > 0
          ? Math.min(...keys.map(k => new Date(k.expiresAt)))
          : null;

      return {
        status: activeKeys.length > 0 ? 'healthy' : 'unhealthy',
        activeKeys: activeKeys.length,
        totalKeys: keys.length,
        expiredKeys: keys.length - activeKeys.length,
        nextRotation,
        lastCheck: now,
      };
    } catch (error) {
      safeLogger.error('Failed to get service status', {
        error: error.message,
      });

      return {
        status: 'unhealthy',
        error: error.message,
        lastCheck: new Date(),
      };
    }
  }

  async forceRefreshKeys() {
    try {
      safeLogger.info('Starting force refresh of keys');

      this._activeKeys = [];

      const newKey = await this.generateKeyPair();

      try {
        await generalCache.delete('jwk', 'set');
      } catch (cacheError) {
        safeLogger.warn('Failed to clear cache during force refresh', {
          error: cacheError.message,
        });
      }

      safeLogger.info('Force refresh completed', {
        newKid: newKey.kid,
      });

      return {
        success: true,
        newKid: newKey.kid,
        message: 'Keys force refreshed successfully',
      };
    } catch (error) {
      safeLogger.error('Failed to force refresh keys', {
        error: error.message,
      });

      return {
        success: false,
        error: error.message,
        message: 'Failed to force refresh keys',
      };
    }
  }

  async cleanupExpiredKeys() {
    const keys = await this.getAllKeys();
    const expiredKeys = keys.filter(
      key => new Date(key.expiresAt) < new Date()
    );
    return expiredKeys.length;
  }
}
const jwkService = new JWKService();
export default jwkService;

const initializeJWKService = async () => {
  await jwkService.initialize();
};

const shutdownJWKService = async () => {
  await jwkService.shutdown();
};

export { initializeJWKService, shutdownJWKService };
