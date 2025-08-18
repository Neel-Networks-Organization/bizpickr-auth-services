/**
 * JWK Service - Business Logic Layer
 *
 * Handles all JSON Web Key (JWK) related business logic:
 * - Key generation and management
 * - JWK Set operations
 * - Key rotation
 * - Public key distribution
 *
 * @class JWKService
 * @description Manages RSA key pairs for JWT signing and verification
 */
import crypto from 'crypto';
import { safeLogger } from '../config/logger.js';
import { env } from '../config/env.js';
import { generalCache } from '../cache/general.cache.js';
import { publishEvent } from '../events/index.js';
import { v4 as uuidv4 } from 'uuid';
import * as jose from 'jose';

class JWKService {
  // Configuration constants
  static KEY_ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
  static MAX_KEYS = 5; // Maximum number of keys to keep
  static CACHE_TTL = 3600; // 1 hour cache
  static RSA_KEY_SIZE = 2048; // RSA key size in bits
  static JWT_ALGORITHM = 'RS256'; // JWT signing algorithm

  constructor() {
    this.keyRotationInterval = JWKService.KEY_ROTATION_INTERVAL;
    this.maxKeys = JWKService.MAX_KEYS;
    this.cacheTTL = JWKService.CACHE_TTL;
    this._activeKeys = []; // Initialize the active keys array
  }
  /**
   * Generate a new RSA key pair
   * @param {string} kid - Key ID
   * @returns {Promise<Object>} Generated key pair
   */
  async generateKeyPair(kid = null) {
    try {
      safeLogger.info('generateKeyPair called', { providedKid: kid });

      const keyId = kid || this.generateKeyId();
      safeLogger.info('Key ID generated', { keyId });

      // Generate RSA key pair
      safeLogger.info('Generating RSA key pair...');
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: JWKService.RSA_KEY_SIZE,
      });
      safeLogger.info('RSA key pair generated successfully');

      const publicKeyJwk = await jose.exportJWK(publicKey);
      const privateKeyJwk = await jose.exportJWK(privateKey);

      const jwk = {
        ...publicKeyJwk,
        kid: keyId,
        alg: JWKService.JWT_ALGORITHM,
      };

      const privateJwk = {
        ...privateKeyJwk,
        kid: keyId,
        alg: JWKService.JWT_ALGORITHM,
      };

      safeLogger.info('JWK objects created', {
        kid: keyId,
        kty: jwk.kty,
        hasN: !!jwk.n,
        hasE: !!jwk.e,
      });

      const keyPair = {
        kid: keyId,
        publicKey,
        privateKey,
        jwk,
        privateJwk,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + this.keyRotationInterval),
      };

      safeLogger.info('Key pair object created', {
        kid: keyPair.kid,
        hasJwk: !!keyPair.jwk,
        expiresAt: keyPair.expiresAt,
      });

      // Store in memory
      safeLogger.info('Storing key pair...');
      await this.storeKeyPair(keyPair);
      safeLogger.info('Key pair stored successfully');

      safeLogger.info('New key pair generated', {
        kid: keyId,
        algorithm: JWKService.JWT_ALGORITHM,
        keySize: JWKService.RSA_KEY_SIZE,
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
  /**
   * Get current JWK Set
   * @returns {Promise<Object>} JWK Set
   */
  async getJWKSet() {
    try {
      safeLogger.info('getJWKSet called - starting key retrieval');

      // Try to get from cache first
      const cached = await generalCache.get('jwk', 'set');
      safeLogger.info('Cache check result', { cached: !!cached });

      if (cached) {
        safeLogger.info('Returning cached JWK set');
        return cached;
      }

      // Get all active keys
      safeLogger.info('Getting active keys...');
      const keys = await this.getActiveKeys();
      safeLogger.info('Active keys retrieved', {
        keyCount: keys.length,
        keys: keys.map(k => ({ kid: k.kid, hasJwk: !!k.jwk })),
      });

      // Ensure keys is an array and has valid structure
      if (!Array.isArray(keys)) {
        safeLogger.warn('Keys is not an array, returning empty JWK set', {
          keys,
        });
        return { keys: [] };
      }

      const jwkSet = {
        keys: keys.filter(key => key && key.jwk).map(key => key.jwk),
      };

      safeLogger.info('JWK set created', {
        totalKeys: keys.length,
        filteredKeys: jwkSet.keys.length,
        jwkSet,
      });

      // Cache the result
      try {
        await generalCache.set('jwk', 'set', jwkSet, {
          ttl: this.cacheTTL,
          compress: true,
        });
        safeLogger.info('JWK set cached successfully');
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
      // Return empty JWK set instead of throwing error
      return { keys: [] };
    }
  }
  /**
   * Get specific JWK by key ID
   * @param {string} kid - Key ID
   * @returns {Promise<Object>} JWK
   */
  async getJWKByKid(kid) {
    try {
      safeLogger.info('getJWKByKid called', { kid });

      // First check if the key exists in current active keys
      const currentKeys = this._activeKeys || [];
      safeLogger.info('Current _activeKeys state', {
        kid,
        hasActiveKeys: !!this._activeKeys,
        activeKeysLength: currentKeys.length,
        currentKids: currentKeys.map(k => k.kid),
      });

      const key = await this.getKeyByKid(kid);
      safeLogger.info('Key lookup result', {
        kid,
        found: !!key,
        hasJwk: !!key?.jwk,
      });

      if (!key) {
        // Get current active keys for debugging
        const activeKeys = await this.getActiveKeys();
        safeLogger.warn('Key not found, current active keys', {
          kid,
          activeKeysCount: activeKeys.length,
          activeKids: activeKeys.map(k => k.kid),
        });

        // Check if there's a mismatch between _activeKeys and getActiveKeys()
        if (currentKeys.length !== activeKeys.length) {
          safeLogger.error(
            'Inconsistency detected between _activeKeys and getActiveKeys()',
            {
              kid,
              _activeKeysLength: currentKeys.length,
              getActiveKeysLength: activeKeys.length,
              _activeKeysKids: currentKeys.map(k => k.kid),
              getActiveKeysKids: activeKeys.map(k => k.kid),
            }
          );
        }

        throw new Error(`Key not found: ${kid}`);
      }

      return key.jwk;
    } catch (error) {
      safeLogger.error('Failed to get JWK by KID', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }
  /**
   * Rotate keys
   * @returns {Promise<Object>} Rotation result
   */
  async rotateKeys() {
    try {
      // Generate new key
      const newKey = await this.generateKeyPair();
      // Get all keys
      const allKeys = await this.getAllKeys();
      // Remove expired keys
      const activeKeys = allKeys.filter(
        key => new Date(key.expiresAt) > new Date()
      );
      // Keep only the latest keys
      if (activeKeys.length > this.maxKeys) {
        const keysToRemove = activeKeys
          .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
          .slice(0, activeKeys.length - this.maxKeys);
        for (const key of keysToRemove) {
          await this.removeKey(key.kid);
        }
      }
      // Clear cache
      await generalCache.delete('jwk', 'set');
      // Publish key rotation event
      await publishEvent('jwk.keys_rotated', {
        newKid: newKey.kid,
        totalKeys: activeKeys.length + 1,
        timestamp: new Date(),
      });
      safeLogger.info('Keys rotated successfully', {
        newKid: newKey.kid,
        totalKeys: activeKeys.length + 1,
      });
      return {
        newKid: newKey.kid,
        totalKeys: activeKeys.length + 1,
        rotatedAt: new Date(),
      };
    } catch (error) {
      safeLogger.error('Failed to rotate keys', {
        error: error.message,
      });
      throw error;
    }
  }
  /**
   * Get private key for signing
   * @param {string} kid - Key ID
   * @returns {Promise<string>} Private key
   */
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
  /**
   * Get current signing key
   * @returns {Promise<Object>} Current signing key
   */
  async getCurrentSigningKey() {
    try {
      const keys = await this.getActiveKeys();
      if (keys.length === 0) {
        // Generate new key if none exist
        return await this.generateKeyPair();
      }
      // Return the most recent key
      return keys.sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
      )[0];
    } catch (error) {
      safeLogger.error('Failed to get current signing key', {
        error: error.message,
      });
      throw error;
    }
  }
  /**
   * Validate key expiration and rotate if needed
   * @returns {Promise<boolean>} Whether rotation was performed
   */
  async validateAndRotateKeys() {
    try {
      const keys = await this.getActiveKeys();
      const now = new Date();
      // Check if any key is expiring soon (within 1 hour)
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
  /**
   * Get key statistics
   * @returns {Promise<Object>} Key statistics
   */
  async getKeyStats() {
    try {
      const allKeys = await this.getAllKeys();
      const activeKeys = await this.getActiveKeys();
      const expiredKeys = allKeys.filter(
        key => new Date(key.expiresAt) <= new Date()
      );
      return {
        total: allKeys.length,
        active: activeKeys.length,
        expired: expiredKeys.length,
        nextRotation:
          activeKeys.length > 0
            ? Math.min(...activeKeys.map(k => new Date(k.expiresAt)))
            : null,
        lastRotation:
          activeKeys.length > 0
            ? Math.max(...activeKeys.map(k => new Date(k.createdAt)))
            : null,
      };
    } catch (error) {
      safeLogger.error('Failed to get key statistics', {
        error: error.message,
      });
      throw error;
    }
  }
  /**
   * Store key pair in Redis
   * @param {Object} keyPair - Key pair object
   * @returns {Promise<void>}
   */
  async storeKeyPair(keyPair) {
    try {
      // Store in memory instead of Redis for now
      if (!this._activeKeys) {
        this._activeKeys = [];
      }

      // Remove existing key with same kid if exists
      this._activeKeys = this._activeKeys.filter(
        key => key.kid !== keyPair.kid
      );

      // Add new key
      this._activeKeys.push(keyPair);

      safeLogger.info('Key pair stored in memory', { kid: keyPair.kid });
    } catch (error) {
      safeLogger.error('Failed to store key pair', {
        error: error.message,
        kid: keyPair.kid,
      });
      throw error;
    }
  }
  /**
   * Get key by KID
   * @param {string} kid - Key ID
   * @returns {Promise<Object>} Key pair
   */
  async getKeyByKid(kid) {
    try {
      safeLogger.info('getKeyByKid called', { kid });

      const keys = await this.getActiveKeys();
      safeLogger.info('Active keys retrieved for lookup', {
        kid,
        totalKeys: keys.length,
        keys: keys.map(k => ({ kid: k.kid, hasJwk: !!k.jwk })),
      });

      const foundKey = keys.find(key => key.kid === kid);
      safeLogger.info('Key search result', {
        kid,
        found: !!foundKey,
        foundKid: foundKey?.kid,
      });

      return foundKey || null;
    } catch (error) {
      safeLogger.error('Failed to get key by KID', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }
  /**
   * Get all keys
   * @returns {Promise<Array>} All keys
   */
  async getAllKeys() {
    try {
      return await this.getActiveKeys();
    } catch (error) {
      safeLogger.error('Failed to get all keys', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get active keys
   * @returns {Promise<Array>} Active keys
   */
  async getActiveKeys() {
    try {
      safeLogger.info('getActiveKeys called', {
        hasActiveKeys: !!this._activeKeys,
        activeKeysLength: this._activeKeys?.length || 0,
      });

      // Check if we have any keys in memory
      if (!this._activeKeys || this._activeKeys.length === 0) {
        safeLogger.info('No active keys found, generating initial key...');
        // Generate initial key if none exist
        const initialKey = await this.generateKeyPair();
        safeLogger.info('Initial key generated successfully', {
          kid: initialKey.kid,
          hasJwk: !!initialKey.jwk,
          jwk: initialKey.jwk,
        });
        this._activeKeys = [initialKey];
        safeLogger.info('Generated initial JWK key', { kid: initialKey.kid });
      }

      // Filter out expired keys
      const now = new Date();
      const beforeFilter = this._activeKeys.length;
      this._activeKeys = this._activeKeys.filter(
        key => new Date(key.expiresAt) > now
      );
      const afterFilter = this._activeKeys.length;

      safeLogger.info('Key filtering completed', {
        beforeFilter,
        afterFilter,
        filteredOut: beforeFilter - afterFilter,
      });

      // If no valid keys remain, generate a new one
      if (this._activeKeys.length === 0) {
        safeLogger.info('No valid keys after filtering, generating new key...');
        const newKey = await this.generateKeyPair();
        this._activeKeys = [newKey];
        safeLogger.info('Generated new JWK key after cleanup', {
          kid: newKey.kid,
        });
      }

      safeLogger.info('Returning active keys', {
        count: this._activeKeys.length,
        keys: this._activeKeys.map(k => ({ kid: k.kid, hasJwk: !!k.jwk })),
      });

      return this._activeKeys;
    } catch (error) {
      safeLogger.error('Failed to get active keys', {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  }

  /**
   * Remove key
   * @param {string} kid - Key ID
   * @returns {Promise<void>}
   */
  async removeKey(kid) {
    try {
      if (this._activeKeys) {
        this._activeKeys = this._activeKeys.filter(key => key.kid !== kid);
        safeLogger.info('Key removed from memory', { kid });
      }
    } catch (error) {
      safeLogger.error('Failed to remove key', {
        error: error.message,
        kid,
      });
      throw error;
    }
  }

  /**
   * Generate key ID
   * @returns {string} Key ID
   */
  generateKeyId() {
    return `jwk-${uuidv4()}`;
  }
  /**
   * Initialize JWK service
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      // Check if we have any keys
      const keys = await this.getActiveKeys();
      if (keys.length === 0) {
        // Generate initial key
        await this.generateKeyPair();
        safeLogger.info('Initial JWK key generated');
      } else {
        // Validate existing keys
        await this.validateAndRotateKeys();
        safeLogger.info('JWK service initialized with existing keys', {
          keyCount: keys.length,
        });
      }
    } catch (error) {
      safeLogger.error('Failed to initialize JWK service', {
        error: error.message,
      });
      throw error;
    }
  }
  /**
   * Clean up expired keys
   * @returns {Promise<number>} Number of keys removed
   */
  async cleanupExpiredKeys() {
    try {
      const allKeys = await this.getAllKeys();
      const now = new Date();
      let removedCount = 0;

      for (const key of allKeys) {
        if (new Date(key.expiresAt) <= now) {
          await this.removeKey(key.kid);
          removedCount++;
        }
      }

      if (removedCount > 0) {
        safeLogger.info('Cleaned up expired keys', {
          removedCount,
        });
      }

      return removedCount;
    } catch (error) {
      safeLogger.error('Failed to cleanup expired keys', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get service health status
   * @returns {Promise<Object>} Service health information
   */
  async getHealthStatus() {
    try {
      const keys = await this.getActiveKeys();
      const now = new Date();

      return {
        status: 'healthy',
        activeKeys: keys.length,
        totalKeys: keys.length,
        nextRotation:
          keys.length > 0
            ? Math.min(...keys.map(k => new Date(k.expiresAt)))
            : null,
        lastCheck: now,
        service: 'JWKService',
        version: '1.0.0',
      };
    } catch (error) {
      safeLogger.error('Failed to get health status', {
        error: error.message,
      });

      return {
        status: 'unhealthy',
        error: error.message,
        service: 'JWKService',
        version: '1.0.0',
      };
    }
  }

  /**
   * Force refresh keys and ensure consistency
   * @returns {Promise<Object>} Refresh result
   */
  async forceRefreshKeys() {
    try {
      safeLogger.info('Force refreshing keys...');

      // Clear current keys
      this._activeKeys = [];
      safeLogger.info('Cleared current _activeKeys');

      // Generate new key
      const newKey = await this.generateKeyPair();
      safeLogger.info('Generated new key after force refresh', {
        kid: newKey.kid,
      });

      // Clear cache
      try {
        await generalCache.delete('jwk', 'set');
        safeLogger.info('Cleared JWK cache');
      } catch (cacheError) {
        safeLogger.warn('Failed to clear cache during force refresh', {
          error: cacheError.message,
        });
      }

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
}
export default new JWKService();
