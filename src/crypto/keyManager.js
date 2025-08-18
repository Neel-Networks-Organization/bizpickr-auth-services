import fs from 'fs';
import path from 'path';
import { generateKeyPair } from 'jose';
import { exportPKCS8, exportSPKI } from 'jose';
import ms from 'ms';
import { env } from '../config/env.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/ApiError.js';
/**
 * Industry-level Key Manager Service
 *
 * Features:
 * - Enhanced error handling and logging
 * - Key validation and security checks
 * - Performance monitoring and metrics
 * - Key rotation with backup strategies
 * - Security audit trails
 * - Health monitoring
 */
const KEYS_DIR = path.join(process.cwd(), 'keys');
const KEYS_JSON = path.join(KEYS_DIR, 'keys.json');
// Key management metrics
const keyMetrics = {
  totalRotations: 0,
  lastRotation: null,
  failedRotations: 0,
  keyGenerationTime: 0,
  activeKeys: 0,
};
/**
 * Load keys metadata with enhanced error handling
 * @returns {Object} Keys metadata
 */
function loadKeysMeta() {
  try {
    if (!fs.existsSync(KEYS_JSON)) {
      safeLogger.info('Keys metadata file not found, creating new one');
      return { current: null, keys: [] };
    }
    const data = fs.readFileSync(KEYS_JSON, 'utf-8');
    if (!data || data.trim().length === 0) {
      safeLogger.warn('Keys metadata file is empty');
      return { current: null, keys: [] };
    }
    const meta = JSON.parse(data);
    // Validate metadata structure
    if (!meta || typeof meta !== 'object') {
      throw new Error('Invalid metadata structure');
    }
    if (!Array.isArray(meta.keys)) {
      meta.keys = [];
    }
    if (!meta.current && meta.keys.length > 0) {
      meta.current = meta.keys[0].kid;
      safeLogger.info('No current key set, using first available key', {
        currentKey: meta.current,
      });
    }
    return meta;
  } catch (error) {
    safeLogger.error('Failed to load keys metadata', {
      error: error.message,
      stack: error.stack,
    });
    // Return safe default
    return { current: null, keys: [] };
  }
}
/**
 * Save keys metadata with enhanced error handling
 * @param {Object} meta - Keys metadata
 */
function saveKeysMeta(meta) {
  try {
    // Validate metadata before saving
    if (!meta || typeof meta !== 'object') {
      throw new Error('Invalid metadata object');
    }
    if (!Array.isArray(meta.keys)) {
      throw new Error('Keys array is required');
    }
    // Create keys directory if it doesn't exist
    if (!fs.existsSync(KEYS_DIR)) {
      fs.mkdirSync(KEYS_DIR, { recursive: true });
      safeLogger.info('Created keys directory', { path: KEYS_DIR });
    }
    // Create backup of existing metadata
    if (fs.existsSync(KEYS_JSON)) {
      const backupPath = `${KEYS_JSON}.backup.${Date.now()}`;
      fs.copyFileSync(KEYS_JSON, backupPath);
      safeLogger.debug('Created metadata backup', { backupPath });
    }
    // Save metadata with pretty formatting
    fs.writeFileSync(KEYS_JSON, JSON.stringify(meta, null, 2));
    safeLogger.debug('Keys metadata saved successfully', {
      totalKeys: meta.keys.length,
      currentKey: meta.current,
    });
  } catch (error) {
    safeLogger.error('Failed to save keys metadata', {
      error: error.message,
      stack: error.stack,
    });
    throw new ApiError(500, 'Failed to save key metadata', [
      'Key management system error',
      'Please check system permissions',
    ]);
  }
}
/**
 * Get current key metadata with validation
 * @returns {Object|null} Current key metadata
 */
export function getCurrentKeyMeta() {
  try {
    const meta = loadKeysMeta();
    const currentKey = meta.keys.find(k => k.kid === meta.current);
    if (!currentKey) {
      safeLogger.warn('No current key found in metadata');
      return null;
    }
    // Validate key files exist
    const privatePath = path.join(KEYS_DIR, currentKey.private);
    const publicPath = path.join(KEYS_DIR, currentKey.public);
    if (!fs.existsSync(privatePath) || !fs.existsSync(publicPath)) {
      safeLogger.error('Current key files missing', {
        kid: currentKey.kid,
        privatePath: currentKey.private,
        publicPath: currentKey.public,
      });
      return null;
    }
    safeLogger.debug('Current key metadata retrieved', {
      kid: currentKey.kid,
      createdAt: currentKey.createdAt,
      expiresAt: currentKey.expiresAt,
    });
    return currentKey;
  } catch (error) {
    safeLogger.error('Failed to get current key metadata', {
      error: error.message,
      stack: error.stack,
    });
    return null;
  }
}
/**
 * Get all public keys metadata with validation
 * @returns {Array} Array of public key metadata
 */
export function getAllPublicKeysMeta() {
  try {
    const meta = loadKeysMeta();
    const validKeys = [];
    for (const key of meta.keys) {
      const publicPath = path.join(KEYS_DIR, key.public);
      if (fs.existsSync(publicPath)) {
        validKeys.push({ kid: key.kid, public: key.public });
      } else {
        safeLogger.warn('Public key file missing', {
          kid: key.kid,
          publicPath: key.public,
        });
      }
    }
    safeLogger.debug('Public keys metadata retrieved', {
      totalKeys: meta.keys.length,
      validKeys: validKeys.length,
    });
    return validKeys;
  } catch (error) {
    safeLogger.error('Failed to get public keys metadata', {
      error: error.message,
      stack: error.stack,
    });
    return [];
  }
}
/**
 * Check if current key is valid with enhanced validation
 * @returns {boolean} Key validity status
 */
function hasValidCurrentKey() {
  try {
    if (!fs.existsSync(KEYS_JSON)) {
      safeLogger.debug('Keys metadata file not found');
      return false;
    }
    const meta = JSON.parse(fs.readFileSync(KEYS_JSON, 'utf-8'));
    if (!meta.current) {
      safeLogger.debug('No current key set');
      return false;
    }
    const currentKey = meta.keys.find(k => k.kid === meta.current);
    if (!currentKey) {
      safeLogger.warn('Current key not found in metadata', {
        currentKey: meta.current,
        availableKeys: meta.keys.map(k => k.kid),
      });
      return false;
    }
    // Check if key files exist
    const privatePath = path.join(KEYS_DIR, currentKey.private);
    const publicPath = path.join(KEYS_DIR, currentKey.public);
    if (!fs.existsSync(privatePath) || !fs.existsSync(publicPath)) {
      safeLogger.warn('Current key files missing', {
        kid: currentKey.kid,
        privatePath: currentKey.private,
        publicPath: currentKey.public,
      });
      return false;
    }
    // Check if not expired
    const isExpired = new Date(currentKey.expiresAt).getTime() <= Date.now();
    if (isExpired) {
      safeLogger.warn('Current key has expired', {
        kid: currentKey.kid,
        expiresAt: currentKey.expiresAt,
        currentTime: new Date().toISOString(),
      });
      return false;
    }
    safeLogger.debug('Current key is valid', {
      kid: currentKey.kid,
      expiresAt: currentKey.expiresAt,
    });
    return true;
  } catch (error) {
    safeLogger.error('Error checking key validity', {
      error: error.message,
      stack: error.stack,
    });
    return false;
  }
}
/**
 * Rotate keys with enhanced error handling and monitoring
 * @param {Object} options - Rotation options
 * @returns {Promise<void>}
 */
export async function rotateKeys(options = {}) {
  const startTime = Date.now();
  try {
    if (hasValidCurrentKey()) {
      safeLogger.info('Valid current key exists, skipping key generation', {
        skipReason: 'valid_key_exists',
      });
      return;
    }
    safeLogger.info('Starting JWT key rotation process');
    const now = new Date();
    const kid =
      now
        .toISOString()
        .replace(/[-:.TZ]/g, '')
        .slice(0, 12) + 'Z';
    const privatePath = `${kid}_private.pem`;
    const publicPath = `${kid}_public.pem`;
    // Generate key pair with enhanced security
    const keyGenStartTime = Date.now();
    const { publicKey, privateKey } = await generateKeyPair('RS256', {
      modulusLength: 2048,
      extractable: true,
    });
    const keyGenTime = Date.now() - keyGenStartTime;
    keyMetrics.keyGenerationTime = keyGenTime;
    safeLogger.info('Key pair generated successfully', {
      kid,
      keyGenTime: `${keyGenTime}ms`,
      modulusLength: 2048,
    });
    // Export keys
    const privatePem = await exportPKCS8(privateKey);
    const publicPem = await exportSPKI(publicKey);
    // Ensure keys directory exists
    fs.mkdirSync(KEYS_DIR, { recursive: true });
    // Write key files with proper permissions
    const privateKeyPath = path.join(KEYS_DIR, privatePath);
    const publicKeyPath = path.join(KEYS_DIR, publicPath);
    fs.writeFileSync(privateKeyPath, privatePem);
    fs.writeFileSync(publicKeyPath, publicPem);
    // Set restrictive permissions on private key
    if (process.platform !== 'win32') {
      fs.chmodSync(privateKeyPath, 0o600); // Read/write for owner only
      fs.chmodSync(publicKeyPath, 0o644); // Read for all, write for owner
    }
    safeLogger.info('Key files written successfully', {
      kid,
      privatePath,
      publicPath,
    });
    // Update metadata
    const meta = loadKeysMeta();
    const createdAt = now.toISOString();
    const retentionMs = ms(env.PRIVATE_KEY_RETENTION) || 60 * 60 * 1000;
    const expiresAt = new Date(now.getTime() + retentionMs).toISOString();
    const newKey = {
      kid,
      private: privatePath,
      public: publicPath,
      createdAt,
      expiresAt,
    };
    meta.keys.push(newKey);
    meta.current = kid;
    // Clean up old keys (keep last 5 keys)
    if (meta.keys.length > 5) {
      const keysToRemove = meta.keys.slice(0, meta.keys.length - 5);
      for (const oldKey of keysToRemove) {
        try {
          const oldPrivatePath = path.join(KEYS_DIR, oldKey.private);
          const oldPublicPath = path.join(KEYS_DIR, oldKey.public);
          if (fs.existsSync(oldPrivatePath)) {
            fs.unlinkSync(oldPrivatePath);
          }
          if (fs.existsSync(oldPublicPath)) {
            fs.unlinkSync(oldPublicPath);
          }
          safeLogger.info('Removed old key files', {
            kid: oldKey.kid,
            privatePath: oldKey.private,
            publicPath: oldKey.public,
          });
        } catch (error) {
          safeLogger.warn('Failed to remove old key files', {
            kid: oldKey.kid,
            error: error.message,
          });
        }
      }
      meta.keys = meta.keys.slice(-5);
    }
    saveKeysMeta(meta);
    // Update metrics
    keyMetrics.totalRotations++;
    keyMetrics.lastRotation = now.toISOString();
    keyMetrics.activeKeys = meta.keys.length;
    const totalTime = Date.now() - startTime;
    safeLogger.info('Key rotation completed successfully', {
      kid,
      totalTime: `${totalTime}ms`,
      keyGenTime: `${keyGenTime}ms`,
      totalRotations: keyMetrics.totalRotations,
      activeKeys: keyMetrics.activeKeys,
    });
  } catch (error) {
    keyMetrics.failedRotations++;
    safeLogger.error('Key rotation failed', {
      error: error.message,
      stack: error.stack,
      failedRotations: keyMetrics.failedRotations,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to rotate keys', [
      'Key rotation process failed',
      'Please check system permissions and disk space',
    ]);
  }
}
/**
 * Get key management metrics
 * @returns {Object} Key metrics
 */
export function getKeyMetrics() {
  return {
    ...keyMetrics,
    currentTime: new Date().toISOString(),
    keysDirectory: KEYS_DIR,
    metadataFile: KEYS_JSON,
  };
}
/**
 * Get key health status
 * @returns {Object} Health status
 */
export function getKeyHealth() {
  const currentKey = getCurrentKeyMeta();
  const allKeys = getAllPublicKeysMeta();
  return {
    status: currentKey ? 'healthy' : 'unhealthy',
    currentKey: currentKey
      ? {
        kid: currentKey.kid,
        createdAt: currentKey.createdAt,
        expiresAt: currentKey.expiresAt,
        isValid: hasValidCurrentKey(),
      }
      : null,
    totalKeys: allKeys.length,
    lastRotation: keyMetrics.lastRotation,
    totalRotations: keyMetrics.totalRotations,
    failedRotations: keyMetrics.failedRotations,
  };
}
/**
 * Clean up expired keys
 * @returns {number} Number of keys cleaned
 */
export function cleanupExpiredKeys() {
  try {
    const meta = loadKeysMeta();
    const now = new Date();
    let cleanedCount = 0;
    for (const key of meta.keys) {
      if (new Date(key.expiresAt) < now) {
        try {
          const privatePath = path.join(KEYS_DIR, key.private);
          const publicPath = path.join(KEYS_DIR, key.public);
          if (fs.existsSync(privatePath)) {
            fs.unlinkSync(privatePath);
          }
          if (fs.existsSync(publicPath)) {
            fs.unlinkSync(publicPath);
          }
          cleanedCount++;
          safeLogger.info('Cleaned up expired key', {
            kid: key.kid,
            expiresAt: key.expiresAt,
          });
        } catch (error) {
          safeLogger.warn('Failed to clean up expired key', {
            kid: key.kid,
            error: error.message,
          });
        }
      }
    }
    if (cleanedCount > 0) {
      // Remove cleaned keys from metadata
      meta.keys = meta.keys.filter(key => new Date(key.expiresAt) >= now);
      saveKeysMeta(meta);
      safeLogger.info('Key cleanup completed', {
        cleanedCount,
        remainingKeys: meta.keys.length,
      });
    }
    return cleanedCount;
  } catch (error) {
    safeLogger.error('Key cleanup failed', {
      error: error.message,
      stack: error.stack,
    });
    return 0;
  }
}
// Cleanup expired keys every hour
setInterval(cleanupExpiredKeys, 60 * 60 * 1000);
