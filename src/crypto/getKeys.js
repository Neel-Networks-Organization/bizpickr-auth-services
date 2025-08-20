import fs from 'fs';
import path from 'path';
import { importPKCS8, importSPKI } from 'jose/key/import';
import { getCurrentKeyMeta } from './keyManager.js';
import { safeLogger } from '../config/logger.js';
import { ApiError } from '../utils/index.js';
/**
 * Industry-level Key Management Service
 *
 * Features:
 * - Enhanced error handling and logging
 * - Key validation and security checks
 * - Performance monitoring and caching
 * - Key rotation support
 * - Security audit trails
 */
// Key cache for performance optimization
const keyCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
/**
 * Get private key with enhanced security and caching
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Object containing private key and kid
 */
export async function getPrivateKey(options = {}) {
  try {
    const keyMeta = getCurrentKeyMeta();
    if (!keyMeta) {
      throw new ApiError(503, 'No current private key found', [
        'Key management service is unavailable',
        'Please try again later',
      ]);
    }
    // Check cache first
    const cacheKey = `private_${keyMeta.kid}`;
    const cached = keyCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      safeLogger.debug('Private key retrieved from cache', {
        kid: keyMeta.kid,
        cacheHit: true,
      });
      return cached.data;
    }
    // Validate key file path
    const keyPath = path.join(process.cwd(), 'keys', keyMeta.private);
    if (!fs.existsSync(keyPath)) {
      throw new ApiError(500, 'Private key file not found', [
        'Key file is missing from the filesystem',
        'Please check key rotation process',
      ]);
    }
    // Read and validate private key
    const privatePem = fs.readFileSync(keyPath, 'utf-8');
    if (!privatePem || privatePem.trim().length === 0) {
      throw new ApiError(500, 'Private key file is empty', [
        'Key file contains no data',
        'Please check key generation process',
      ]);
    }
    // Import and validate private key
    const pirvateKey = await importPKCS8(privatePem, 'RS256');
    if (!pirvateKey) {
      throw new ApiError(500, 'Failed to import private key', [
        'Key format is invalid',
        'Please check key generation process',
      ]);
    }
    const result = { pirvateKey, kid: keyMeta.kid };
    // Cache the result
    keyCache.set(cacheKey, {
      data: result,
      timestamp: Date.now(),
    });
    safeLogger.info('Private key retrieved successfully', {
      kid: keyMeta.kid,
      keyPath: keyMeta.private,
      cacheHit: false,
    });
    return result;
  } catch (error) {
    safeLogger.error('Failed to get private key', {
      error: error.message,
      stack: error.stack,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to retrieve private key', [
      'Key retrieval process failed',
      'Please try again later',
    ]);
  }
}
/**
 * Get public key with enhanced security and caching
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Public key object
 */
export async function getPublicKey(options = {}) {
  try {
    const keyMeta = getCurrentKeyMeta();
    if (!keyMeta) {
      throw new ApiError(503, 'No current public key found', [
        'Key management service is unavailable',
        'Please try again later',
      ]);
    }
    // Check cache first
    const cacheKey = `public_${keyMeta.kid}`;
    const cached = keyCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      safeLogger.debug('Public key retrieved from cache', {
        kid: keyMeta.kid,
        cacheHit: true,
      });
      return cached.data;
    }
    // Validate key file path
    const keyPath = path.join(process.cwd(), 'keys', keyMeta.public);
    if (!fs.existsSync(keyPath)) {
      throw new ApiError(500, 'Public key file not found', [
        'Key file is missing from the filesystem',
        'Please check key rotation process',
      ]);
    }
    // Read and validate public key
    const publicPem = fs.readFileSync(keyPath, 'utf-8');
    if (!publicPem || publicPem.trim().length === 0) {
      throw new ApiError(500, 'Public key file is empty', [
        'Key file contains no data',
        'Please check key generation process',
      ]);
    }
    // Import and validate public key
    const publicKey = await importSPKI(publicPem, 'RS256');
    if (!publicKey) {
      throw new ApiError(500, 'Failed to import public key', [
        'Key format is invalid',
        'Please check key generation process',
      ]);
    }
    // Cache the result
    keyCache.set(cacheKey, {
      data: publicKey,
      timestamp: Date.now(),
    });
    safeLogger.info('Public key retrieved successfully', {
      kid: keyMeta.kid,
      keyPath: keyMeta.public,
      cacheHit: false,
    });
    return publicKey;
  } catch (error) {
    safeLogger.error('Failed to get public key', {
      error: error.message,
      stack: error.stack,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to retrieve public key', [
      'Key retrieval process failed',
      'Please try again later',
    ]);
  }
}
/**
 * Get all available public keys
 * @param {Object} options - Additional options
 * @returns {Promise<Array>} Array of public key objects
 */
export async function getAllPublicKeys(options = {}) {
  try {
    const { getAllPublicKeysMeta } = await import('./keyManager.js');
    const keysMeta = getAllPublicKeysMeta();
    if (!keysMeta || keysMeta.length === 0) {
      throw new ApiError(503, 'No public keys available', [
        'Key management service is unavailable',
        'Please try again later',
      ]);
    }
    const publicKeys = [];
    for (const { kid, public: publicPath } of keysMeta) {
      try {
        const keyPath = path.join(process.cwd(), 'keys', publicPath);
        if (!fs.existsSync(keyPath)) {
          safeLogger.warn('Public key file not found', { kid, publicPath });
          continue;
        }
        const publicPem = fs.readFileSync(keyPath, 'utf-8');
        if (!publicPem || publicPem.trim().length === 0) {
          safeLogger.warn('Public key file is empty', { kid, publicPath });
          continue;
        }
        const publicKey = await importSPKI(publicPem, 'RS256');
        if (publicKey) {
          publicKeys.push({ kid, publicKey, publicPath });
        }
      } catch (error) {
        safeLogger.error('Failed to process public key', {
          kid,
          publicPath,
          error: error.message,
        });
        // Continue with other keys instead of failing completely
      }
    }
    if (publicKeys.length === 0) {
      throw new ApiError(503, 'Failed to retrieve any public keys', [
        'All public keys are unavailable',
        'Please try again later',
      ]);
    }
    safeLogger.info('All public keys retrieved successfully', {
      totalKeys: keysMeta.length,
      successfulKeys: publicKeys.length,
      failedKeys: keysMeta.length - publicKeys.length,
    });
    return publicKeys;
  } catch (error) {
    safeLogger.error('Failed to get all public keys', {
      error: error.message,
      stack: error.stack,
    });
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(500, 'Failed to retrieve public keys', [
      'Key retrieval process failed',
      'Please try again later',
    ]);
  }
}
/**
 * Clear key cache
 * @returns {number} Number of cached items cleared
 */
export function clearKeyCache() {
  const cacheSize = keyCache.size;
  keyCache.clear();
  safeLogger.info('Key cache cleared', {
    clearedItems: cacheSize,
  });
  return cacheSize;
}
/**
 * Get key cache statistics
 * @returns {Object} Cache statistics
 */
export function getKeyCacheStats() {
  const now = Date.now();
  let validEntries = 0;
  let expiredEntries = 0;
  for (const [key, value] of keyCache.entries()) {
    if (now - value.timestamp < CACHE_TTL) {
      validEntries++;
    } else {
      expiredEntries++;
    }
  }
  return {
    totalEntries: keyCache.size,
    validEntries,
    expiredEntries,
    cacheTTL: CACHE_TTL,
  };
}
/**
 * Clean up expired cache entries
 * @returns {number} Number of entries cleaned
 */
export function cleanupExpiredCacheEntries() {
  const now = Date.now();
  let cleanedCount = 0;
  for (const [key, value] of keyCache.entries()) {
    if (now - value.timestamp >= CACHE_TTL) {
      keyCache.delete(key);
      cleanedCount++;
    }
  }
  if (cleanedCount > 0) {
    safeLogger.info('Cleaned up expired cache entries', {
      cleanedCount,
      remainingEntries: keyCache.size,
    });
  }
  return cleanedCount;
}
// Cleanup expired cache entries every 10 minutes
setInterval(cleanupExpiredCacheEntries, 10 * 60 * 1000);
