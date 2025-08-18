import crypto from 'crypto';
import { safeLogger } from '../config/logger.js';
/**
 * Secrets Management System
 *
 * Features:
 * - Secure secret storage and retrieval
 * - Encryption/decryption of sensitive data
 * - Secret rotation capabilities
 * - Environment-based secret management
 * - Audit logging for secret access
 * - Key derivation and management
 * - Enterprise-grade secrets management
 */
// ✅ Encryption algorithms
const ENCRYPTION_ALGORITHMS = {
  AES_256_GCM: 'aes-256-gcm',
  AES_256_CBC: 'aes-256-cbc',
  CHACHA20_POLY1305: 'chacha20-poly1305',
};
// ✅ Secret types
const SECRET_TYPES = {
  API_KEY: 'api_key',
  DATABASE_PASSWORD: 'database_password',
  JWT_SECRET: 'jwt_secret',
  ENCRYPTION_KEY: 'encryption_key',
  OAUTH_SECRET: 'oauth_secret',
  WEBHOOK_SECRET: 'webhook_secret',
  CERTIFICATE: 'certificate',
  PRIVATE_KEY: 'private_key',
  CUSTOM: 'custom',
};
// ✅ Secret configuration
const SECRET_CONFIG = {
  algorithm: ENCRYPTION_ALGORITHMS.AES_256_GCM,
  keyLength: 32,
  ivLength: 16,
  saltLength: 64,
  iterations: 100000,
  digest: 'sha512',
  rotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
  maxRetention: 90 * 24 * 60 * 60 * 1000, // 90 days
};
/**
 * Secret Class
 */
class Secret {
  constructor(name, value, type = SECRET_TYPES.CUSTOM, metadata = {}) {
    this.id = crypto.randomUUID();
    this.name = name;
    this.value = value;
    this.type = type;
    this.metadata = {
      createdBy: metadata.createdBy || 'system',
      environment: metadata.environment || process.env.NODE_ENV,
      version: metadata.version || '1.0',
      description: metadata.description || '',
      tags: metadata.tags || [],
      ...metadata,
    };
    this.createdAt = new Date();
    this.updatedAt = new Date();
    this.lastAccessed = null;
    this.accessCount = 0;
    this.encrypted = false;
    this.rotationDate = new Date(Date.now() + SECRET_CONFIG.rotationInterval);
  }
  // ✅ Encrypt secret value
  encrypt(masterKey) {
    try {
      if (this.encrypted) {
        return this;
      }
      const salt = crypto.randomBytes(SECRET_CONFIG.saltLength);
      const key = crypto.pbkdf2Sync(
        masterKey,
        salt,
        SECRET_CONFIG.iterations,
        SECRET_CONFIG.keyLength,
        SECRET_CONFIG.digest,
      );
      const iv = crypto.randomBytes(SECRET_CONFIG.ivLength);
      const cipher = crypto.createCipher(SECRET_CONFIG.algorithm, key);
      cipher.setAAD(Buffer.from(this.name, 'utf8'));
      let encrypted = cipher.update(this.value, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      this.value = {
        encrypted,
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: SECRET_CONFIG.algorithm,
      };
      this.encrypted = true;
      this.updatedAt = new Date();
      safeLogger.debug('Secret encrypted', {
        secretId: this.id,
        secretName: this.name,
        type: this.type,
      });
      return this;
    } catch (error) {
      safeLogger.error('Failed to encrypt secret', {
        secretId: this.id,
        secretName: this.name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Decrypt secret value
  decrypt(masterKey) {
    try {
      if (!this.encrypted) {
        return this.value;
      }
      const { encrypted, salt, iv, authTag, algorithm } = this.value;
      const key = crypto.pbkdf2Sync(
        masterKey,
        Buffer.from(salt, 'hex'),
        SECRET_CONFIG.iterations,
        SECRET_CONFIG.keyLength,
        SECRET_CONFIG.digest,
      );
      const decipher = crypto.createDecipher(algorithm, key);
      decipher.setAAD(Buffer.from(this.name, 'utf8'));
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      this.lastAccessed = new Date();
      this.accessCount++;
      safeLogger.debug('Secret decrypted', {
        secretId: this.id,
        secretName: this.name,
        accessCount: this.accessCount,
      });
      return decrypted;
    } catch (error) {
      safeLogger.error('Failed to decrypt secret', {
        secretId: this.id,
        secretName: this.name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Check if secret needs rotation
  needsRotation() {
    return new Date() >= this.rotationDate;
  }
  // ✅ Rotate secret
  rotate(newValue, metadata = {}) {
    const oldValue = this.value;
    this.value = newValue;
    this.updatedAt = new Date();
    this.rotationDate = new Date(Date.now() + SECRET_CONFIG.rotationInterval);
    this.encrypted = false;
    // ✅ Update metadata
    Object.assign(this.metadata, metadata);
    safeLogger.info('Secret rotated', {
      secretId: this.id,
      secretName: this.name,
      type: this.type,
    });
    return {
      oldValue,
      newValue: this.value,
      rotationDate: this.rotationDate,
    };
  }
  // ✅ Get secret metadata (without value)
  getMetadata() {
    return {
      id: this.id,
      name: this.name,
      type: this.type,
      metadata: this.metadata,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      lastAccessed: this.lastAccessed,
      accessCount: this.accessCount,
      encrypted: this.encrypted,
      rotationDate: this.rotationDate,
      needsRotation: this.needsRotation(),
    };
  }
  // ✅ Validate secret
  validate() {
    const errors = [];
    if (!this.name || this.name.trim().length === 0) {
      errors.push('Secret name is required');
    }
    if (!this.value) {
      errors.push('Secret value is required');
    }
    if (!Object.values(SECRET_TYPES).includes(this.type)) {
      errors.push('Invalid secret type');
    }
    if (this.rotationDate < new Date()) {
      errors.push('Secret rotation date is in the past');
    }
    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
/**
 * Secrets Manager Class
 */
class SecretsManager {
  constructor() {
    this.secrets = new Map();
    this.masterKey =
      process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex');
    this.auditLog = [];
    this.metrics = {
      totalSecrets: 0,
      encryptedSecrets: 0,
      decryptedSecrets: 0,
      rotatedSecrets: 0,
      failedOperations: 0,
    };
  }
  // ✅ Store secret
  store(name, value, type = SECRET_TYPES.CUSTOM, metadata = {}) {
    try {
      const secret = new Secret(name, value, type, metadata);
      const validation = secret.validate();
      if (!validation.isValid) {
        throw new Error(
          `Secret validation failed: ${validation.errors.join(', ')}`,
        );
      }
      // ✅ Encrypt secret before storing
      secret.encrypt(this.masterKey);
      this.secrets.set(secret.id, secret);
      this.metrics.totalSecrets++;
      this.metrics.encryptedSecrets++;
      this.logAudit('store', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
        success: true,
      });
      safeLogger.info('Secret stored', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
      });
      return secret;
    } catch (error) {
      this.metrics.failedOperations++;
      this.logAudit('store', {
        secretName: name,
        type,
        success: false,
        error: error.message,
      });
      safeLogger.error('Failed to store secret', {
        secretName: name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Retrieve secret
  retrieve(name, decrypt = true) {
    try {
      const secret = this.findByName(name);
      if (!secret) {
        throw new Error(`Secret not found: ${name}`);
      }
      let value = secret.value;
      if (decrypt && secret.encrypted) {
        value = secret.decrypt(this.masterKey);
        this.metrics.decryptedSecrets++;
      }
      this.logAudit('retrieve', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
        success: true,
      });
      safeLogger.debug('Secret retrieved', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
      });
      return {
        value,
        metadata: secret.getMetadata(),
      };
    } catch (error) {
      this.metrics.failedOperations++;
      this.logAudit('retrieve', {
        secretName: name,
        success: false,
        error: error.message,
      });
      safeLogger.error('Failed to retrieve secret', {
        secretName: name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Update secret
  update(name, newValue, metadata = {}) {
    try {
      const secret = this.findByName(name);
      if (!secret) {
        throw new Error(`Secret not found: ${name}`);
      }
      const oldValue = secret.value;
      secret.value = newValue;
      secret.updatedAt = new Date();
      secret.encrypted = false;
      // ✅ Re-encrypt with new value
      secret.encrypt(this.masterKey);
      // ✅ Update metadata
      Object.assign(secret.metadata, metadata);
      this.logAudit('update', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
        success: true,
      });
      safeLogger.info('Secret updated', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
      });
      return secret;
    } catch (error) {
      this.metrics.failedOperations++;
      this.logAudit('update', {
        secretName: name,
        success: false,
        error: error.message,
      });
      safeLogger.error('Failed to update secret', {
        secretName: name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Delete secret
  delete(name) {
    try {
      const secret = this.findByName(name);
      if (!secret) {
        throw new Error(`Secret not found: ${name}`);
      }
      this.secrets.delete(secret.id);
      this.metrics.totalSecrets--;
      this.logAudit('delete', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
        success: true,
      });
      safeLogger.info('Secret deleted', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
      });
      return true;
    } catch (error) {
      this.metrics.failedOperations++;
      this.logAudit('delete', {
        secretName: name,
        success: false,
        error: error.message,
      });
      safeLogger.error('Failed to delete secret', {
        secretName: name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Rotate secret
  rotate(name, newValue, metadata = {}) {
    try {
      const secret = this.findByName(name);
      if (!secret) {
        throw new Error(`Secret not found: ${name}`);
      }
      const rotationResult = secret.rotate(newValue, metadata);
      secret.encrypt(this.masterKey);
      this.metrics.rotatedSecrets++;
      this.logAudit('rotate', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
        success: true,
      });
      safeLogger.info('Secret rotated', {
        secretId: secret.id,
        secretName: secret.name,
        type: secret.type,
      });
      return rotationResult;
    } catch (error) {
      this.metrics.failedOperations++;
      this.logAudit('rotate', {
        secretName: name,
        success: false,
        error: error.message,
      });
      safeLogger.error('Failed to rotate secret', {
        secretName: name,
        error: error.message,
      });
      throw error;
    }
  }
  // ✅ Find secret by name
  findByName(name) {
    return Array.from(this.secrets.values()).find(
      secret => secret.name === name,
    );
  }
  // ✅ Find secrets by type
  findByType(type) {
    return Array.from(this.secrets.values()).filter(
      secret => secret.type === type,
    );
  }
  // ✅ Get all secrets metadata
  getAllMetadata() {
    return Array.from(this.secrets.values()).map(secret =>
      secret.getMetadata(),
    );
  }
  // ✅ Get secrets that need rotation
  getSecretsNeedingRotation() {
    return Array.from(this.secrets.values()).filter(secret =>
      secret.needsRotation(),
    );
  }
  // ✅ Log audit event
  logAudit(action, data) {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      action,
      ...data,
    };
    this.auditLog.push(auditEntry);
    // ✅ Keep only last 1000 audit entries
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }
  // ✅ Get audit log
  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }
  // ✅ Get metrics
  getMetrics() {
    return {
      ...this.metrics,
      totalSecrets: this.secrets.size,
      secretsNeedingRotation: this.getSecretsNeedingRotation().length,
      auditLogSize: this.auditLog.length,
    };
  }
  // ✅ Clear all secrets
  clear() {
    this.secrets.clear();
    this.auditLog = [];
    Object.assign(this.metrics, {
      totalSecrets: 0,
      encryptedSecrets: 0,
      decryptedSecrets: 0,
      rotatedSecrets: 0,
      failedOperations: 0,
    });
    safeLogger.info('All secrets cleared');
  }
}
// ✅ Global secrets manager instance
const secretsManager = new SecretsManager();
// ✅ Export functions
export const storeSecret = (name, value, type, metadata) =>
  secretsManager.store(name, value, type, metadata);
export const retrieveSecret = (name, decrypt) =>
  secretsManager.retrieve(name, decrypt);
export const updateSecret = (name, newValue, metadata) =>
  secretsManager.update(name, newValue, metadata);
export const deleteSecret = name => secretsManager.delete(name);
export const rotateSecret = (name, newValue, metadata) =>
  secretsManager.rotate(name, newValue, metadata);
export const findSecretByName = name => secretsManager.findByName(name);
export const findSecretsByType = type => secretsManager.findByType(type);
export const getAllSecretsMetadata = () => secretsManager.getAllMetadata();
export const getSecretsNeedingRotation = () =>
  secretsManager.getSecretsNeedingRotation();
export const getAuditLog = limit => secretsManager.getAuditLog(limit);
export const getSecretsMetrics = () => secretsManager.getMetrics();
export const clearAllSecrets = () => secretsManager.clear();
// ✅ Export classes and constants
export { Secret, SecretsManager, secretsManager };
export { SECRET_TYPES, ENCRYPTION_ALGORITHMS, SECRET_CONFIG };
export default secretsManager;
