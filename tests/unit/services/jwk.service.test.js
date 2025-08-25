import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import { jwkService } from '../../../src/services/jwk.service.js';

describe('JWK Service Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateKeyPair', () => {
    it('should generate RSA key pair', async () => {
      // Arrange
      const keySize = 2048;

      // Act
      const result = await jwkService.generateKeyPair(keySize);

      // Assert
      expect(result).toHaveProperty('publicKey');
      expect(result).toHaveProperty('privateKey');
      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('alg');
      expect(result.alg).toBe('RS256');
    });

    it('should generate key pair with default size', async () => {
      // Act
      const result = await jwkService.generateKeyPair();

      // Assert
      expect(result).toHaveProperty('publicKey');
      expect(result).toHaveProperty('privateKey');
      expect(result).toHaveProperty('kid');
    });

    it('should handle key generation errors', async () => {
      // Arrange
      const invalidKeySize = -1;

      // Act & Assert
      await expect(
        jwkService.generateKeyPair(invalidKeySize)
      ).rejects.toThrow();
    });
  });

  describe('getPublicKey', () => {
    it('should return public key in JWK format', async () => {
      // Arrange
      const mockKeyPair = {
        publicKey: 'mock-public-key',
        privateKey: 'mock-private-key',
        kid: 'key-123',
        alg: 'RS256',
      };

      jwkService.generateKeyPair = jest.fn().mockResolvedValue(mockKeyPair);

      // Act
      const result = await jwkService.getPublicKey();

      // Assert
      expect(result).toHaveProperty('kty');
      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('alg');
      expect(result).toHaveProperty('n');
      expect(result).toHaveProperty('e');
    });

    it('should handle missing public key', async () => {
      // Arrange
      jwkService.generateKeyPair = jest.fn().mockResolvedValue(null);

      // Act & Assert
      await expect(jwkService.getPublicKey()).rejects.toThrow();
    });
  });

  describe('getJWKSet', () => {
    it('should return JWK set with all public keys', async () => {
      // Arrange
      const mockKeys = [
        { kid: 'key-1', alg: 'RS256' },
        { kid: 'key-2', alg: 'RS256' },
      ];

      jwkService.getAllKeys = jest.fn().mockResolvedValue(mockKeys);

      // Act
      const result = await jwkService.getJWKSet();

      // Assert
      expect(result).toHaveProperty('keys');
      expect(result.keys).toBeInstanceOf(Array);
      expect(result.keys.length).toBe(2);
    });

    it('should return empty JWK set when no keys exist', async () => {
      // Arrange
      jwkService.getAllKeys = jest.fn().mockResolvedValue([]);

      // Act
      const result = await jwkService.getJWKSet();

      // Assert
      expect(result).toHaveProperty('keys');
      expect(result.keys).toBeInstanceOf(Array);
      expect(result.keys.length).toBe(0);
    });
  });

  describe('getKeyById', () => {
    it('should return key by ID', async () => {
      // Arrange
      const keyId = 'key-123';
      const mockKey = { kid: keyId, alg: 'RS256' };

      jwkService.findKeyById = jest.fn().mockResolvedValue(mockKey);

      // Act
      const result = await jwkService.getKeyById(keyId);

      // Assert
      expect(result).toEqual(mockKey);
      expect(jwkService.findKeyById).toHaveBeenCalledWith(keyId);
    });

    it('should return null for non-existent key', async () => {
      // Arrange
      const keyId = 'non-existent-key';
      jwkService.findKeyById = jest.fn().mockResolvedValue(null);

      // Act
      const result = await jwkService.getKeyById(keyId);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('rotateKeys', () => {
    it('should rotate keys successfully', async () => {
      // Arrange
      const mockNewKey = {
        publicKey: 'new-public-key',
        privateKey: 'new-private-key',
        kid: 'new-key-123',
        alg: 'RS256',
      };

      jwkService.generateKeyPair = jest.fn().mockResolvedValue(mockNewKey);
      jwkService.storeKey = jest.fn().mockResolvedValue(true);
      jwkService.markOldKeysAsExpired = jest.fn().mockResolvedValue(true);

      // Act
      const result = await jwkService.rotateKeys();

      // Assert
      expect(result).toBe(true);
      expect(jwkService.generateKeyPair).toHaveBeenCalled();
      expect(jwkService.storeKey).toHaveBeenCalledWith(mockNewKey);
      expect(jwkService.markOldKeysAsExpired).toHaveBeenCalled();
    });

    it('should handle key rotation errors', async () => {
      // Arrange
      jwkService.generateKeyPair = jest
        .fn()
        .mockRejectedValue(new Error('Generation failed'));

      // Act & Assert
      await expect(jwkService.rotateKeys()).rejects.toThrow(
        'Generation failed'
      );
    });
  });

  describe('validateKey', () => {
    it('should validate valid key', async () => {
      // Arrange
      const mockKey = {
        kid: 'key-123',
        alg: 'RS256',
        n: 'valid-modulus',
        e: 'valid-exponent',
      };

      // Act
      const result = await jwkService.validateKey(mockKey);

      // Assert
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid key without required fields', async () => {
      // Arrange
      const invalidKey = {
        kid: 'key-123',
        // Missing required fields
      };

      // Act
      const result = await jwkService.validateKey(invalidKey);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject key with invalid algorithm', async () => {
      // Arrange
      const invalidKey = {
        kid: 'key-123',
        alg: 'INVALID_ALG',
        n: 'valid-modulus',
        e: 'valid-exponent',
      };

      // Act
      const result = await jwkService.validateKey(invalidKey);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Invalid algorithm');
    });
  });

  describe('exportKey', () => {
    it('should export key in PEM format', async () => {
      // Arrange
      const mockKey = {
        publicKey: 'mock-public-key',
        privateKey: 'mock-private-key',
        kid: 'key-123',
        alg: 'RS256',
      };

      // Act
      const result = await jwkService.exportKey(mockKey, 'pem');

      // Assert
      expect(result).toHaveProperty('publicKey');
      expect(result).toHaveProperty('privateKey');
      expect(result.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----/);
      expect(result.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    });

    it('should export key in JWK format', async () => {
      // Arrange
      const mockKey = {
        publicKey: 'mock-public-key',
        privateKey: 'mock-private-key',
        kid: 'key-123',
        alg: 'RS256',
      };

      // Act
      const result = await jwkService.exportKey(mockKey, 'jwk');

      // Assert
      expect(result).toHaveProperty('kty');
      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('alg');
    });

    it('should throw error for unsupported format', async () => {
      // Arrange
      const mockKey = {
        publicKey: 'mock-public-key',
        privateKey: 'mock-private-key',
        kid: 'key-123',
        alg: 'RS256',
      };

      // Act & Assert
      await expect(
        jwkService.exportKey(mockKey, 'unsupported')
      ).rejects.toThrow('Unsupported export format');
    });
  });

  describe('importKey', () => {
    it('should import key from PEM format', async () => {
      // Arrange
      const pemKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

      // Act
      const result = await jwkService.importKey(pemKey, 'pem');

      // Assert
      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('alg');
      expect(result).toHaveProperty('n');
      expect(result).toHaveProperty('e');
    });

    it('should import key from JWK format', async () => {
      // Arrange
      const jwkKey = {
        kty: 'RSA',
        kid: 'imported-key-123',
        alg: 'RS256',
        n: 'modulus',
        e: 'exponent',
      };

      // Act
      const result = await jwkService.importKey(jwkKey, 'jwk');

      // Assert
      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('alg');
    });

    it('should throw error for invalid key format', async () => {
      // Arrange
      const invalidKey = 'invalid-key-format';

      // Act & Assert
      await expect(jwkService.importKey(invalidKey, 'pem')).rejects.toThrow();
    });
  });

  describe('getKeyUsage', () => {
    it('should return key usage information', async () => {
      // Arrange
      const keyId = 'key-123';

      // Act
      const result = await jwkService.getKeyUsage(keyId);

      // Assert
      expect(result).toHaveProperty('sign');
      expect(result).toHaveProperty('verify');
      expect(result).toHaveProperty('encrypt');
      expect(result).toHaveProperty('decrypt');
    });

    it('should return null for non-existent key', async () => {
      // Arrange
      const keyId = 'non-existent-key';
      jwkService.findKeyById = jest.fn().mockResolvedValue(null);

      // Act
      const result = await jwkService.getKeyUsage(keyId);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('revokeKey', () => {
    it('should revoke key successfully', async () => {
      // Arrange
      const keyId = 'key-123';
      jwkService.findKeyById = jest.fn().mockResolvedValue({
        id: keyId,
        update: jest.fn().mockResolvedValue(true),
      });

      // Act
      const result = await jwkService.revokeKey(keyId);

      // Assert
      expect(result).toBe(true);
    });

    it('should handle non-existent key during revocation', async () => {
      // Arrange
      const keyId = 'non-existent-key';
      jwkService.findKeyById = jest.fn().mockResolvedValue(null);

      // Act & Assert
      await expect(jwkService.revokeKey(keyId)).rejects.toThrow(
        'Key not found'
      );
    });
  });

  describe('getKeyStats', () => {
    it('should return key statistics', async () => {
      // Arrange
      const mockStats = {
        totalKeys: 10,
        activeKeys: 8,
        expiredKeys: 1,
        revokedKeys: 1,
      };

      jwkService.countKeys = jest
        .fn()
        .mockResolvedValueOnce(mockStats.totalKeys)
        .mockResolvedValueOnce(mockStats.activeKeys)
        .mockResolvedValueOnce(mockStats.expiredKeys)
        .mockResolvedValueOnce(mockStats.revokedKeys);

      // Act
      const result = await jwkService.getKeyStats();

      // Assert
      expect(result).toEqual(mockStats);
    });

    it('should handle stats calculation errors', async () => {
      // Arrange
      jwkService.countKeys = jest
        .fn()
        .mockRejectedValue(new Error('Count failed'));

      // Act & Assert
      await expect(jwkService.getKeyStats()).rejects.toThrow('Count failed');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null key input gracefully', async () => {
      // Act & Assert
      await expect(jwkService.validateKey(null)).rejects.toThrow();
    });

    it('should handle undefined key input gracefully', async () => {
      // Act & Assert
      await expect(jwkService.validateKey(undefined)).rejects.toThrow();
    });

    it('should handle empty key object gracefully', async () => {
      // Arrange
      const emptyKey = {};

      // Act
      const result = await jwkService.validateKey(emptyKey);

      // Assert
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('Performance Tests', () => {
    it('should generate keys efficiently', async () => {
      // Arrange
      const iterations = 5;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        await jwkService.generateKeyPair(2048);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1000); // Less than 1 second per key
    });

    it('should validate keys efficiently', async () => {
      // Arrange
      const mockKey = {
        kid: 'key-123',
        alg: 'RS256',
        n: 'valid-modulus',
        e: 'valid-exponent',
      };

      const iterations = 1000;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        await jwkService.validateKey(mockKey);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per validation
    });
  });
});
