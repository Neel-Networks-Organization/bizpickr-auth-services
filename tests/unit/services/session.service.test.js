import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';
import jwt from 'jsonwebtoken';
import { sessionService } from '../../../src/services/session.service.js';

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../../src/models/index.model.js');
jest.mock('../../../src/cache/auth.cache.js');

import { Session } from '../../../src/models/index.model.js';
import { authCache } from '../../../src/cache/auth.cache.js';

describe('Session Service Unit Tests', () => {
  let mockSessionData;

  beforeEach(() => {
    jest.clearAllMocks();

    mockSessionData = {
      userId: 1,
      deviceInfo: 'Mozilla/5.0',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
      expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
    };
  });

  describe('createSession', () => {
    it('should successfully create a new session', async () => {
      // Arrange
      const mockSession = {
        id: 'session-123',
        userId: mockSessionData.userId,
        deviceInfo: mockSessionData.deviceInfo,
        ipAddress: mockSessionData.ipAddress,
        userAgent: mockSessionData.userAgent,
        expiresAt: mockSessionData.expiresAt,
        createdAt: new Date(),
      };

      Session.create.mockResolvedValue(mockSession);
      jwt.sign.mockReturnValue('access-token');
      jwt.sign.mockReturnValueOnce('refresh-token');

      // Act
      const result = await sessionService.createSession(mockSessionData);

      // Assert
      expect(Session.create).toHaveBeenCalledWith({
        userId: mockSessionData.userId,
        deviceInfo: mockSessionData.deviceInfo,
        ipAddress: mockSessionData.ipAddress,
        userAgent: mockSessionData.userAgent,
        expiresAt: mockSessionData.expiresAt,
        status: 'active',
      });
      expect(jwt.sign).toHaveBeenCalledTimes(2);
      expect(result).toHaveProperty('id', mockSession.id);
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
    });

    it('should handle session creation errors', async () => {
      // Arrange
      const error = new Error('Database error');
      Session.create.mockRejectedValue(error);

      // Act & Assert
      await expect(
        sessionService.createSession(mockSessionData)
      ).rejects.toThrow('Database error');
    });

    it('should create session with default expiration', async () => {
      // Arrange
      const sessionDataWithoutExpiry = { ...mockSessionData };
      delete sessionDataWithoutExpiry.expiresAt;

      const mockSession = {
        id: 'session-123',
        userId: mockSessionData.userId,
        expiresAt: expect.any(Date),
      };

      Session.create.mockResolvedValue(mockSession);
      jwt.sign.mockReturnValue('token');

      // Act
      await sessionService.createSession(sessionDataWithoutExpiry);

      // Assert
      expect(Session.create).toHaveBeenCalledWith(
        expect.objectContaining({
          expiresAt: expect.any(Date),
        })
      );
    });

    it('should create session with custom expiration', async () => {
      // Arrange
      const customExpiry = new Date(Date.now() + 7200000); // 2 hours
      const sessionDataWithCustomExpiry = {
        ...mockSessionData,
        expiresAt: customExpiry,
      };

      const mockSession = {
        id: 'session-123',
        userId: mockSessionData.userId,
        expiresAt: customExpiry,
      };

      Session.create.mockResolvedValue(mockSession);
      jwt.sign.mockReturnValue('token');

      // Act
      await sessionService.createSession(sessionDataWithCustomExpiry);

      // Assert
      expect(Session.create).toHaveBeenCalledWith(
        expect.objectContaining({
          expiresAt: customExpiry,
        })
      );
    });
  });

  describe('verifySession', () => {
    it('should verify valid session token', async () => {
      // Arrange
      const token = 'valid-token';
      const mockDecoded = { sessionId: 'session-123' };
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'active',
        expiresAt: new Date(Date.now() + 3600000),
        user: { id: 1, email: 'test@example.com' },
      };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(mockSession);

      // Act
      const result = await sessionService.verifySession(token);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith(token, expect.any(String));
      expect(Session.findByPk).toHaveBeenCalledWith('session-123', {
        include: expect.any(Array),
      });
      expect(result).toEqual(mockSession.user);
    });

    it('should reject expired session', async () => {
      // Arrange
      const token = 'expired-token';
      const mockDecoded = { sessionId: 'session-123' };
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'active',
        expiresAt: new Date(Date.now() - 3600000), // Expired 1 hour ago
      };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(mockSession);

      // Act & Assert
      await expect(sessionService.verifySession(token)).rejects.toThrow(
        'Session expired'
      );
    });

    it('should reject inactive session', async () => {
      // Arrange
      const token = 'inactive-token';
      const mockDecoded = { sessionId: 'session-123' };
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'inactive',
        expiresAt: new Date(Date.now() + 3600000),
      };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(mockSession);

      // Act & Assert
      await expect(sessionService.verifySession(token)).rejects.toThrow(
        'Session inactive'
      );
    });

    it('should reject invalid token', async () => {
      // Arrange
      const token = 'invalid-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act & Assert
      await expect(sessionService.verifySession(token)).rejects.toThrow(
        'Invalid token'
      );
    });

    it('should reject non-existent session', async () => {
      // Arrange
      const token = 'valid-token';
      const mockDecoded = { sessionId: 'session-123' };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(sessionService.verifySession(token)).rejects.toThrow(
        'Session not found'
      );
    });
  });

  describe('refreshSession', () => {
    it('should refresh valid session', async () => {
      // Arrange
      const refreshToken = 'valid-refresh-token';
      const mockDecoded = { sessionId: 'session-123' };
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'active',
        expiresAt: new Date(Date.now() + 3600000),
        user: { id: 1, email: 'test@example.com' },
      };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(mockSession);
      jwt.sign.mockReturnValue('new-access-token');

      // Act
      const result = await sessionService.refreshSession(refreshToken);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith(refreshToken, expect.any(String));
      expect(Session.findByPk).toHaveBeenCalledWith('session-123');
      expect(result).toHaveProperty('accessToken', 'new-access-token');
      expect(result).toHaveProperty('user');
    });

    it('should reject expired refresh token', async () => {
      // Arrange
      const refreshToken = 'expired-refresh-token';
      jwt.verify.mockImplementation(() => {
        throw new Error('Token expired');
      });

      // Act & Assert
      await expect(sessionService.refreshSession(refreshToken)).rejects.toThrow(
        'Token expired'
      );
    });

    it('should reject inactive session during refresh', async () => {
      // Arrange
      const refreshToken = 'valid-refresh-token';
      const mockDecoded = { sessionId: 'session-123' };
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'inactive',
        expiresAt: new Date(Date.now() + 3600000),
      };

      jwt.verify.mockReturnValue(mockDecoded);
      Session.findByPk.mockResolvedValue(mockSession);

      // Act & Assert
      await expect(sessionService.refreshSession(refreshToken)).rejects.toThrow(
        'Session inactive'
      );
    });
  });

  describe('invalidateSession', () => {
    it('should invalidate active session', async () => {
      // Arrange
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        update: jest.fn().mockResolvedValue(true),
      };

      Session.findByPk.mockResolvedValue(mockSession);
      authCache.blacklistToken.mockResolvedValue();

      // Act
      await sessionService.invalidateSession(sessionId);

      // Assert
      expect(Session.findByPk).toHaveBeenCalledWith(sessionId);
      expect(mockSession.update).toHaveBeenCalledWith({
        status: 'inactive',
        invalidatedAt: expect.any(Date),
      });
      expect(authCache.blacklistToken).toHaveBeenCalledWith(sessionId);
    });

    it('should handle non-existent session during invalidation', async () => {
      // Arrange
      const sessionId = 'non-existent-session';
      Session.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(sessionService.invalidateSession(sessionId)).rejects.toThrow(
        'Session not found'
      );
    });

    it('should handle invalidation errors gracefully', async () => {
      // Arrange
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        update: jest.fn().mockRejectedValue(new Error('Update failed')),
      };

      Session.findByPk.mockResolvedValue(mockSession);

      // Act & Assert
      await expect(sessionService.invalidateSession(sessionId)).rejects.toThrow(
        'Update failed'
      );
    });
  });

  describe('getUserSessions', () => {
    it('should get all active sessions for user', async () => {
      // Arrange
      const userId = 1;
      const mockSessions = [
        {
          id: 'session-1',
          deviceInfo: 'Mozilla/5.0',
          ipAddress: '192.168.1.1',
          createdAt: new Date(),
        },
        {
          id: 'session-2',
          deviceInfo: 'Mobile App',
          ipAddress: '192.168.1.2',
          createdAt: new Date(),
        },
      ];

      Session.findAll.mockResolvedValue(mockSessions);

      // Act
      const result = await sessionService.getUserSessions(userId);

      // Assert
      expect(Session.findAll).toHaveBeenCalledWith({
        where: { userId, status: 'active' },
        attributes: { exclude: ['refreshToken'] },
        order: [['createdAt', 'DESC']],
      });
      expect(result).toEqual(mockSessions);
    });

    it('should return empty array for user with no sessions', async () => {
      // Arrange
      const userId = 999;
      Session.findAll.mockResolvedValue([]);

      // Act
      const result = await sessionService.getUserSessions(userId);

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('should cleanup expired sessions', async () => {
      // Arrange
      const mockExpiredSessions = [
        { id: 'expired-1', destroy: jest.fn().mockResolvedValue(true) },
        { id: 'expired-2', destroy: jest.fn().mockResolvedValue(true) },
      ];

      Session.findAll.mockResolvedValue(mockExpiredSessions);

      // Act
      const result = await sessionService.cleanupExpiredSessions();

      // Assert
      expect(Session.findAll).toHaveBeenCalledWith({
        where: {
          expiresAt: { [expect.any(Object)]: new Date() },
          status: 'active',
        },
      });
      expect(mockExpiredSessions[0].destroy).toHaveBeenCalled();
      expect(mockExpiredSessions[1].destroy).toHaveBeenCalled();
      expect(result).toBe(2);
    });

    it('should handle cleanup errors gracefully', async () => {
      // Arrange
      const mockExpiredSessions = [
        {
          id: 'expired-1',
          destroy: jest.fn().mockRejectedValue(new Error('Destroy failed')),
        },
      ];

      Session.findAll.mockResolvedValue(mockExpiredSessions);

      // Act & Assert
      await expect(sessionService.cleanupExpiredSessions()).rejects.toThrow(
        'Destroy failed'
      );
    });
  });

  describe('updateSessionActivity', () => {
    it('should update session last activity', async () => {
      // Arrange
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        update: jest.fn().mockResolvedValue(true),
      };

      Session.findByPk.mockResolvedValue(mockSession);

      // Act
      await sessionService.updateSessionActivity(sessionId);

      // Assert
      expect(Session.findByPk).toHaveBeenCalledWith(sessionId);
      expect(mockSession.update).toHaveBeenCalledWith({
        lastActivityAt: expect.any(Date),
      });
    });

    it('should handle non-existent session during activity update', async () => {
      // Arrange
      const sessionId = 'non-existent-session';
      Session.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(
        sessionService.updateSessionActivity(sessionId)
      ).rejects.toThrow('Session not found');
    });
  });

  describe('getSessionStats', () => {
    it('should get session statistics', async () => {
      // Arrange
      const mockStats = {
        totalSessions: 100,
        activeSessions: 75,
        expiredSessions: 20,
        invalidatedSessions: 5,
      };

      Session.count = jest
        .fn()
        .mockResolvedValueOnce(mockStats.totalSessions)
        .mockResolvedValueOnce(mockStats.activeSessions)
        .mockResolvedValueOnce(mockStats.expiredSessions)
        .mockResolvedValueOnce(mockStats.invalidatedSessions);

      // Act
      const result = await sessionService.getSessionStats();

      // Assert
      expect(Session.count).toHaveBeenCalledTimes(4);
      expect(result).toEqual(mockStats);
    });

    it('should handle stats calculation errors', async () => {
      // Arrange
      Session.count.mockRejectedValue(new Error('Count failed'));

      // Act & Assert
      await expect(sessionService.getSessionStats()).rejects.toThrow(
        'Count failed'
      );
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle JWT signing errors', async () => {
      // Arrange
      jwt.sign.mockImplementation(() => {
        throw new Error('JWT signing failed');
      });

      // Act & Assert
      await expect(
        sessionService.createSession(mockSessionData)
      ).rejects.toThrow('JWT signing failed');
    });

    it('should handle database connection errors', async () => {
      // Arrange
      const error = new Error('Connection failed');
      Session.create.mockRejectedValue(error);

      // Act & Assert
      await expect(
        sessionService.createSession(mockSessionData)
      ).rejects.toThrow('Connection failed');
    });

    it('should handle cache errors gracefully', async () => {
      // Arrange
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        update: jest.fn().mockResolvedValue(true),
      };

      Session.findByPk.mockResolvedValue(mockSession);
      authCache.blacklistToken.mockRejectedValue(new Error('Cache error'));

      // Act
      await sessionService.invalidateSession(sessionId);

      // Assert
      expect(mockSession.update).toHaveBeenCalled();
      // Should continue even if cache fails
    });
  });

  describe('Performance Tests', () => {
    it('should handle multiple session creations efficiently', async () => {
      // Arrange
      const sessions = [];
      for (let i = 0; i < 10; i++) {
        sessions.push({
          ...mockSessionData,
          userId: i + 1,
        });
      }

      Session.create.mockResolvedValue({ id: 'session' });
      jwt.sign.mockReturnValue('token');

      // Act
      const startTime = Date.now();
      await Promise.all(
        sessions.map(session => sessionService.createSession(session))
      );
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / sessions.length;
      expect(averageTime).toBeLessThan(50); // Less than 50ms per session
    });

    it('should handle concurrent session verifications', async () => {
      // Arrange
      const tokens = Array.from({ length: 10 }, (_, i) => `token-${i}`);
      const mockSession = {
        id: 'session-123',
        userId: 1,
        status: 'active',
        expiresAt: new Date(Date.now() + 3600000),
        user: { id: 1, email: 'test@example.com' },
      };

      jwt.verify.mockReturnValue({ sessionId: 'session-123' });
      Session.findByPk.mockResolvedValue(mockSession);

      // Act
      const startTime = Date.now();
      await Promise.all(
        tokens.map(token => sessionService.verifySession(token))
      );
      const endTime = Date.now();

      // Assert
      const totalTime = endTime - startTime;
      expect(totalTime).toBeLessThan(100); // Less than 100ms total
    });
  });
});
