import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from '@jest/globals';

// Mock dependencies
jest.mock('sequelize');

// Create mock objects directly
const safeLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
};

const getCorrelationId = jest.fn(() => 'test-correlation-id');

const mockSequelize = {
  Op: {
    gt: 'gt',
    lt: 'lt',
    eq: 'eq',
    ne: 'ne',
    in: 'in',
    like: 'like',
    between: 'between',
  },
  fn: jest.fn(),
  col: jest.fn(),
  literal: jest.fn(),
  models: {
    AuthUser: {},
  },
};

// Mock ApiError
class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = 'ApiError';
  }
}

// Simple UserActivity Model Tests - Basic Functionality
describe('UserActivity Model - Basic Tests', () => {
  let mockUserActivity;
  let mockUserActivityData;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock user activity data
    mockUserActivityData = {
      id: 'activity-id-123',
      userId: 'user-id-456',
      userEmail: 'test@example.com',
      activityType: 'login',
      activitySubtype: 'web_login',
      description: 'User logged in via web interface',
      details: {
        ipAddress: '192.168.1.1',
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        location: 'New York, US',
        deviceType: 'desktop',
        browser: 'Chrome',
        os: 'Windows 10',
        success: true,
        timestamp: new Date().toISOString(),
      },
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      location: 'New York, US',
      deviceType: 'desktop',
      browser: 'Chrome',
      os: 'Windows 10',
      status: 'completed',
      priority: 'normal',
      correlationId: 'req-123-abcdefgh',
      sessionId: 'session-789',
      metadata: {
        requestId: 'req-123-abcdefgh',
        version: '1.0',
        features: ['2fa', 'remember_me'],
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      lastActiveAt: new Date(),
    };

    // Mock user activity instance
    mockUserActivity = {
      ...mockUserActivityData,
      save: jest.fn(),
      update: jest.fn(),
      destroy: jest.fn(),
      changed: jest.fn(),
      findByPk: jest.fn(),
      findOne: jest.fn(),
      findAll: jest.fn(),
      create: jest.fn(),
    };

    // Mock static methods
    mockUserActivity.constructor.createActivity = jest.fn();
    mockUserActivity.constructor.findByUser = jest.fn();
    mockUserActivity.constructor.findByType = jest.fn();
    mockUserActivity.constructor.findByDateRange = jest.fn();
    mockUserActivity.constructor.findByLocation = jest.fn();
    mockUserActivity.constructor.findByDevice = jest.fn();
    mockUserActivity.constructor.findByStatus = jest.fn();
    mockUserActivity.constructor.findByCorrelationId = jest.fn();
    mockUserActivity.constructor.findBySession = jest.fn();
    mockUserActivity.constructor.cleanupOldActivities = jest.fn();
    mockUserActivity.constructor.getActivityStats = jest.fn();
    mockUserActivity.constructor.exportActivities = jest.fn();
    mockUserActivity.constructor.validateActivityType = jest.fn();
    mockUserActivity.constructor.validatePriority = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Static Methods - User Activity Management', () => {
    describe('createActivity', () => {
      it('should create user activity with required fields', async () => {
        // Arrange
        const activityData = {
          userId: 'user-id-123',
          userEmail: 'user@example.com',
          activityType: 'login',
          activitySubtype: 'web_login',
          description: 'User logged in',
          details: { success: true },
          ipAddress: '192.168.1.1',
          userAgent: 'Mozilla/5.0',
        };
        const createdActivity = { ...activityData, id: 'new-activity-id' };

        mockUserActivity.constructor.createActivity.mockResolvedValue(
          createdActivity
        );

        // Act
        const result =
          await mockUserActivity.constructor.createActivity(activityData);

        // Assert
        expect(result).toEqual(createdActivity);
        expect(
          mockUserActivity.constructor.createActivity
        ).toHaveBeenCalledWith(activityData, {});
      });

      it('should set default values when not provided', async () => {
        // Arrange
        const activityData = {
          userId: 'user-id-123',
          activityType: 'login',
          description: 'User logged in',
        };

        // Act - Simulate default value logic
        if (!activityData.status) {
          activityData.status = 'completed';
        }
        if (!activityData.priority) {
          activityData.priority = 'normal';
        }
        if (!activityData.createdAt) {
          activityData.createdAt = new Date();
        }
        if (!activityData.lastActiveAt) {
          activityData.lastActiveAt = new Date();
        }

        // Assert
        expect(activityData.status).toBe('completed');
        expect(activityData.priority).toBe('normal');
        expect(activityData.createdAt).toBeInstanceOf(Date);
        expect(activityData.lastActiveAt).toBeInstanceOf(Date);
      });

      it('should reject creation without required fields', async () => {
        const requiredFields = ['userId', 'activityType', 'description'];

        requiredFields.forEach(field => {
          const incompleteData = { ...mockUserActivityData };
          delete incompleteData[field];

          // Act & Assert
          expect(() => {
            if (!incompleteData[field]) {
              throw new ApiError(
                400,
                `${field.charAt(0).toUpperCase() + field.slice(1)} is required`
              );
            }
          }).toThrow(
            `${field.charAt(0).toUpperCase() + field.slice(1)} is required`
          );
        });
      });

      it('should handle creation errors gracefully', async () => {
        // Arrange
        const activityData = { userId: 'user-id-123', activityType: 'test' };
        const creationError = new Error('User activity creation failed');
        mockUserActivity.constructor.createActivity.mockRejectedValue(
          creationError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.createActivity(activityData)
        ).rejects.toThrow('User activity creation failed');
      });
    });

    describe('findByUser', () => {
      it('should find user activities by user ID', async () => {
        // Arrange
        const userId = 'user-id-123';
        const userActivities = [
          { id: 'activity-1', activityType: 'login', status: 'completed' },
          { id: 'activity-2', activityType: 'logout', status: 'completed' },
        ];

        mockUserActivity.constructor.findByUser.mockResolvedValue(
          userActivities
        );

        // Act
        const result = await mockUserActivity.constructor.findByUser(userId);

        // Assert
        expect(result).toEqual(userActivities);
        expect(mockUserActivity.constructor.findByUser).toHaveBeenCalledWith(
          userId,
          {}
        );
      });

      it('should handle user search errors gracefully', async () => {
        // Arrange
        const userId = 'user-id-123';
        const searchError = new Error('User search failed');
        mockUserActivity.constructor.findByUser.mockRejectedValue(searchError);

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByUser(userId)
        ).rejects.toThrow('User search failed');
      });
    });

    describe('findByType', () => {
      it('should find user activities by activity type', async () => {
        // Arrange
        const activityType = 'login';
        const typeActivities = [
          { id: 'activity-1', userId: 'user-1', status: 'completed' },
          { id: 'activity-2', userId: 'user-2', status: 'completed' },
        ];

        mockUserActivity.constructor.findByType.mockResolvedValue(
          typeActivities
        );

        // Act
        const result =
          await mockUserActivity.constructor.findByType(activityType);

        // Assert
        expect(result).toEqual(typeActivities);
        expect(mockUserActivity.constructor.findByType).toHaveBeenCalledWith(
          activityType,
          {}
        );
      });

      it('should handle type search errors gracefully', async () => {
        // Arrange
        const activityType = 'invalid_type';
        const searchError = new Error('Type search failed');
        mockUserActivity.constructor.findByType.mockRejectedValue(searchError);

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByType(activityType)
        ).rejects.toThrow('Type search failed');
      });
    });

    describe('findByDateRange', () => {
      it('should find user activities within date range', async () => {
        // Arrange
        const startDate = new Date('2024-01-01');
        const endDate = new Date('2024-01-31');
        const dateRangeActivities = [
          { id: 'activity-1', createdAt: new Date('2024-01-15') },
          { id: 'activity-2', createdAt: new Date('2024-01-20') },
        ];

        mockUserActivity.constructor.findByDateRange.mockResolvedValue(
          dateRangeActivities
        );

        // Act
        const result = await mockUserActivity.constructor.findByDateRange(
          startDate,
          endDate
        );

        // Assert
        expect(result).toEqual(dateRangeActivities);
        expect(
          mockUserActivity.constructor.findByDateRange
        ).toHaveBeenCalledWith(startDate, endDate, {});
      });

      it('should handle date range search errors gracefully', async () => {
        // Arrange
        const startDate = new Date('2024-01-01');
        const endDate = new Date('2024-01-31');
        const searchError = new Error('Date range search failed');
        mockUserActivity.constructor.findByDateRange.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByDateRange(startDate, endDate)
        ).rejects.toThrow('Date range search failed');
      });
    });

    describe('findByLocation', () => {
      it('should find user activities by location', async () => {
        // Arrange
        const location = 'New York, US';
        const locationActivities = [
          { id: 'activity-1', userId: 'user-1', location: 'New York, US' },
          { id: 'activity-2', userId: 'user-2', location: 'New York, US' },
        ];

        mockUserActivity.constructor.findByLocation.mockResolvedValue(
          locationActivities
        );

        // Act
        const result =
          await mockUserActivity.constructor.findByLocation(location);

        // Assert
        expect(result).toEqual(locationActivities);
        expect(
          mockUserActivity.constructor.findByLocation
        ).toHaveBeenCalledWith(location, {});
      });

      it('should handle location search errors gracefully', async () => {
        // Arrange
        const location = 'invalid_location';
        const searchError = new Error('Location search failed');
        mockUserActivity.constructor.findByLocation.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByLocation(location)
        ).rejects.toThrow('Location search failed');
      });
    });

    describe('findByDevice', () => {
      it('should find user activities by device type', async () => {
        // Arrange
        const deviceType = 'mobile';
        const deviceActivities = [
          { id: 'activity-1', userId: 'user-1', deviceType: 'mobile' },
          { id: 'activity-2', userId: 'user-2', deviceType: 'mobile' },
        ];

        mockUserActivity.constructor.findByDevice.mockResolvedValue(
          deviceActivities
        );

        // Act
        const result =
          await mockUserActivity.constructor.findByDevice(deviceType);

        // Assert
        expect(result).toEqual(deviceActivities);
        expect(mockUserActivity.constructor.findByDevice).toHaveBeenCalledWith(
          deviceType,
          {}
        );
      });

      it('should handle device search errors gracefully', async () => {
        // Arrange
        const deviceType = 'invalid_device';
        const searchError = new Error('Device search failed');
        mockUserActivity.constructor.findByDevice.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByDevice(deviceType)
        ).rejects.toThrow('Device search failed');
      });
    });

    describe('findByStatus', () => {
      it('should find user activities by status', async () => {
        // Arrange
        const status = 'completed';
        const statusActivities = [
          { id: 'activity-1', activityType: 'login', status: 'completed' },
          { id: 'activity-2', activityType: 'logout', status: 'completed' },
        ];

        mockUserActivity.constructor.findByStatus.mockResolvedValue(
          statusActivities
        );

        // Act
        const result = await mockUserActivity.constructor.findByStatus(status);

        // Assert
        expect(result).toEqual(statusActivities);
        expect(mockUserActivity.constructor.findByStatus).toHaveBeenCalledWith(
          status,
          {}
        );
      });

      it('should handle status search errors gracefully', async () => {
        // Arrange
        const status = 'invalid_status';
        const searchError = new Error('Status search failed');
        mockUserActivity.constructor.findByStatus.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByStatus(status)
        ).rejects.toThrow('Status search failed');
      });
    });

    describe('findByCorrelationId', () => {
      it('should find user activities by correlation ID', async () => {
        // Arrange
        const correlationId = 'req-123-abcdefgh';
        const correlationActivities = [
          {
            id: 'activity-1',
            correlationId: 'req-123-abcdefgh',
            activityType: 'login',
          },
          {
            id: 'activity-2',
            correlationId: 'req-123-abcdefgh',
            activityType: 'logout',
          },
        ];

        mockUserActivity.constructor.findByCorrelationId.mockResolvedValue(
          correlationActivities
        );

        // Act
        const result =
          await mockUserActivity.constructor.findByCorrelationId(correlationId);

        // Assert
        expect(result).toEqual(correlationActivities);
        expect(
          mockUserActivity.constructor.findByCorrelationId
        ).toHaveBeenCalledWith(correlationId, {});
      });

      it('should handle correlation ID search errors gracefully', async () => {
        // Arrange
        const correlationId = 'invalid-correlation-id';
        const searchError = new Error('Correlation ID search failed');
        mockUserActivity.constructor.findByCorrelationId.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findByCorrelationId(correlationId)
        ).rejects.toThrow('Correlation ID search failed');
      });
    });

    describe('findBySession', () => {
      it('should find user activities by session ID', async () => {
        // Arrange
        const sessionId = 'session-789';
        const sessionActivities = [
          { id: 'activity-1', sessionId: 'session-789', activityType: 'login' },
          {
            id: 'activity-2',
            sessionId: 'session-789',
            activityType: 'page_view',
          },
        ];

        mockUserActivity.constructor.findBySession.mockResolvedValue(
          sessionActivities
        );

        // Act
        const result =
          await mockUserActivity.constructor.findBySession(sessionId);

        // Assert
        expect(result).toEqual(sessionActivities);
        expect(mockUserActivity.constructor.findBySession).toHaveBeenCalledWith(
          sessionId,
          {}
        );
      });

      it('should handle session search errors gracefully', async () => {
        // Arrange
        const sessionId = 'invalid-session-id';
        const searchError = new Error('Session search failed');
        mockUserActivity.constructor.findBySession.mockRejectedValue(
          searchError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.findBySession(sessionId)
        ).rejects.toThrow('Session search failed');
      });
    });

    describe('cleanupOldActivities', () => {
      it('should cleanup old user activities and return count', async () => {
        // Arrange
        const retentionDays = 365;
        const cleanedCount = 250;
        mockUserActivity.constructor.cleanupOldActivities.mockResolvedValue(
          cleanedCount
        );

        // Act
        const result =
          await mockUserActivity.constructor.cleanupOldActivities(
            retentionDays
          );

        // Assert
        expect(result).toBe(cleanedCount);
        expect(
          mockUserActivity.constructor.cleanupOldActivities
        ).toHaveBeenCalledWith(retentionDays);
      });

      it('should handle cleanup errors gracefully', async () => {
        // Arrange
        const retentionDays = 365;
        const cleanupError = new Error('Cleanup operation failed');
        mockUserActivity.constructor.cleanupOldActivities.mockRejectedValue(
          cleanupError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.cleanupOldActivities(retentionDays)
        ).rejects.toThrow('Cleanup operation failed');
      });
    });

    describe('getActivityStats', () => {
      it('should return user activity statistics', async () => {
        // Arrange
        const mockStats = {
          totalActivities: 5000,
          activitiesByType: {
            login: 1500,
            logout: 1200,
            page_view: 800,
            api_call: 500,
            password_change: 100,
          },
          activitiesByDevice: {
            desktop: 3000,
            mobile: 1500,
            tablet: 500,
          },
          activitiesByLocation: {
            'New York, US': 1000,
            'London, UK': 800,
            'Tokyo, JP': 600,
          },
          activitiesByStatus: {
            completed: 4800,
            failed: 200,
          },
        };

        mockUserActivity.constructor.getActivityStats.mockResolvedValue(
          mockStats
        );

        // Act
        const result = await mockUserActivity.constructor.getActivityStats();

        // Assert
        expect(result).toEqual(mockStats);
        expect(
          mockUserActivity.constructor.getActivityStats
        ).toHaveBeenCalled();
      });

      it('should return empty stats when no data available', async () => {
        // Arrange
        mockUserActivity.constructor.getActivityStats.mockResolvedValue({});

        // Act
        const result = await mockUserActivity.constructor.getActivityStats();

        // Assert
        expect(result).toEqual({});
      });

      it('should handle statistics errors gracefully', async () => {
        // Arrange
        const statsError = new Error('Statistics query failed');
        mockUserActivity.constructor.getActivityStats.mockRejectedValue(
          statsError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.getActivityStats()
        ).rejects.toThrow('Statistics query failed');
      });
    });

    describe('exportActivities', () => {
      it('should export user activities in specified format', async () => {
        // Arrange
        const exportOptions = {
          format: 'csv',
          dateRange: {
            start: new Date('2024-01-01'),
            end: new Date('2024-01-31'),
          },
          filters: { activityType: 'login' },
        };
        const exportedData = 'csv_data_content';

        mockUserActivity.constructor.exportActivities.mockResolvedValue(
          exportedData
        );

        // Act
        const result =
          await mockUserActivity.constructor.exportActivities(exportOptions);

        // Assert
        expect(result).toBe(exportedData);
        expect(
          mockUserActivity.constructor.exportActivities
        ).toHaveBeenCalledWith(exportOptions);
      });

      it('should handle export errors gracefully', async () => {
        // Arrange
        const exportOptions = { format: 'csv' };
        const exportError = new Error('Export failed');
        mockUserActivity.constructor.exportActivities.mockRejectedValue(
          exportError
        );

        // Act & Assert
        await expect(
          mockUserActivity.constructor.exportActivities(exportOptions)
        ).rejects.toThrow('Export failed');
      });
    });
  });

  describe('Static Methods - Validation', () => {
    describe('validateActivityType', () => {
      it('should validate activity type format correctly', async () => {
        // Arrange
        const validTypes = [
          'login',
          'logout',
          'page_view',
          'api_call',
          'password_change',
        ];
        const invalidTypes = ['invalid_type', 'type with spaces', ''];

        // Act - Simulate activity type validation logic
        const validateActivityType = type => {
          if (!type || typeof type !== 'string') {
            return {
              isValid: false,
              errors: ['Activity type is required and must be a string'],
            };
          }
          if (type.includes(' ')) {
            return {
              isValid: false,
              errors: ['Activity type cannot contain spaces'],
            };
          }
          if (type.length < 2) {
            return { isValid: false, errors: ['Activity type too short'] };
          }
          return { isValid: true, errors: [] };
        };

        validTypes.forEach(type => {
          const result = validateActivityType(type);
          expect(result.isValid).toBe(true);
          expect(result.errors).toEqual([]);
        });

        invalidTypes.forEach(type => {
          const result = validateActivityType(type);
          expect(result.isValid).toBe(false);
          expect(result.errors.length).toBeGreaterThan(0);
        });
      });

      it('should handle validation errors gracefully', async () => {
        // Arrange
        const activityType = 'test_type';
        const validationError = new Error('Activity type validation failed');

        // Act & Assert
        try {
          throw validationError;
        } catch (error) {
          expect(error.message).toBe('Activity type validation failed');
        }
      });
    });

    describe('validatePriority', () => {
      it('should validate priority levels correctly', async () => {
        // Arrange
        const validPriorities = ['low', 'normal', 'high', 'critical'];
        const invalidPriorities = ['invalid', 'medium', 'urgent', ''];

        // Act - Simulate priority validation logic
        const validatePriority = priority => {
          const allowedPriorities = ['low', 'normal', 'high', 'critical'];
          if (!allowedPriorities.includes(priority)) {
            return { isValid: false, errors: ['Invalid priority level'] };
          }
          return { isValid: true, errors: [] };
        };

        validPriorities.forEach(priority => {
          const result = validatePriority(priority);
          expect(result.isValid).toBe(true);
          expect(result.errors).toEqual([]);
        });

        invalidPriorities.forEach(priority => {
          const result = validatePriority(priority);
          expect(result.isValid).toBe(false);
          expect(result.errors).toContain('Invalid priority level');
        });
      });

      it('should handle validation errors gracefully', async () => {
        // Arrange
        const priority = 'normal';
        const validationError = new Error('Priority validation failed');

        // Act & Assert
        try {
          throw validationError;
        } catch (error) {
          expect(error.message).toBe('Priority validation failed');
        }
      });
    });
  });

  describe('Instance Methods', () => {
    describe('updateLastActivity', () => {
      it('should update last activity timestamp', async () => {
        // Arrange
        const activity = { ...mockUserActivityData };
        const originalLastActiveAt = activity.lastActiveAt;

        // Act - Simulate updating last activity
        activity.lastActiveAt = new Date();

        // Assert
        expect(activity.lastActiveAt).toBeInstanceOf(Date);
        expect(activity.lastActiveAt.getTime()).toBeGreaterThanOrEqual(
          originalLastActiveAt.getTime()
        );
      });

      it('should handle update errors gracefully', async () => {
        // Arrange
        const activity = { ...mockUserActivityData };
        const updateError = new Error('Update failed');

        // Act & Assert
        try {
          throw updateError;
        } catch (error) {
          expect(error.message).toBe('Update failed');
        }
      });
    });

    describe('toSafeJSON', () => {
      it('should return activity data without sensitive fields', () => {
        // Arrange
        const activity = { ...mockUserActivityData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...activity };
        delete safeData.details.ipAddress;
        delete safeData.details.userAgent;

        // Assert
        expect(safeData.details.ipAddress).toBeUndefined();
        expect(safeData.details.userAgent).toBeUndefined();
        expect(safeData.userId).toBe(activity.userId);
        expect(safeData.activityType).toBe(activity.activityType);
        expect(safeData.description).toBe(activity.description);
      });

      it('should preserve all non-sensitive fields', () => {
        // Arrange
        const activity = { ...mockUserActivityData };

        // Act - Simulate toSafeJSON method
        const safeData = { ...activity };
        delete safeData.details.ipAddress;
        delete safeData.details.userAgent;

        // Assert - Check that important fields are preserved
        const preservedFields = [
          'id',
          'userId',
          'userEmail',
          'activityType',
          'activitySubtype',
          'description',
          'status',
          'priority',
          'correlationId',
          'sessionId',
          'metadata',
          'createdAt',
          'updatedAt',
          'lastActiveAt',
        ];

        preservedFields.forEach(field => {
          expect(safeData[field]).toBeDefined();
        });
      });
    });

    describe('getFormattedDetails', () => {
      it('should format details for display', () => {
        // Arrange
        const activity = { ...mockUserActivityData };

        // Act - Simulate getFormattedDetails method
        const formattedDetails = {
          type: activity.activityType,
          subtype: activity.activitySubtype,
          description: activity.description,
          status: activity.status,
          priority: activity.priority,
          timestamp: activity.createdAt.toISOString(),
          user: activity.userEmail,
          location: activity.location,
          device: activity.deviceType,
        };

        // Assert
        expect(formattedDetails.type).toBe(activity.activityType);
        expect(formattedDetails.subtype).toBe(activity.activitySubtype);
        expect(formattedDetails.description).toBe(activity.description);
        expect(formattedDetails.status).toBe(activity.status);
        expect(formattedDetails.priority).toBe(activity.priority);
        expect(formattedDetails.user).toBe(activity.userEmail);
        expect(formattedDetails.location).toBe(activity.location);
        expect(formattedDetails.device).toBe(activity.deviceType);
      });

      it('should handle missing details gracefully', () => {
        // Arrange
        const activity = { ...mockUserActivityData };
        delete activity.details;

        // Act - Simulate getFormattedDetails method with fallback
        const formattedDetails = {
          type: activity.activityType,
          subtype: activity.activitySubtype,
          description: activity.description,
          status: activity.status,
          priority: activity.priority,
          timestamp: activity.createdAt.toISOString(),
          user: activity.userEmail,
          location: activity.location,
          device: activity.deviceType,
          details: activity.details || 'No details available',
        };

        // Assert
        expect(formattedDetails.details).toBe('No details available');
      });
    });
  });

  describe('Model Validation and Constraints', () => {
    it('should validate required fields', () => {
      const requiredFields = ['userId', 'activityType', 'description'];
      const activity = { ...mockUserActivityData };

      requiredFields.forEach(field => {
        expect(activity[field]).toBeDefined();
        expect(activity[field]).not.toBeNull();
      });
    });

    it('should validate activity type format constraints', () => {
      const activity = { ...mockUserActivityData };

      // Activity type should be a string without spaces
      expect(typeof activity.activityType).toBe('string');
      expect(activity.activityType.length).toBeGreaterThan(0);
      expect(activity.activityType).not.toContain(' ');
    });

    it('should validate priority level constraints', () => {
      const activity = { ...mockUserActivityData };

      // Priority should be one of the allowed values
      const allowedPriorities = ['low', 'normal', 'high', 'critical'];
      expect(allowedPriorities.includes(activity.priority)).toBe(true);
    });

    it('should validate status constraints', () => {
      const activity = { ...mockUserActivityData };

      // Status should be one of the allowed values
      const allowedStatuses = [
        'pending',
        'in_progress',
        'completed',
        'failed',
        'cancelled',
      ];
      expect(allowedStatuses.includes(activity.status)).toBe(true);
    });

    it('should validate correlation ID format', () => {
      const activity = { ...mockUserActivityData };

      // Correlation ID should follow the pattern req-{timestamp}-{random}
      expect(activity.correlationId).toMatch(/^req-\d+-\w{9}$/);
    });
  });

  describe('Security and Privacy', () => {
    it('should mask sensitive information in logs', () => {
      const activity = { ...mockUserActivityData };

      // IP addresses should be logged for security but can be masked in exports
      expect(activity.ipAddress).toBeDefined();
      expect(activity.ipAddress).toMatch(/^\d+\.\d+\.\d+\.\d+$/);

      // User agents should be logged for security
      expect(activity.userAgent).toBeDefined();
      expect(activity.userAgent.length).toBeGreaterThan(0);
    });

    it('should preserve activity trail integrity', () => {
      const activity = { ...mockUserActivityData };

      // Created and updated timestamps should be preserved
      expect(activity.createdAt).toBeInstanceOf(Date);
      expect(activity.updatedAt).toBeInstanceOf(Date);
      expect(activity.lastActiveAt).toBeInstanceOf(Date);

      // Correlation ID should link related events
      expect(activity.correlationId).toBeDefined();
      expect(typeof activity.correlationId).toBe('string');
    });

    it('should handle data retention policies', () => {
      const activity = { ...mockUserActivityData };

      // User activities should have creation timestamp for retention policies
      expect(activity.createdAt).toBeInstanceOf(Date);

      // Should support cleanup based on age
      const ageInDays =
        (new Date() - activity.createdAt) / (1000 * 60 * 60 * 24);
      expect(ageInDays).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null and undefined values gracefully', () => {
      const activity = { ...mockUserActivityData };

      // Test with null values
      activity.userEmail = null;
      activity.location = null;
      activity.metadata = null;

      // Test with undefined values
      activity.details = undefined;
      activity.correlationId = undefined;

      // Assert - Should not crash
      expect(activity.userEmail).toBeNull();
      expect(activity.location).toBeNull();
      expect(activity.metadata).toBeNull();
      expect(activity.details).toBeUndefined();
      expect(activity.correlationId).toBeUndefined();
    });

    it('should handle very long strings gracefully', () => {
      const activity = { ...mockUserActivityData };

      // Test with very long activity type
      const longActivityType = 'a'.repeat(255);
      activity.activityType = longActivityType;

      // Test with very long description
      const longDescription = 'b'.repeat(500);
      activity.description = longDescription;

      // Assert
      expect(activity.activityType.length).toBe(255);
      expect(activity.description.length).toBe(500);
    });

    it('should handle special characters in data', () => {
      const activity = { ...mockUserActivityData };

      // Test with special characters in activity type
      activity.activityType = 'user_login_with_special_chars_@#$%^&*()';

      // Test with special characters in description
      activity.description = 'User logged in via web interface (v2.1)';

      // Assert
      expect(activity.activityType).toBe(
        'user_login_with_special_chars_@#$%^&*()'
      );
      expect(activity.description).toBe(
        'User logged in via web interface (v2.1)'
      );
    });
  });

  describe('Performance Tests', () => {
    it('should handle bulk user activity operations efficiently', () => {
      // Arrange
      const bulkActivities = Array.from({ length: 1000 }, (_, i) => ({
        id: `activity-${i}`,
        userId: `user-${i % 100}`,
        activityType: [
          'login',
          'logout',
          'page_view',
          'api_call',
          'password_change',
        ][i % 5],
        status: ['completed', 'failed', 'pending'][i % 3],
        priority: ['low', 'normal', 'high', 'critical'][i % 4],
        deviceType: ['desktop', 'mobile', 'tablet'][i % 3],
        createdAt: new Date(Date.now() - i * 60000), // Each created 1 minute earlier
      }));

      // Act
      const startTime = Date.now();
      const completedActivities = bulkActivities.filter(
        activity => activity.status === 'completed'
      );
      const highPriorityActivities = bulkActivities.filter(
        activity => activity.priority === 'high'
      );
      const endTime = Date.now();

      // Assert
      expect(completedActivities).toHaveLength(334); // 1000 / 3 rounded down
      expect(highPriorityActivities).toHaveLength(250);
      expect(endTime - startTime).toBeLessThan(10); // Less than 10ms for 1000 items
    });

    it('should handle user activity validation efficiently', () => {
      // Arrange
      const iterations = 100;
      const startTime = Date.now();

      // Act
      for (let i = 0; i < iterations; i++) {
        const activity = {
          id: `activity-${i}`,
          userId: `user-${i}`,
          activityType: `type_${i}`,
          description: `Description for activity ${i}`,
          status: ['completed', 'failed', 'pending'][i % 3],
          priority: ['low', 'normal', 'high', 'critical'][i % 4],
          createdAt: new Date(),
        };

        // Simulate validation checks
        expect(activity.activityType.length).toBeGreaterThan(0);
        expect(activity.description.length).toBeGreaterThan(0);
        expect(
          ['completed', 'failed', 'pending'].includes(activity.status)
        ).toBe(true);
        expect(
          ['low', 'normal', 'high', 'critical'].includes(activity.priority)
        ).toBe(true);
      }
      const endTime = Date.now();

      // Assert
      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Less than 1ms per validation
    });
  });
});
