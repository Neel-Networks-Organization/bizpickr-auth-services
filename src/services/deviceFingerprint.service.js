/**
 * Device Fingerprinting Service
 * Provides device identification and validation for security
 */

import crypto from 'crypto';
import { safeLogger } from '../config/logger.js';
import { authCache } from '../cache/auth.cache.js';
import { metricsService } from './metrics.service.js';

class DeviceFingerprintService {
  constructor() {
    this.fingerprintComponents = [
      'userAgent',
      'acceptLanguage',
      'acceptEncoding',
      'ipAddress',
      'screenResolution',
      'timezone',
      'platform',
      'cookieEnabled',
      'doNotTrack',
    ];

    this.suspiciousPatterns = {
      rapidDeviceChanges: { threshold: 3, window: 3600000 }, // 3 changes per hour
      multipleDevices: { threshold: 5, window: 86400000 }, // 5 devices per day
      unusualLocations: { threshold: 1000 }, // 1000km distance
    };
  }

  generateFingerprint(req) {
    try {
      const components = [
        req.get('User-Agent') || '',
        req.get('Accept-Language') || '',
        req.get('Accept-Encoding') || '',
        req.ip || '',
        req.get('X-Forwarded-For') || '',
        req.get('X-Real-IP') || '',
        req.get('X-Client-IP') || '',
        req.get('CF-Connecting-IP') || '', // Cloudflare
        req.get('X-Forwarded-Host') || '',
        req.get('Host') || '',
      ];

      // Add client-side fingerprinting data if available
      const clientFingerprint = req.body?.fingerprint || req.query?.fingerprint;
      if (clientFingerprint) {
        components.push(clientFingerprint);
      }

      // Create hash from components
      const fingerprint = crypto
        .createHash('sha256')
        .update(components.join('|'))
        .digest('hex');

      return fingerprint;
    } catch (error) {
      safeLogger.error('Failed to generate device fingerprint', {
        error: error.message,
      });
      return null;
    }
  }

  async validateDevice(userId, fingerprint, context = {}) {
    try {
      const userDevices = await this.getUserDevices(userId);
      const isKnownDevice = userDevices.some(
        device => device.fingerprint === fingerprint
      );

      if (!isKnownDevice) {
        // Check for suspicious patterns
        const analysis = await this.analyzeDevicePattern(
          userId,
          fingerprint,
          context
        );

        if (analysis.isSuspicious) {
          metricsService.recordSecurityEvent('suspicious_device', 'high', {
            userId,
            fingerprint,
            reasons: analysis.reasons,
          });

          return {
            isValid: false,
            isSuspicious: true,
            reasons: analysis.reasons,
            riskScore: analysis.riskScore,
          };
        }
      }

      return {
        isValid: isKnownDevice,
        isSuspicious: false,
        reasons: [],
        riskScore: 0,
      };
    } catch (error) {
      safeLogger.error('Failed to validate device', {
        userId,
        fingerprint,
        error: error.message,
      });

      // Fail open for known devices, fail closed for unknown
      return {
        isValid: false,
        isSuspicious: false,
        reasons: ['validation_error'],
        riskScore: 50,
      };
    }
  }

  async registerDevice(userId, fingerprint, deviceInfo = {}) {
    try {
      const device = {
        fingerprint,
        userId,
        registeredAt: new Date().toISOString(),
        lastUsed: new Date().toISOString(),
        deviceInfo: {
          userAgent: deviceInfo.userAgent,
          ipAddress: deviceInfo.ipAddress,
          location: deviceInfo.location,
          browser: deviceInfo.browser,
          os: deviceInfo.os,
          screenResolution: deviceInfo.screenResolution,
          timezone: deviceInfo.timezone,
        },
        isTrusted: false,
        trustLevel: 'new',
      };

      await authCache.addUserDevice(userId, device);

      safeLogger.info('Device registered', {
        userId,
        fingerprint,
        deviceInfo: device.deviceInfo,
      });

      metricsService.incrementMetric('deviceRegistrations', 1);

      return device;
    } catch (error) {
      safeLogger.error('Failed to register device', {
        userId,
        fingerprint,
        error: error.message,
      });
      throw error;
    }
  }

  async updateDeviceActivity(userId, fingerprint) {
    try {
      await authCache.updateDeviceActivity(userId, fingerprint, {
        lastUsed: new Date().toISOString(),
        activityCount: 1, // Increment activity count
      });
    } catch (error) {
      safeLogger.error('Failed to update device activity', {
        userId,
        fingerprint,
        error: error.message,
      });
    }
  }

  async getUserDevices(userId) {
    try {
      return (await authCache.getUserDevices(userId)) || [];
    } catch (error) {
      safeLogger.error('Failed to get user devices', {
        userId,
        error: error.message,
      });
      return [];
    }
  }

  async removeDevice(userId, fingerprint) {
    try {
      await authCache.removeUserDevice(userId, fingerprint);

      safeLogger.info('Device removed', { userId, fingerprint });
      metricsService.incrementMetric('deviceRemovals', 1);

      return true;
    } catch (error) {
      safeLogger.error('Failed to remove device', {
        userId,
        fingerprint,
        error: error.message,
      });
      return false;
    }
  }

  async trustDevice(userId, fingerprint) {
    try {
      await authCache.updateDeviceTrust(userId, fingerprint, {
        isTrusted: true,
        trustLevel: 'trusted',
        trustedAt: new Date().toISOString(),
      });

      safeLogger.info('Device trusted', { userId, fingerprint });
      return true;
    } catch (error) {
      safeLogger.error('Failed to trust device', {
        userId,
        fingerprint,
        error: error.message,
      });
      return false;
    }
  }

  async analyzeDevicePattern(userId, fingerprint, context) {
    const analysis = {
      isSuspicious: false,
      riskScore: 0,
      reasons: [],
    };

    try {
      const userDevices = await this.getUserDevices(userId);
      const deviceHistory = await this.getDeviceHistory(userId);

      // Check for rapid device changes
      const recentChanges = deviceHistory.filter(
        change =>
          Date.now() - new Date(change.timestamp).getTime() <
          this.suspiciousPatterns.rapidDeviceChanges.window
      );

      if (
        recentChanges.length >=
        this.suspiciousPatterns.rapidDeviceChanges.threshold
      ) {
        analysis.isSuspicious = true;
        analysis.riskScore += 30;
        analysis.reasons.push('rapid_device_changes');
      }

      // Check for multiple devices
      if (
        userDevices.length >= this.suspiciousPatterns.multipleDevices.threshold
      ) {
        analysis.isSuspicious = true;
        analysis.riskScore += 20;
        analysis.reasons.push('multiple_devices');
      }

      // Check for unusual location
      if (
        context.location &&
        this.isUnusualLocation(userDevices, context.location)
      ) {
        analysis.isSuspicious = true;
        analysis.riskScore += 40;
        analysis.reasons.push('unusual_location');
      }

      // Check for known malicious fingerprints
      if (await this.isKnownMaliciousFingerprint(fingerprint)) {
        analysis.isSuspicious = true;
        analysis.riskScore += 80;
        analysis.reasons.push('known_malicious_device');
      }
    } catch (error) {
      safeLogger.error('Failed to analyze device pattern', {
        userId,
        fingerprint,
        error: error.message,
      });
    }

    return analysis;
  }

  async getDeviceHistory(userId) {
    try {
      return (await authCache.getDeviceHistory(userId)) || [];
    } catch (error) {
      safeLogger.error('Failed to get device history', {
        userId,
        error: error.message,
      });
      return [];
    }
  }

  isUnusualLocation(devices, newLocation) {
    // Simple distance calculation (would use proper geolocation service in production)
    const knownLocations = devices
      .map(device => device.deviceInfo?.location)
      .filter(location => location);

    if (knownLocations.length === 0) {
      return false; // No known locations to compare against
    }

    // Check if new location is significantly different from known locations
    // This is a simplified check - would use proper geolocation distance calculation
    return false; // Default to not unusual until proper implementation
  }

  async isKnownMaliciousFingerprint(fingerprint) {
    try {
      // Check against blacklist of known malicious fingerprints
      const blacklistedFingerprints =
        await authCache.getBlacklistedFingerprints();
      return blacklistedFingerprints.includes(fingerprint);
    } catch (error) {
      safeLogger.error('Failed to check malicious fingerprint', {
        fingerprint,
        error: error.message,
      });
      return false;
    }
  }

  async addToBlacklist(fingerprint, reason) {
    try {
      await authCache.addBlacklistedFingerprint(fingerprint, {
        reason,
        blacklistedAt: new Date().toISOString(),
      });

      safeLogger.warn('Fingerprint blacklisted', { fingerprint, reason });
      return true;
    } catch (error) {
      safeLogger.error('Failed to blacklist fingerprint', {
        fingerprint,
        reason,
        error: error.message,
      });
      return false;
    }
  }

  getDeviceInfo(req) {
    return {
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.get('X-Forwarded-For'),
      acceptLanguage: req.get('Accept-Language'),
      acceptEncoding: req.get('Accept-Encoding'),
      host: req.get('Host'),
      referer: req.get('Referer'),
      origin: req.get('Origin'),
      // Additional headers that might be useful
      cfConnectingIp: req.get('CF-Connecting-IP'),
      xRealIp: req.get('X-Real-IP'),
      xClientIp: req.get('X-Client-IP'),
    };
  }

  async getDeviceAnalytics(userId) {
    try {
      const devices = await this.getUserDevices(userId);
      const history = await this.getDeviceHistory(userId);

      return {
        totalDevices: devices.length,
        trustedDevices: devices.filter(d => d.isTrusted).length,
        activeDevices: devices.filter(
          d => Date.now() - new Date(d.lastUsed).getTime() < 86400000 // Last 24 hours
        ).length,
        recentActivity: history.filter(
          h => Date.now() - new Date(h.timestamp).getTime() < 604800000 // Last 7 days
        ).length,
        riskScore: this.calculateOverallRiskScore(devices, history),
      };
    } catch (error) {
      safeLogger.error('Failed to get device analytics', {
        userId,
        error: error.message,
      });
      return null;
    }
  }

  calculateOverallRiskScore(devices, history) {
    let riskScore = 0;

    // Factor in number of devices
    if (devices.length > 5) riskScore += 20;
    if (devices.length > 10) riskScore += 30;

    // Factor in untrusted devices
    const untrustedDevices = devices.filter(d => !d.isTrusted).length;
    riskScore += untrustedDevices * 10;

    // Factor in recent activity
    const recentActivity = history.filter(
      h => Date.now() - new Date(h.timestamp).getTime() < 3600000 // Last hour
    ).length;

    if (recentActivity > 10) riskScore += 20;
    if (recentActivity > 50) riskScore += 40;

    return Math.min(riskScore, 100);
  }
}

export const deviceFingerprintService = new DeviceFingerprintService();
