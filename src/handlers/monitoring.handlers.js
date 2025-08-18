import { safeLogger } from '../config/logger.js';
import { getCorrelationId } from '../config/requestContext.js';
import { ApiError } from '../utils/ApiError.js';
/**
 * Socket.IO Monitoring Handlers
 *
 * Features:
 * - System monitoring
 * - Performance metrics
 * - Health checks
 * - Real-time alerts
 */
class MonitoringHandlers {
  constructor() {
    this.handlerStats = {
      totalEvents: 0,
      successfulEvents: 0,
      failedEvents: 0,
      errors: 0,
    };
  }
  /**
   * Register monitoring event handlers
   * @param {Object} socket - Socket.IO socket instance
   * @param {Object} server - Socket server instance
   */
  register(socket, server) {
    const correlationId = getCorrelationId();
    safeLogger.info('Registering monitoring handlers', {
      socketId: socket.id,
      userId: socket.user?.id,
      correlationId,
    });
    // Monitoring events
    socket.on('get_health_status', data =>
      this.handleGetHealthStatus(socket, data, server),
    );
    socket.on('get_performance_metrics', data =>
      this.handleGetPerformanceMetrics(socket, data, server),
    );
    socket.on('get_system_info', data =>
      this.handleGetSystemInfo(socket, data, server),
    );
    socket.on('subscribe_alerts', data =>
      this.handleSubscribeAlerts(socket, data, server),
    );
    socket.on('unsubscribe_alerts', data =>
      this.handleUnsubscribeAlerts(socket, data, server),
    );
  }
  /**
   * Handle get health status
   * @param {Object} socket - Socket instance
   * @param {Object} data - Request data
   * @param {Object} server - Server instance
   */
  async handleGetHealthStatus(socket, data, server) {
    const correlationId = getCorrelationId();
    try {
      this.handlerStats.totalEvents++;
      if (!socket.user) {
        throw new ApiError(401, 'User not authenticated');
      }
      // Get health status
      const healthStatus = await this._getHealthStatus(server);
      // Send health status
      socket.emit('health_status', {
        success: true,
        status: healthStatus,
        timestamp: Date.now(),
      });
      this.handlerStats.successfulEvents++;
      safeLogger.info('Health status sent to super admin', {
        socketId: socket.id,
        userId: socket.user.id,
        correlationId,
      });
    } catch (error) {
      this.handlerStats.failedEvents++;
      this.handlerStats.errors++;
      safeLogger.error('Get health status failed', {
        error: error.message,
        socketId: socket.id,
        userId: socket.user?.id,
        correlationId,
      });
      socket.emit('health_status_error', {
        success: false,
        error: error.message,
        code: error.statusCode || 500,
        timestamp: Date.now(),
      });
    }
  }
  /**
   * Handle get performance metrics
   * @param {Object} socket - Socket instance
   * @param {Object} data - Request data
   * @param {Object} server - Server instance
   */
  async handleGetPerformanceMetrics(socket, data, server) {
    const correlationId = getCorrelationId();
    try {
      this.handlerStats.totalEvents++;
      if (!socket.user) {
        throw new ApiError(401, 'User not authenticated');
      }
      const options = {
        duration: data?.duration || 3600, // 1 hour
        interval: data?.interval || 60, // 1 minute
      };
      // Get performance metrics
      const metrics = await this._getPerformanceMetrics(options);
      // Send performance metrics
      socket.emit('performance_metrics', {
        success: true,
        metrics,
        timestamp: Date.now(),
      });
      this.handlerStats.successfulEvents++;
      safeLogger.info('Performance metrics sent to super admin', {
        socketId: socket.id,
        userId: socket.user.id,
        correlationId,
      });
    } catch (error) {
      this.handlerStats.failedEvents++;
      this.handlerStats.errors++;
      safeLogger.error('Get performance metrics failed', {
        error: error.message,
        socketId: socket.id,
        userId: socket.user?.id,
        correlationId,
      });
      socket.emit('performance_metrics_error', {
        success: false,
        error: error.message,
        code: error.statusCode || 500,
        timestamp: Date.now(),
      });
    }
  }
  /**
   * Handle get system info
   * @param {Object} socket - Socket instance
   * @param {Object} data - Request data
   * @param {Object} server - Server instance
   */
  async handleGetSystemInfo(socket, data, server) {
    const correlationId = getCorrelationId();
    try {
      this.handlerStats.totalEvents++;
      if (!socket.user) {
        throw new ApiError(401, 'User not authenticated');
      }
      // Get system info
      const systemInfo = await this._getSystemInfo();
      // Send system info
      socket.emit('system_info', {
        success: true,
        info: systemInfo,
        timestamp: Date.now(),
      });
      this.handlerStats.successfulEvents++;
      safeLogger.info('System info sent to super admin', {
        socketId: socket.id,
        userId: socket.user.id,
        correlationId,
      });
    } catch (error) {
      this.handlerStats.failedEvents++;
      this.handlerStats.errors++;
      safeLogger.error('Get system info failed', {
        error: error.message,
        socketId: socket.id,
        userId: socket.user?.id,
        correlationId,
      });
      socket.emit('system_info_error', {
        success: false,
        error: error.message,
        code: error.statusCode || 500,
        timestamp: Date.now(),
      });
    }
  }
  /**
   * Handle subscribe to alerts
   * @param {Object} socket - Socket instance
   * @param {Object} data - Subscription data
   * @param {Object} server - Server instance
   */
  async handleSubscribeAlerts(socket, data, server) {
    const correlationId = getCorrelationId();
    try {
      this.handlerStats.totalEvents++;
      if (!socket.user) {
        throw new ApiError(401, 'User not authenticated');
      }
      const userId = socket.user.id;
      const alertTypes = data?.alertTypes || ['error', 'warning', 'info'];
      // Join alert rooms
      for (const alertType of alertTypes) {
        await server.joinUserToRoom(
          userId,
          `alerts:${alertType}`,
          'monitoring',
        );
      }
      // Send confirmation
      socket.emit('alerts_subscribed', {
        success: true,
        alertTypes,
        timestamp: Date.now(),
      });
      this.handlerStats.successfulEvents++;
      safeLogger.info('Super admin subscribed to alerts', {
        socketId: socket.id,
        userId,
        alertTypes,
        correlationId,
      });
    } catch (error) {
      this.handlerStats.failedEvents++;
      this.handlerStats.errors++;
      safeLogger.error('Alert subscription failed', {
        error: error.message,
        socketId: socket.id,
        userId: socket.user?.id,
        correlationId,
      });
      socket.emit('alerts_subscription_error', {
        success: false,
        error: error.message,
        code: error.statusCode || 500,
        timestamp: Date.now(),
      });
    }
  }
  /**
   * Handle unsubscribe from alerts
   * @param {Object} socket - Socket instance
   * @param {Object} data - Unsubscription data
   * @param {Object} server - Server instance
   */
  async handleUnsubscribeAlerts(socket, data, server) {
    const correlationId = getCorrelationId();
    try {
      this.handlerStats.totalEvents++;
      if (!socket.user) {
        throw new ApiError(401, 'User not authenticated');
      }
      const userId = socket.user.id;
      const alertTypes = data?.alertTypes || ['error', 'warning', 'info'];
      // Leave alert rooms
      for (const alertType of alertTypes) {
        await server.removeUserFromRoom(
          userId,
          `alerts:${alertType}`,
          'monitoring',
        );
      }
      // Send confirmation
      socket.emit('alerts_unsubscribed', {
        success: true,
        alertTypes,
        timestamp: Date.now(),
      });
      this.handlerStats.successfulEvents++;
      safeLogger.info('Super admin unsubscribed from alerts', {
        socketId: socket.id,
        userId,
        alertTypes,
        correlationId,
      });
    } catch (error) {
      this.handlerStats.failedEvents++;
      this.handlerStats.errors++;
      safeLogger.error('Alert unsubscription failed', {
        error: error.message,
        socketId: socket.id,
        userId: socket.user?.id,
        correlationId,
      });
      socket.emit('alerts_unsubscription_error', {
        success: false,
        error: error.message,
        code: error.statusCode || 500,
        timestamp: Date.now(),
      });
    }
  }
  /**
   * Get health status (placeholder - integrate with your health check service)
   * @private
   */
  async _getHealthStatus(server) {
    // This would integrate with your health check service
    return {
      status: 'healthy',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      connections: server.getStats().health.connections,
      errors: server.getStats().health.errors,
    };
  }
  /**
   * Get performance metrics
   * @private
   */
  async _getPerformanceMetrics(options) {
    // Integration with monitoring service will be implemented when needed
    return {
      cpu: [],
      memory: [],
      network: [],
      disk: [],
    };
  }
  /**
   * Get system info
   * @private
   */
  async _getSystemInfo() {
    // Integration with system service will be implemented when needed
    return {
      platform: process.platform,
      arch: process.arch,
      version: process.version,
      pid: process.pid,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
    };
  }
  /**
   * Get handler statistics
   * @returns {Object} Handler statistics
   */
  getStats() {
    const successRate =
      this.handlerStats.totalEvents > 0
        ? (
          (this.handlerStats.successfulEvents /
              this.handlerStats.totalEvents) *
            100
        ).toFixed(2)
        : 0;
    return {
      ...this.handlerStats,
      successRate: `${successRate}%`,
    };
  }
  /**
   * Reset statistics
   */
  resetStats() {
    this.handlerStats = {
      totalEvents: 0,
      successfulEvents: 0,
      failedEvents: 0,
      errors: 0,
    };
  }
}
// Create singleton instance
const monitoringHandlers = new MonitoringHandlers();
export default monitoringHandlers;
