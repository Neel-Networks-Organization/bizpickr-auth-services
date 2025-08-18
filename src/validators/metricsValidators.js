/**
 * Metrics Validators
 * Validation schemas for metrics endpoints
 */

import Joi from 'joi';

export const metricsValidators = {
  /**
   * Trigger cache warming validation
   */
  triggerCacheWarming: Joi.object({
    body: Joi.object({
      cacheType: Joi.string()
        .valid(
          'all',
          'userProfiles',
          'jwkSets',
          'permissions',
          'sessionData',
          'rateLimitData',
        )
        .default('all')
        .description('Type of cache to warm'),
    }),
  }),

  /**
   * Get device analytics validation
   */
  getDeviceAnalytics: Joi.object({
    params: Joi.object({
      userId: Joi.string()
        .uuid()
        .optional()
        .description(
          'User ID for device analytics (optional if accessing own data)',
        ),
    }),
    query: Joi.object({
      timeRange: Joi.string()
        .valid('1h', '24h', '7d', '30d')
        .default('7d')
        .description('Time range for analytics'),
      includeHistory: Joi.boolean()
        .default(false)
        .description('Include device history in response'),
    }),
  }),

  /**
   * Export metrics validation
   */
  exportMetrics: Joi.object({
    query: Joi.object({
      format: Joi.string()
        .valid('json', 'csv')
        .default('json')
        .description('Export format'),
      timeRange: Joi.string()
        .valid('1h', '24h', '7d', '30d', 'all')
        .default('24h')
        .description('Time range for export'),
      categories: Joi.array()
        .items(Joi.string().valid('business', 'technical', 'cache', 'database'))
        .default(['business', 'technical'])
        .description('Categories to include in export'),
    }),
  }),

  /**
   * Reset metrics validation
   */
  resetMetrics: Joi.object({
    body: Joi.object({
      confirm: Joi.boolean()
        .valid(true)
        .required()
        .description('Confirmation flag to prevent accidental resets'),
      categories: Joi.array()
        .items(Joi.string().valid('business', 'technical', 'all'))
        .default(['all'])
        .description('Categories to reset'),
    }),
  }),

  /**
   * Get metrics with filters validation
   */
  getMetricsWithFilters: Joi.object({
    query: Joi.object({
      categories: Joi.array()
        .items(Joi.string().valid('business', 'technical', 'cache', 'database'))
        .default(['business', 'technical'])
        .description('Categories to include'),
      timeRange: Joi.string()
        .valid('1h', '24h', '7d', '30d')
        .default('24h')
        .description('Time range for metrics'),
      granularity: Joi.string()
        .valid('1m', '5m', '15m', '1h', '1d')
        .default('1h')
        .description('Data granularity'),
      includeRaw: Joi.boolean()
        .default(false)
        .description('Include raw data points'),
    }),
  }),

  /**
   * Create custom metric validation
   */
  createCustomMetric: Joi.object({
    body: Joi.object({
      name: Joi.string().min(1).max(100).required().description('Metric name'),
      value: Joi.number().required().description('Metric value'),
      type: Joi.string()
        .valid('counter', 'gauge', 'histogram')
        .default('counter')
        .description('Metric type'),
      tags: Joi.object().default({}).description('Metric tags'),
      description: Joi.string()
        .max(500)
        .optional()
        .description('Metric description'),
    }),
  }),

  /**
   * Update metric threshold validation
   */
  updateMetricThreshold: Joi.object({
    params: Joi.object({
      metricName: Joi.string().required().description('Name of the metric'),
    }),
    body: Joi.object({
      warning: Joi.number().optional().description('Warning threshold'),
      critical: Joi.number().optional().description('Critical threshold'),
      enabled: Joi.boolean()
        .default(true)
        .description('Enable/disable threshold monitoring'),
    }),
  }),

  /**
   * Get metric history validation
   */
  getMetricHistory: Joi.object({
    params: Joi.object({
      metricName: Joi.string().required().description('Name of the metric'),
    }),
    query: Joi.object({
      startTime: Joi.date()
        .iso()
        .optional()
        .description('Start time for history'),
      endTime: Joi.date().iso().optional().description('End time for history'),
      granularity: Joi.string()
        .valid('1m', '5m', '15m', '1h', '1d')
        .default('1h')
        .description('Data granularity'),
      limit: Joi.number()
        .integer()
        .min(1)
        .max(1000)
        .default(100)
        .description('Maximum number of data points'),
    }),
  }),

  /**
   * Create alert rule validation
   */
  createAlertRule: Joi.object({
    body: Joi.object({
      name: Joi.string()
        .min(1)
        .max(100)
        .required()
        .description('Alert rule name'),
      metricName: Joi.string().required().description('Metric to monitor'),
      condition: Joi.string()
        .valid('gt', 'gte', 'lt', 'lte', 'eq', 'ne')
        .required()
        .description('Comparison condition'),
      threshold: Joi.number().required().description('Threshold value'),
      duration: Joi.number()
        .integer()
        .min(1)
        .default(1)
        .description('Duration in minutes for condition to be true'),
      severity: Joi.string()
        .valid('low', 'medium', 'high', 'critical')
        .default('medium')
        .description('Alert severity'),
      enabled: Joi.boolean()
        .default(true)
        .description('Enable/disable alert rule'),
      description: Joi.string()
        .max(500)
        .optional()
        .description('Alert description'),
    }),
  }),

  /**
   * Update alert rule validation
   */
  updateAlertRule: Joi.object({
    params: Joi.object({
      ruleId: Joi.string().uuid().required().description('Alert rule ID'),
    }),
    body: Joi.object({
      name: Joi.string()
        .min(1)
        .max(100)
        .optional()
        .description('Alert rule name'),
      condition: Joi.string()
        .valid('gt', 'gte', 'lt', 'lte', 'eq', 'ne')
        .optional()
        .description('Comparison condition'),
      threshold: Joi.number().optional().description('Threshold value'),
      duration: Joi.number()
        .integer()
        .min(1)
        .optional()
        .description('Duration in minutes for condition to be true'),
      severity: Joi.string()
        .valid('low', 'medium', 'high', 'critical')
        .optional()
        .description('Alert severity'),
      enabled: Joi.boolean()
        .optional()
        .description('Enable/disable alert rule'),
      description: Joi.string()
        .max(500)
        .optional()
        .description('Alert description'),
    }),
  }),

  /**
   * Get alert history validation
   */
  getAlertHistory: Joi.object({
    query: Joi.object({
      startTime: Joi.date()
        .iso()
        .optional()
        .description('Start time for history'),
      endTime: Joi.date().iso().optional().description('End time for history'),
      severity: Joi.string()
        .valid('low', 'medium', 'high', 'critical')
        .optional()
        .description('Filter by severity'),
      status: Joi.string()
        .valid('active', 'resolved', 'acknowledged')
        .optional()
        .description('Filter by status'),
      limit: Joi.number()
        .integer()
        .min(1)
        .max(1000)
        .default(100)
        .description('Maximum number of alerts'),
    }),
  }),

  /**
   * Acknowledge alert validation
   */
  acknowledgeAlert: Joi.object({
    params: Joi.object({
      alertId: Joi.string().uuid().required().description('Alert ID'),
    }),
    body: Joi.object({
      comment: Joi.string()
        .max(500)
        .optional()
        .description('Acknowledgment comment'),
    }),
  }),

  /**
   * Resolve alert validation
   */
  resolveAlert: Joi.object({
    params: Joi.object({
      alertId: Joi.string().uuid().required().description('Alert ID'),
    }),
    body: Joi.object({
      comment: Joi.string()
        .max(500)
        .optional()
        .description('Resolution comment'),
    }),
  }),
};

// Export individual validators for specific use cases
export const {
  triggerCacheWarming,
  getDeviceAnalytics,
  exportMetrics,
  resetMetrics,
  getMetricsWithFilters,
  createCustomMetric,
  updateMetricThreshold,
  getMetricHistory,
  createAlertRule,
  updateAlertRule,
  getAlertHistory,
  acknowledgeAlert,
  resolveAlert,
} = metricsValidators;
