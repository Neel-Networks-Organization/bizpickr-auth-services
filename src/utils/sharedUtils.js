/**
 * Essential Shared Utilities for authService
 *
 * Purpose: Common utilities used across authService
 * Features:
 * - Response formatting
 * - Basic logging helpers
 * - Common utilities
 * - Input sanitization
 */

import { safeLogger } from '../config/logger.js';

/**
 * Standardized Error Response Format
 */
export const createErrorResponse = (
  statusCode,
  message,
  details = [],
  stack = null
) => ({
  success: false,
  message,
  errors: Array.isArray(details) ? details : [details],
  ...(process.env.NODE_ENV === 'development' ? { stack } : {}),
});

/**
 * Standardized Success Response Format
 */
export const createSuccessResponse = (data, message = 'Success') => ({
  success: true,
  message,
  data,
});

/**
 * Standardized Logging Patterns
 */
export const logInfo = (message, data = {}) => {
  safeLogger.info(message, {
    ...data,
    timestamp: new Date().toISOString(),
  });
};

export const logError = (message, error, data = {}) => {
  safeLogger.error(message, {
    ...data,
    error: {
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      name: error.name,
      code: error.code,
    },
    timestamp: new Date().toISOString(),
  });
};

export const logWarn = (message, data = {}) => {
  safeLogger.warn(message, {
    ...data,
    timestamp: new Date().toISOString(),
  });
};

export const logDebug = (message, data = {}) => {
  safeLogger.debug(message, {
    ...data,
    timestamp: new Date().toISOString(),
  });
};

/**
 * Basic Input Sanitization
 */
export const sanitizeString = input => {
  if (typeof input !== 'string') {
    return input;
  }

  return input
    .trim()
    .replace(/[<>]/g, '') // Remove < and >
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, ''); // Remove event handlers
};

export const sanitizeObject = obj => {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeString(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

/**
 * Common Utility Functions
 */
export const generateRandomString = (length = 32) => {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

export const generateRandomNumber = (min = 100000, max = 999999) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

export const formatDate = date => {
  if (!date) return null;

  const d = new Date(date);
  if (isNaN(d.getTime())) return null;

  return d.toISOString();
};

export const isValidDate = date => {
  if (!date) return false;
  const d = new Date(date);
  return !isNaN(d.getTime());
};

export const isEmpty = value => {
  if (value === null || value === undefined) return true;
  if (typeof value === 'string') return value.trim() === '';
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
};

export const isNotEmpty = value => !isEmpty(value);

/**
 * Array Utilities
 */
export const chunkArray = (array, size) => {
  const chunks = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
};

export const uniqueArray = array => {
  return [...new Set(array)];
};

export const shuffleArray = array => {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
};

/**
 * String Utilities
 */
export const capitalizeFirst = str => {
  if (typeof str !== 'string') return str;
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const truncateString = (str, length = 100, suffix = '...') => {
  if (typeof str !== 'string') return str;
  if (str.length <= length) return str;
  return str.substring(0, length) + suffix;
};

export const slugify = str => {
  if (typeof str !== 'string') return str;
  return str
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

/**
 * Number Utilities
 */
export const formatNumber = (num, decimals = 2) => {
  if (typeof num !== 'number') return num;
  return Number(num.toFixed(decimals));
};

export const clamp = (num, min, max) => {
  if (typeof num !== 'number') return num;
  return Math.min(Math.max(num, min), max);
};

export const isInRange = (num, min, max) => {
  if (typeof num !== 'number') return false;
  return num >= min && num <= max;
};

export default {
  createErrorResponse,
  createSuccessResponse,
  logInfo,
  logError,
  logWarn,
  logDebug,
  sanitizeString,
  sanitizeObject,
  generateRandomString,
  generateRandomNumber,
  formatDate,
  isValidDate,
  isEmpty,
  isNotEmpty,
  chunkArray,
  uniqueArray,
  shuffleArray,
  capitalizeFirst,
  truncateString,
  slugify,
  formatNumber,
  clamp,
  isInRange,
};
